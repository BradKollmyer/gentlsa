mod azure;
mod cert;
mod cli;
mod cloudflare;
mod dns;
mod google;
mod nsupdate;
mod output;
mod publish;
mod report;
mod rollover;
mod route53;
mod timeout;
mod tlsa;
mod verbose;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::azure::Client as Azure;
use crate::cert::{CertDetails, Certificate, fetch_live};
use crate::cli::PublisherFlags;
use crate::cli::{Cli, Command};
use crate::cloudflare::Client as Cloudflare;
use crate::google::Client as Google;
use crate::nsupdate::Config as Nsupdate;
use crate::publish::{PublishMode, PublishReport, PublisherKind};
use crate::report::{
    CloudflareList, DnsName, FileRecord, GenerateResult, JsonTlsa, LiveHash, NsupdateList,
    ProviderList, PruneResult, ReloadReport, Report, ResumeJob, RolloverPublish, VerifyResult,
    ZoneRef, apply_dnssec, apply_expiry, expiry_phrase, verify_outcome, worst_verify_exit,
};
use crate::route53::Client as Route53;
use crate::tlsa::{HostTarget, StarttlsProto, TlsaParams, connect_host, fqdn};

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(err) = cert::install_crypto_provider() {
        eprintln!("{err:#}");
        return ExitCode::from(1);
    }

    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("{err:#}");
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<u8> {
    let cli = Cli::parse();
    verbose::init(cli.verbose);
    output::init(cli.json);
    timeout::init(cli.timeout);
    verbose::step(format_args!("timeout {}s", cli.timeout));

    match cli.command {
        Command::Generate {
            zone,
            ports,
            hostname,
            mx,
            info,
            starttls,
            params,
            publisher,
            replace,
            dryrun,
        } => {
            let publisher = PublisherOpts::from_flags(publisher, replace, dryrun)?;
            let params = params.params();
            require_default_params_for_publish(params, &publisher)?;
            let starttls = starttls.proto();
            let mx = mx.mx;
            let targets = match resolve_targets(&zone, hostname.as_deref(), mx).await {
                Ok(targets) => targets,
                Err(err) => {
                    eprintln!("{err:#}");
                    return Ok(1);
                }
            };
            require_targets_in_zone_for_publish(&zone, &targets, &publisher)?;
            let mut code = 0;
            let mut results = Vec::new();
            for target in &targets {
                for port in ports.as_slice() {
                    let (port_code, result) = generate(
                        &target.zone,
                        *port,
                        target.hostname.as_deref(),
                        info,
                        params,
                        publisher,
                        starttls,
                    )
                    .await?;
                    code = port_code;
                    results.push(result);
                }
            }
            if output::is_json() {
                output::emit(&Report::Generate {
                    zone,
                    hostname,
                    mx,
                    results,
                })?;
            }
            Ok(code)
        }
        Command::List {
            zone,
            ports,
            hostname,
            starttls,
            publisher,
            info,
        } => {
            list(
                &zone,
                ports.as_ref().map(cli::Ports::as_slice).unwrap_or(&[]),
                hostname.as_deref(),
                publisher.kind(),
                info,
                starttls.proto(),
            )
            .await
        }
        Command::Prune {
            zone,
            ports,
            hostname,
            mx,
            starttls,
            publisher,
            dryrun,
        } => {
            let starttls = starttls.proto();
            let mx = mx.mx;
            let publisher_kind = publisher.kind();
            let targets = match resolve_targets(&zone, hostname.as_deref(), mx).await {
                Ok(targets) => targets,
                Err(err) => {
                    eprintln!("{err:#}");
                    return Ok(1);
                }
            };
            if publisher_kind.is_some() {
                for target in &targets {
                    if !target.in_zone(&zone) {
                        anyhow::bail!(
                            "MX {} is outside {zone}; cannot prune its TLSA from this zone",
                            target.connect_host()
                        );
                    }
                }
            }
            let mut code = 0;
            let mut results = Vec::new();
            for target in &targets {
                for port in ports.as_slice() {
                    let (port_code, result) = prune(
                        &target.zone,
                        *port,
                        target.hostname.as_deref(),
                        publisher_kind,
                        dryrun,
                        starttls,
                    )
                    .await?;
                    code = port_code;
                    results.push(result);
                }
            }
            if output::is_json() {
                output::emit(&Report::Prune {
                    zone,
                    hostname,
                    mx,
                    results,
                })?;
            }
            Ok(code)
        }
        Command::Rollover {
            certfile,
            zone,
            ports,
            hostname,
            info,
            starttls,
            publisher,
            reload,
            ttl,
            dryrun,
            resume,
            schedule,
        } => {
            if let Some(filter) = resume {
                let filter = if filter == "*" { None } else { Some(filter) };
                return resume_cmd(filter.as_deref(), info, dryrun).await;
            }
            let kind = publisher.kind().with_context(
                || "rollover requires --cloudflare, --nsupdate, --route53, --google, or --azure",
            )?;
            let certfile = certfile.context("CERTFILE is required")?;
            let zone = zone.context("ZONE is required")?;
            let ports = ports.context("PORTS is required")?;
            let args = RolloverArgs {
                certfile,
                zone,
                ports: ports.as_slice(),
                hostname: hostname.as_deref(),
                info,
                kind,
                reload,
                ttl: ttl.unwrap_or(rollover::default_ttl(kind)),
                dryrun,
                starttls: starttls.proto(),
            };
            if schedule {
                schedule_cmd(args).await
            } else {
                rollover_cmd(args).await
            }
        }
        Command::Verify {
            zone,
            ports,
            hostname,
            mx,
            info,
            starttls,
            warn,
            critical,
            no_expiry_check,
            no_dnssec_check,
        } => {
            if critical > warn {
                output::text(format!(
                    "UNKNOWN - --critical ({critical}) cannot be greater than --warn ({warn})"
                ));
                if output::is_json() {
                    output::emit(&Report::Verify {
                        zone,
                        hostname,
                        mx: mx.mx,
                        results: Vec::new(),
                        exit: 3,
                    })?;
                }
                return Ok(3);
            }
            let expiry = (!no_expiry_check).then_some((warn, critical));
            let starttls = starttls.proto();
            let mx = mx.mx;
            let targets = match resolve_targets(&zone, hostname.as_deref(), mx).await {
                Ok(targets) => targets,
                Err(err) => {
                    eprintln!("{err:#}");
                    output::text("UNKNOWN - Something went wrong. Check logs");
                    if output::is_json() {
                        output::emit(&Report::Verify {
                            zone,
                            hostname,
                            mx,
                            results: Vec::new(),
                            exit: 3,
                        })?;
                    }
                    return Ok(3);
                }
            };
            let ports = ports.as_slice();
            let multi_port = ports.len() > 1;
            let multi_host = targets.len() > 1;
            let mut results = Vec::new();
            for target in &targets {
                for port in ports {
                    let prefix = match (multi_host, multi_port) {
                        (true, true) => Some(format!("{}/{port}", target.connect_host())),
                        (true, false) => Some(target.connect_host()),
                        (false, true) => Some(port.to_string()),
                        (false, false) => None,
                    };
                    results.push(
                        verify(
                            &target.zone,
                            *port,
                            target.hostname.as_deref(),
                            info,
                            prefix.as_deref(),
                            expiry,
                            !no_dnssec_check,
                            starttls,
                            mx.then(|| target.connect_host()),
                        )
                        .await,
                    );
                }
            }
            let worst = worst_verify_exit(results.iter().map(|result| result.exit));
            if output::is_json() {
                output::emit(&Report::Verify {
                    zone,
                    hostname,
                    mx,
                    results,
                    exit: worst,
                })?;
            }
            Ok(worst)
        }
        Command::Completions { shell } => {
            use clap::CommandFactory;
            clap_complete::generate(
                shell,
                &mut Cli::command(),
                "gentlsa",
                &mut std::io::stdout(),
            );
            Ok(0)
        }
        Command::Cloudflare { info, listzones } => cloudflare_cmd(info, listzones).await,
        Command::Nsupdate { info } => nsupdate_cmd(info).await,
        Command::Route53 { info, listzones } => route53_cmd(info, listzones).await,
        Command::Google { info, listzones } => google_cmd(info, listzones).await,
        Command::Azure { info, listzones } => azure_cmd(info, listzones).await,
        Command::File {
            certfile,
            zone,
            hostname,
            ports,
            info,
            params,
            publisher,
            replace,
            dryrun,
        } => {
            let publisher = PublisherOpts::from_flags(publisher, replace, dryrun)?;
            let params = params.params();
            require_default_params_for_publish(params, &publisher)?;
            let ports = ports.as_ref().map(cli::Ports::as_slice).unwrap_or(&[]);
            verbose::step(format_args!("file {}", certfile.display()));
            let cert = Certificate::from_file(&certfile)?;
            if !output::is_json() {
                cert.print_info_params(hostname.as_deref(), ports, info, params)?;
            }

            let mut code = 0;
            let mut reports = PublisherReports::default();
            let mut error = None;
            if let Some(kind) = publisher.kind {
                let zone = zone
                    .as_deref()
                    .with_context(|| format!("--zone is required with {}", kind.flag()))?;
                if ports.is_empty() {
                    anyhow::bail!("--port is required with {}", kind.flag());
                }
                for port in ports {
                    match publish_cert(
                        kind,
                        zone,
                        hostname.as_deref(),
                        *port,
                        &cert,
                        info,
                        publisher,
                    )
                    .await?
                    {
                        PublishOutcome::Published(report) => reports.push(kind, report),
                        PublishOutcome::NotManaged(code_name) => {
                            error = Some(code_name.into());
                            code = 1;
                            break;
                        }
                    }
                }
            }

            if output::is_json() {
                let hash = cert.tlsa_record_data(params)?;
                verbose::step(format_args!("{} {hash}", params.label()));
                output::emit(&Report::File {
                    path: certfile.display().to_string(),
                    usage: params.usage,
                    selector: params.selector,
                    matching: params.matching,
                    certificate: hash,
                    info: if info { Some(cert.details()?) } else { None },
                    records: ports
                        .iter()
                        .map(|port| FileRecord {
                            port: *port,
                            owner: tlsa::owner_name(*port, hostname.as_deref()),
                        })
                        .collect(),
                    cloudflare: reports.cloudflare,
                    nsupdate: reports.nsupdate,
                    route53: reports.route53,
                    google: reports.google,
                    azure: reports.azure,
                    error,
                })?;
            }
            Ok(code)
        }
    }
}

/// The publishers' rollover/replace/prune logic only understands 3 1 1, so
/// refuse to publish anything else rather than silently writing wrong params.
async fn resolve_targets(zone: &str, hostname: Option<&str>, mx: bool) -> Result<Vec<HostTarget>> {
    if !mx {
        return Ok(vec![HostTarget::from_label(zone, hostname)]);
    }
    let records = dns::lookup_mx(zone).await?;
    if records.is_empty() {
        anyhow::bail!("no MX records for {zone}");
    }
    verbose::step(format_args!(
        "MX hosts: {}",
        records
            .iter()
            .map(|mx| format!("{} ({})", mx.host, mx.preference))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    Ok(records
        .iter()
        .map(|mx| HostTarget::from_mx(zone, &mx.host))
        .collect())
}

fn require_targets_in_zone_for_publish(
    zone: &str,
    targets: &[HostTarget],
    publisher: &PublisherOpts,
) -> Result<()> {
    if publisher.kind.is_none() {
        return Ok(());
    }
    for target in targets {
        if !target.in_zone(zone) {
            anyhow::bail!(
                "MX {} is outside {zone}; cannot publish its TLSA into this zone",
                target.connect_host()
            );
        }
    }
    Ok(())
}

fn require_default_params_for_publish(params: TlsaParams, publisher: &PublisherOpts) -> Result<()> {
    if publisher.kind.is_some() && !params.is_default() {
        anyhow::bail!(
            "publishing TLSA records other than 3 1 1 is not supported yet; \
             drop the publisher flag and add the printed record manually"
        );
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct PublisherOpts {
    kind: Option<PublisherKind>,
    replace: bool,
    dryrun: bool,
}

impl PublisherOpts {
    fn from_flags(flags: PublisherFlags, replace: bool, dryrun: bool) -> Result<Self> {
        let opts = Self {
            kind: flags.kind(),
            replace,
            dryrun,
        };
        if opts.replace && opts.kind.is_none() {
            anyhow::bail!(
                "--replace requires --cloudflare, --nsupdate, --route53, --google, or --azure"
            );
        }
        Ok(opts)
    }
}

#[derive(Default)]
struct PublisherReports {
    cloudflare: Vec<PublishReport>,
    nsupdate: Vec<PublishReport>,
    route53: Vec<PublishReport>,
    google: Vec<PublishReport>,
    azure: Vec<PublishReport>,
}

impl PublisherReports {
    fn push(&mut self, kind: PublisherKind, report: PublishReport) {
        match kind {
            PublisherKind::Cloudflare => self.cloudflare.push(report),
            PublisherKind::Nsupdate => self.nsupdate.push(report),
            PublisherKind::Route53 => self.route53.push(report),
            PublisherKind::Google => self.google.push(report),
            PublisherKind::Azure => self.azure.push(report),
        }
    }
}

enum PublishOutcome {
    Published(PublishReport),
    NotManaged(&'static str),
}

struct RolloverArgs<'a> {
    certfile: std::path::PathBuf,
    zone: String,
    ports: &'a [u16],
    hostname: Option<&'a str>,
    info: bool,
    kind: PublisherKind,
    reload: Option<String>,
    ttl: u32,
    dryrun: bool,
    starttls: Option<StarttlsProto>,
}

async fn schedule_cmd(args: RolloverArgs<'_>) -> Result<u8> {
    if args.reload.is_none() {
        anyhow::bail!("--schedule requires --reload");
    }
    let cert = Certificate::from_file(&args.certfile)?;
    if !output::is_json() {
        cert.print_info(args.hostname, args.ports, args.info)?;
    }
    let hash = cert.spki_sha256_hex()?;
    let job = rollover::Job::new(
        args.certfile.clone(),
        args.zone.clone(),
        args.ports,
        args.hostname,
        args.kind,
        args.reload.clone(),
        args.ttl,
        hash.clone(),
        args.starttls,
    );
    if args.dryrun {
        output::text(format!(
            ">>> dry run: would schedule {} ({})",
            job.id,
            job.unit_name()
        ));
    } else {
        rollover::save_job(&job)?;
        output::text(format!(">>> Scheduled rollover job {}", job.id));
        match rollover::start_systemd_unit(&job.id) {
            Ok(()) => output::text(format!(">>> Started {}", job.unit_name())),
            Err(err) => {
                output::text(format!(">>> {err:#}"));
                output::text(format!(
                    ">>> Start it with: systemctl start --no-block {}",
                    job.unit_name()
                ));
                output::text(">>> After a reboot: systemctl start gentlsa-resume.service");
            }
        }
    }
    if output::is_json() {
        output::emit(&Report::Rollover {
            zone: args.zone,
            hostname: args.hostname.map(str::to_string),
            path: args.certfile.display().to_string(),
            certificate: hash,
            ttl: args.ttl,
            dryrun: args.dryrun,
            job: Some(job.id.clone()),
            scheduled: true,
            unit: Some(job.unit_name()),
            info: if args.info {
                Some(cert.details()?)
            } else {
                None
            },
            publish: Vec::new(),
            reload: None,
            prune: Vec::new(),
            next: None,
            error: None,
        })?;
    }
    Ok(0)
}

async fn resume_cmd(filter: Option<&str>, info: bool, dryrun: bool) -> Result<u8> {
    let jobs = rollover::load_jobs(filter)?;
    if jobs.is_empty() {
        output::text(">>> no pending rollovers");
        if output::is_json() {
            output::emit(&Report::Resume { jobs: Vec::new() })?;
        }
        return Ok(0);
    }

    let mut code = 0;
    let mut summaries = Vec::new();
    for job in jobs {
        output::text(format!(">>> Resume {} ({})", job.id, job.phase.as_str()));
        match rollover::acquire(&job.id)? {
            None => {
                output::text(format!(">>> already running: {}", job.id));
                summaries.push(ResumeJob {
                    id: job.id,
                    zone: job.zone,
                    status: "already_running",
                    error: None,
                });
            }
            Some(_guard) => {
                let hostname = job.hostname.clone();
                let args = RolloverArgs {
                    certfile: job.certfile.clone(),
                    zone: job.zone.clone(),
                    ports: &job.ports,
                    hostname: hostname.as_deref(),
                    info,
                    kind: job.kind()?,
                    reload: job.reload.clone(),
                    ttl: job.ttl,
                    dryrun,
                    starttls: job.starttls,
                };
                match execute_rollover(args, Some(job.clone()), false).await {
                    Ok(0) => summaries.push(ResumeJob {
                        id: job.id,
                        zone: job.zone,
                        status: "completed",
                        error: None,
                    }),
                    Ok(job_code) => {
                        code = code.max(job_code);
                        summaries.push(ResumeJob {
                            id: job.id,
                            zone: job.zone,
                            status: "error",
                            error: Some(format!("exit {job_code}")),
                        });
                    }
                    Err(err) => {
                        let message = format!("{err:#}");
                        eprintln!("{message}");
                        code = 1;
                        summaries.push(ResumeJob {
                            id: job.id,
                            zone: job.zone,
                            status: "error",
                            error: Some(message),
                        });
                    }
                }
            }
        }
    }
    if output::is_json() {
        output::emit(&Report::Resume { jobs: summaries })?;
    }
    Ok(code)
}

async fn rollover_cmd(args: RolloverArgs<'_>) -> Result<u8> {
    if args.dryrun || args.reload.is_none() {
        return execute_rollover(args, None, true).await;
    }
    let cert = Certificate::from_file(&args.certfile)?;
    let hash = cert.spki_sha256_hex()?;
    let mut job = rollover::Job::new(
        args.certfile.clone(),
        args.zone.clone(),
        args.ports,
        args.hostname,
        args.kind,
        args.reload.clone(),
        args.ttl,
        hash,
        args.starttls,
    );
    if let Some(existing) = rollover::load_job_in(&rollover::state_dir()?, &job.id)?
        && existing.certificate.eq_ignore_ascii_case(&job.certificate)
    {
        verbose::step(format_args!(
            "resuming existing job {} from {}",
            existing.id,
            existing.phase.as_str()
        ));
        job = existing;
    }
    let Some(_guard) = rollover::acquire(&job.id)? else {
        anyhow::bail!("rollover {} is already running", job.id);
    };
    rollover::save_job(&job)?;
    execute_rollover(args, Some(job), true).await
}

async fn execute_rollover(
    args: RolloverArgs<'_>,
    mut job: Option<rollover::Job>,
    emit: bool,
) -> Result<u8> {
    let RolloverArgs {
        certfile,
        zone,
        ports,
        hostname,
        info,
        kind,
        reload,
        ttl,
        dryrun,
        starttls,
    } = args;
    let publisher = PublisherOpts {
        kind: Some(kind),
        replace: false,
        dryrun,
    };

    verbose::step(format_args!(
        "rollover {} zone={zone} ports={} ttl={ttl} reload={} dryrun={dryrun} job={}",
        certfile.display(),
        ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        reload.as_deref().unwrap_or("(none)"),
        job.as_ref().map(|job| job.id.as_str()).unwrap_or("(none)")
    ));

    let cert = Certificate::from_file(&certfile)?;
    if !output::is_json() {
        cert.print_info(hostname, ports, info)?;
    }
    let hash = cert.spki_sha256_hex()?;
    if let Some(job) = &job
        && !hash.eq_ignore_ascii_case(&job.certificate)
    {
        anyhow::bail!(
            "certificate {} no longer matches job {} (job {}, file {}). Remove the job and start a new rollover",
            certfile.display(),
            job.id,
            job.certificate,
            hash
        );
    }

    let persist = |job: Option<&rollover::Job>| -> Result<()> {
        if let Some(job) = job {
            rollover::save_job(job)?;
        }
        Ok(())
    };

    let mut code = 0;
    let mut error = None;
    let mut publish = Vec::new();
    let mut reload_report = None;
    let mut prune_results = Vec::new();
    let mut next = None;
    let start = job.as_ref().map(|job| job.phase.start_index()).unwrap_or(0);
    let sequence = rollover::phases(reload.is_some());
    let mut skip_reload = false;

    for phase in sequence.iter().skip(start) {
        if code != 0 {
            break;
        }
        if skip_reload
            && matches!(
                phase,
                rollover::Phase::Wait(rollover::WaitReason::BeforeReload) | rollover::Phase::Reload
            )
        {
            continue;
        }
        match phase {
            rollover::Phase::Publish => {
                output::text(">>> Publish");
                for port in ports {
                    let mut item = RolloverPublish {
                        port: *port,
                        owner: tlsa::owner_name(*port, hostname),
                        cloudflare: None,
                        nsupdate: None,
                        route53: None,
                        google: None,
                        azure: None,
                        error: None,
                    };
                    match publish_cert(kind, &zone, hostname, *port, &cert, info, publisher).await?
                    {
                        PublishOutcome::Published(report) => match kind {
                            PublisherKind::Cloudflare => item.cloudflare = Some(report),
                            PublisherKind::Nsupdate => item.nsupdate = Some(report),
                            PublisherKind::Route53 => item.route53 = Some(report),
                            PublisherKind::Google => item.google = Some(report),
                            PublisherKind::Azure => item.azure = Some(report),
                        },
                        PublishOutcome::NotManaged(code_name) => {
                            item.error = Some(code_name.into());
                            error = Some(code_name.into());
                            code = 1;
                        }
                    }
                    publish.push(item);
                    if code != 0 {
                        break;
                    }
                }
                if code == 0
                    && let Some(job) = job.as_mut()
                {
                    job.mark_published(rollover::now_unix());
                    persist(Some(job))?;
                }
            }
            rollover::Phase::Wait(reason) => {
                if *reason == rollover::WaitReason::BeforeReload
                    && live_matches_file(&zone, ports, hostname, &hash, starttls).await
                {
                    output::text(
                        ">>> service already presents the new certificate; skipping reload",
                    );
                    skip_reload = true;
                    if let Some(job) = job.as_mut() {
                        job.mark_already_live(rollover::now_unix());
                        persist(Some(job))?;
                    }
                    continue;
                }
                let seconds = match (reason, job.as_ref()) {
                    (rollover::WaitReason::BeforeReload, Some(job)) => {
                        rollover::remaining(job.reload_after, rollover::now_unix())
                    }
                    (rollover::WaitReason::BeforePrune, Some(job)) => {
                        rollover::remaining(job.prune_after, rollover::now_unix())
                    }
                    _ => rollover::wait_seconds(ttl),
                };
                rollover::wait_ttl(seconds, *reason, dryrun).await;
                if let Some(job) = job.as_mut() {
                    match reason {
                        rollover::WaitReason::BeforeReload => job.mark_waiting_reload(),
                        rollover::WaitReason::BeforePrune => job.mark_ready_to_prune(),
                    }
                    persist(Some(job))?;
                }
            }
            rollover::Phase::Reload => {
                let command = reload.as_deref().expect("reload phase requires --reload");
                output::text(rollover::reload_banner(command, dryrun));
                if dryrun {
                    reload_report = Some(ReloadReport {
                        command: command.to_string(),
                        status: "would_run",
                        exit: None,
                    });
                } else {
                    match rollover::run_reload(command) {
                        Ok(exit) => {
                            reload_report = Some(ReloadReport {
                                command: command.to_string(),
                                status: "ran",
                                exit: Some(exit),
                            });
                            if let Some(job) = job.as_mut() {
                                job.mark_reloaded(rollover::now_unix());
                                persist(Some(job))?;
                            }
                        }
                        Err(err) => {
                            let message = format!("{err:#}");
                            eprintln!("{message}");
                            reload_report = Some(ReloadReport {
                                command: command.to_string(),
                                status: "failed",
                                exit: None,
                            });
                            error = Some(message);
                            code = 1;
                        }
                    }
                }
            }
            rollover::Phase::Prune => {
                if dryrun {
                    output::text(">>> dry run: would prune stale TLSA after reload");
                } else {
                    output::text(">>> Prune");
                    for port in ports {
                        let (port_code, result) =
                            prune(&zone, *port, hostname, Some(kind), false, starttls).await?;
                        if port_code != 0 {
                            code = port_code;
                            error = result.error.clone();
                        }
                        prune_results.push(result);
                        if code != 0 {
                            break;
                        }
                    }
                    if code == 0
                        && let Some(job) = &job
                    {
                        rollover::remove_job(&job.id)?;
                    }
                }
            }
        }
    }

    let advise = (reload.is_none() && code == 0)
        || reload_report
            .as_ref()
            .is_some_and(|report| report.status == "failed");
    if advise {
        let advice = rollover::next_steps(&zone, ports, hostname, kind, ttl, starttls);
        output::text(&advice);
        next = Some(advice);
    }

    if emit && output::is_json() {
        output::emit(&Report::Rollover {
            zone,
            hostname: hostname.map(str::to_string),
            path: certfile.display().to_string(),
            certificate: hash,
            ttl,
            dryrun,
            job: job.map(|job| job.id),
            scheduled: false,
            unit: None,
            info: if info { Some(cert.details()?) } else { None },
            publish,
            reload: reload_report,
            prune: prune_results,
            next,
            error,
        })?;
    }
    Ok(code)
}

async fn live_matches_file(
    zone: &str,
    ports: &[u16],
    hostname: Option<&str>,
    file_hash: &str,
    starttls: Option<StarttlsProto>,
) -> bool {
    if ports.is_empty() {
        return false;
    }
    for port in ports {
        let Some(live) = live_hash(zone, *port, hostname, starttls).await else {
            return false;
        };
        if !live.eq_ignore_ascii_case(file_hash) {
            return false;
        }
    }
    true
}

async fn generate(
    zone: &str,
    port: u16,
    hostname: Option<&str>,
    info: bool,
    params: TlsaParams,
    publisher: PublisherOpts,
    starttls: Option<StarttlsProto>,
) -> Result<(u8, GenerateResult)> {
    let host = connect_host(zone, hostname);
    verbose::step(format_args!("generate {host}:{port}"));
    let cert = fetch_live(&host, port, starttls)?;
    if !output::is_json() {
        cert.print_info_params(hostname, &[port], info, params)?;
    }
    let hash = cert.tlsa_record_data(params)?;
    let mut result = GenerateResult::from_cert(
        port,
        host,
        hostname,
        params,
        hash,
        if info { Some(cert.details()?) } else { None },
    );

    let Some(kind) = publisher.kind else {
        return Ok((0, result));
    };
    match publish_cert(kind, zone, hostname, port, &cert, info, publisher).await? {
        PublishOutcome::Published(report) => {
            match kind {
                PublisherKind::Cloudflare => result.cloudflare = Some(report),
                PublisherKind::Nsupdate => result.nsupdate = Some(report),
                PublisherKind::Route53 => result.route53 = Some(report),
                PublisherKind::Google => result.google = Some(report),
                PublisherKind::Azure => result.azure = Some(report),
            }
            Ok((0, result))
        }
        PublishOutcome::NotManaged(code) => {
            result.error = Some(code.into());
            Ok((1, result))
        }
    }
}

fn status_tag(status: Option<&str>) -> &'static str {
    match status {
        Some("current") => " (current)",
        Some("stale") => " (stale)",
        _ => "",
    }
}

async fn live_hash(
    zone: &str,
    port: u16,
    hostname: Option<&str>,
    starttls: Option<StarttlsProto>,
) -> Option<String> {
    let host = connect_host(zone, hostname);
    let cert = fetch_live(&host, port, starttls).ok()?;
    cert.spki_sha256_hex().ok()
}

async fn list(
    zone_name: &str,
    ports: &[u16],
    hostname: Option<&str>,
    publisher: Option<PublisherKind>,
    info: bool,
    starttls: Option<StarttlsProto>,
) -> Result<u8> {
    let ports_label = if ports.is_empty() {
        "*".to_string()
    } else {
        ports
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    };
    verbose::step(format_args!(
        "list {zone_name} ports={ports_label} hostname={} publisher={} info={info}",
        hostname.unwrap_or("(none)"),
        publisher.map(PublisherKind::flag).unwrap_or("(none)")
    ));

    let mut error = None;
    let listed = match publisher {
        Some(PublisherKind::Cloudflare) => {
            let cf = Cloudflare::from_env_or_config()
                .context("Please install/configure Cloudflare credentials for this to work.")?;
            let Some(zone) = cf.zone_by_name(zone_name).await? else {
                output::text("Not managed by cloudflare. Bailing.");
                error = Some("not_managed_by_cloudflare".into());
                if output::is_json() {
                    emit_empty_list(zone_name, hostname, ports, error.clone())?;
                }
                return Ok(1);
            };
            let records = cf.list_tlsa(&zone, hostname, ports).await?;
            Some(ListedSource::Cloudflare {
                zone: zone.name,
                records,
            })
        }
        Some(PublisherKind::Nsupdate) => {
            let ns = Nsupdate::from_env_or_config()
                .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
            let (records, axfr_note) = ns.list_tlsa(zone_name, hostname, ports).await?;
            Some(ListedSource::Nsupdate {
                server: ns.server_label(),
                records,
                note: axfr_note,
            })
        }
        Some(PublisherKind::Route53) => {
            let r53 = Route53::from_env_or_config()
                .context("Please configure Route 53 in /etc/gentlsa/route53.cfg")?;
            let Some(zone) = r53.zone_by_name(zone_name).await? else {
                output::text("Not managed by Route 53. Bailing.");
                error = Some("not_managed_by_route53".into());
                if output::is_json() {
                    emit_empty_list(zone_name, hostname, ports, error.clone())?;
                }
                return Ok(1);
            };
            Some(ListedSource::Route53 {
                zone: zone.name.clone(),
                records: r53.list_tlsa(&zone, hostname, ports).await?,
            })
        }
        Some(PublisherKind::Google) => {
            let gcloud = Google::from_env_or_config()
                .context("Please configure Google Cloud DNS in /etc/gentlsa/google.cfg")?;
            let Some(zone) = gcloud.zone_by_name(zone_name).await? else {
                output::text("Not managed by Google Cloud DNS. Bailing.");
                error = Some("not_managed_by_google".into());
                if output::is_json() {
                    emit_empty_list(zone_name, hostname, ports, error.clone())?;
                }
                return Ok(1);
            };
            Some(ListedSource::Google {
                zone: zone.dns_name.clone(),
                records: gcloud.list_tlsa(&zone, hostname, ports).await?,
            })
        }
        Some(PublisherKind::Azure) => {
            let azure = Azure::from_env_or_config()
                .context("Please configure Azure DNS in /etc/gentlsa/azure.cfg")?;
            let Some(zone) = azure.zone_by_name(zone_name).await? else {
                output::text("Not managed by Azure DNS. Bailing.");
                error = Some("not_managed_by_azure".into());
                if output::is_json() {
                    emit_empty_list(zone_name, hostname, ports, error.clone())?;
                }
                return Ok(1);
            };
            Some(ListedSource::Azure {
                zone: zone.name.clone(),
                records: azure.list_tlsa(&zone, hostname, ports).await?,
            })
        }
        None => None,
    };

    let dns_names = if !ports.is_empty() {
        ports
            .iter()
            .map(|port| fqdn(zone_name, *port, hostname))
            .collect()
    } else if let Some(listed) = &listed {
        unique_names(listed.names())
    } else {
        Vec::new()
    };

    let live_by_port = if info {
        verbose::step("fetching live certificates to mark current/stale");
        let mut hashes = std::collections::BTreeMap::new();
        let info_ports: Vec<u16> = if !ports.is_empty() {
            ports.to_vec()
        } else {
            dns_names
                .iter()
                .filter_map(|name| tlsa::port_from_owner(name))
                .collect()
        };
        for port in info_ports {
            if let Some(hash) = live_hash(zone_name, port, hostname, starttls).await {
                hashes.insert(port, hash);
            }
        }
        hashes
    } else {
        std::collections::BTreeMap::new()
    };

    let note = if ports.is_empty() && dns_names.is_empty() && listed.is_none() {
        Some("no port specified; pass 443 or 25,465 to query public DNS".to_string())
    } else {
        None
    };

    let mut dns = Vec::new();
    if note.is_none() && !dns_names.is_empty() {
        for name in &dns_names {
            let port = tlsa::port_from_owner(name);
            let live = port
                .and_then(|port| live_by_port.get(&port))
                .map(String::as_str);
            match dns::lookup_tlsa(name).await {
                Ok(records) => dns.push(DnsName {
                    name: name.clone(),
                    records: records
                        .iter()
                        .map(|record| JsonTlsa::from_dns(record, live))
                        .collect(),
                    error: None,
                }),
                Err(err) => {
                    eprintln!("{err:#}");
                    dns.push(DnsName {
                        name: name.clone(),
                        records: Vec::new(),
                        error: Some("lookup failed".into()),
                    });
                }
            }
        }
    }

    let mut cloudflare = None;
    let mut nsupdate = None;
    let mut route53 = None;
    let mut google = None;
    let mut azure = None;
    match &listed {
        Some(ListedSource::Cloudflare { zone, records }) => {
            cloudflare = Some(CloudflareList {
                zone: zone.clone(),
                records: records
                    .iter()
                    .map(|record| {
                        let live = tlsa::port_from_owner(&record.name)
                            .and_then(|port| live_by_port.get(&port))
                            .map(String::as_str);
                        JsonTlsa::from_cf(record, live)
                    })
                    .collect(),
            });
        }
        Some(ListedSource::Nsupdate {
            server,
            records,
            note,
        }) => {
            nsupdate = Some(NsupdateList {
                server: server.clone(),
                records: records
                    .iter()
                    .map(|record| {
                        let live = tlsa::port_from_owner(&record.name)
                            .and_then(|port| live_by_port.get(&port))
                            .map(String::as_str);
                        JsonTlsa::from_nsupdate(record, live)
                    })
                    .collect(),
                note: note.clone(),
            });
        }
        Some(ListedSource::Route53 { zone, records }) => {
            route53 = Some(json_provider_list(zone, records, &live_by_port));
        }
        Some(ListedSource::Google { zone, records }) => {
            google = Some(json_provider_list(zone, records, &live_by_port));
        }
        Some(ListedSource::Azure { zone, records }) => {
            azure = Some(json_provider_list(zone, records, &live_by_port));
        }
        None => {}
    }

    if output::is_json() {
        output::emit(&Report::List {
            zone: zone_name.to_string(),
            hostname: hostname.map(str::to_string),
            ports: ports.to_vec(),
            live: live_by_port
                .iter()
                .map(|(port, hash)| LiveHash {
                    port: *port,
                    certificate: hash.clone(),
                })
                .collect(),
            dns,
            cloudflare,
            nsupdate,
            route53,
            google,
            azure,
            note,
            error,
        })?;
        return Ok(0);
    }

    for (port, hash) in &live_by_port {
        println!(
            "Live _{port}._tcp TLSA {}",
            tlsa::rdata_text(tlsa::USAGE, tlsa::SELECTOR, tlsa::MATCHING, hash)
        );
    }

    if let Some(note) = note {
        println!(">>> DNS");
        println!("({note})");
    } else if dns.is_empty() {
        println!(">>> DNS");
        println!("(none)");
    } else {
        for entry in &dns {
            println!(">>> DNS {}", entry.name);
            if let Some(err) = &entry.error {
                println!("({err})");
            } else if entry.records.is_empty() {
                println!("(none)");
            } else {
                for record in &entry.records {
                    println!("{}{}", record.to_text(), status_tag(record.status));
                }
            }
        }
    }

    if let Some(cf) = &cloudflare {
        println!(">>> Cloudflare {}", cf.zone);
        if cf.records.is_empty() {
            println!("(none)");
        } else {
            for record in &cf.records {
                println!(
                    "{}  {}  {}{}",
                    record.id.as_deref().unwrap_or("-"),
                    record.name.as_deref().unwrap_or("-"),
                    record.to_text(),
                    status_tag(record.status)
                );
            }
        }
    }

    if let Some(ns) = &nsupdate {
        println!(">>> nsupdate {}", ns.server);
        if let Some(note) = &ns.note {
            println!("({note})");
        } else if ns.records.is_empty() {
            println!("(none)");
        } else {
            for record in &ns.records {
                println!(
                    "{}  {}{}",
                    record.name.as_deref().unwrap_or("-"),
                    record.to_text(),
                    status_tag(record.status)
                );
            }
        }
    }

    if let Some(r53) = &route53 {
        print_provider_list("Route 53", r53);
    }
    if let Some(gcloud) = &google {
        print_provider_list("Google Cloud DNS", gcloud);
    }
    if let Some(azure) = &azure {
        print_provider_list("Azure DNS", azure);
    }
    Ok(0)
}

enum ListedSource {
    Cloudflare {
        zone: String,
        records: Vec<cloudflare::ListedTlsa>,
    },
    Nsupdate {
        server: String,
        records: Vec<nsupdate::ListedTlsa>,
        note: Option<String>,
    },
    Route53 {
        zone: String,
        records: Vec<publish::ListedTlsa>,
    },
    Google {
        zone: String,
        records: Vec<publish::ListedTlsa>,
    },
    Azure {
        zone: String,
        records: Vec<publish::ListedTlsa>,
    },
}

impl ListedSource {
    fn names(&self) -> Vec<String> {
        match self {
            Self::Cloudflare { records, .. } => {
                records.iter().map(|record| record.name.clone()).collect()
            }
            Self::Nsupdate { records, .. } => {
                records.iter().map(|record| record.name.clone()).collect()
            }
            Self::Route53 { records, .. }
            | Self::Google { records, .. }
            | Self::Azure { records, .. } => {
                records.iter().map(|record| record.name.clone()).collect()
            }
        }
    }
}

fn json_provider_list(
    zone: &str,
    records: &[publish::ListedTlsa],
    live_by_port: &std::collections::BTreeMap<u16, String>,
) -> ProviderList {
    ProviderList {
        zone: zone.trim_end_matches('.').to_string(),
        records: records
            .iter()
            .map(|record| {
                let live = tlsa::port_from_owner(&record.name)
                    .and_then(|port| live_by_port.get(&port))
                    .map(String::as_str);
                JsonTlsa::from_listed(record, live)
            })
            .collect(),
    }
}

fn print_provider_list(label: &str, list: &ProviderList) {
    println!(">>> {label} {}", list.zone);
    if list.records.is_empty() {
        println!("(none)");
        return;
    }
    for record in &list.records {
        println!(
            "{}  {}{}",
            record.name.as_deref().unwrap_or("-"),
            record.to_text(),
            status_tag(record.status)
        );
    }
}

fn emit_empty_list(
    zone: &str,
    hostname: Option<&str>,
    ports: &[u16],
    error: Option<String>,
) -> Result<()> {
    output::emit(&Report::List {
        zone: zone.to_string(),
        hostname: hostname.map(str::to_string),
        ports: ports.to_vec(),
        live: Vec::new(),
        dns: Vec::new(),
        cloudflare: None,
        nsupdate: None,
        route53: None,
        google: None,
        azure: None,
        note: None,
        error,
    })
}

fn unique_names(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out = Vec::new();
    for name in names {
        if !out
            .iter()
            .any(|existing: &String| existing.eq_ignore_ascii_case(&name))
        {
            out.push(name);
        }
    }
    out
}

async fn prune(
    zone_name: &str,
    port: u16,
    hostname: Option<&str>,
    publisher: Option<PublisherKind>,
    dryrun: bool,
    starttls: Option<StarttlsProto>,
) -> Result<(u8, PruneResult)> {
    let host = connect_host(zone_name, hostname);
    verbose::step(format_args!(
        "prune {host}:{port} publisher={} dryrun={dryrun}",
        publisher.map(PublisherKind::flag).unwrap_or("(none)")
    ));
    let cert = fetch_live(&host, port, starttls)?;
    let live_hash = cert.spki_sha256_hex()?;
    verbose::step(format_args!("live SPKI SHA-256 {live_hash}"));
    output::text(format!(
        "Live TLSA {}",
        tlsa::rdata_text(tlsa::USAGE, tlsa::SELECTOR, tlsa::MATCHING, &live_hash)
    ));

    let name = fqdn(zone_name, port, hostname);
    let mut dns_records = Vec::new();
    match dns::lookup_tlsa(&name).await {
        Ok(records) if records.is_empty() => {
            output::text(format!("DNS: no TLSA records for {name}"));
        }
        Ok(records) => {
            for record in &records {
                let listed = JsonTlsa::from_dns(record, Some(&live_hash));
                output::text(format!(
                    "DNS: {}{}",
                    listed.to_text(),
                    status_tag(listed.status)
                ));
                dns_records.push(listed);
            }
        }
        Err(err) => eprintln!("{err:#}"),
    }

    let mut result = PruneResult {
        port,
        host,
        live: live_hash.clone(),
        dns: dns_records,
        cloudflare: None,
        nsupdate: None,
        route53: None,
        google: None,
        azure: None,
        error: None,
    };

    match publisher {
        Some(PublisherKind::Nsupdate) => {
            let ns = Nsupdate::from_env_or_config()
                .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
            result.nsupdate = Some(
                ns.prune_tlsa(zone_name, hostname, port, &live_hash, dryrun)
                    .await?,
            );
        }
        Some(PublisherKind::Cloudflare) => {
            let cf = Cloudflare::from_env_or_config()
                .context("Please install/configure Cloudflare credentials for this to work.")?;
            let Some(zone) = cf.zone_by_name(zone_name).await? else {
                output::text("Not managed by cloudflare. Bailing.");
                result.error = Some("not_managed_by_cloudflare".into());
                return Ok((1, result));
            };
            result.cloudflare = Some(
                cf.prune_tlsa(&zone, hostname, port, &live_hash, dryrun)
                    .await?,
            );
        }
        Some(PublisherKind::Route53) => {
            let r53 = Route53::from_env_or_config()
                .context("Please configure Route 53 in /etc/gentlsa/route53.cfg")?;
            let Some(zone) = r53.zone_by_name(zone_name).await? else {
                output::text("Not managed by Route 53. Bailing.");
                result.error = Some("not_managed_by_route53".into());
                return Ok((1, result));
            };
            result.route53 = Some(
                r53.prune_tlsa(&zone, hostname, port, &live_hash, dryrun)
                    .await?,
            );
        }
        Some(PublisherKind::Google) => {
            let gcloud = Google::from_env_or_config()
                .context("Please configure Google Cloud DNS in /etc/gentlsa/google.cfg")?;
            let Some(zone) = gcloud.zone_by_name(zone_name).await? else {
                output::text("Not managed by Google Cloud DNS. Bailing.");
                result.error = Some("not_managed_by_google".into());
                return Ok((1, result));
            };
            result.google = Some(
                gcloud
                    .prune_tlsa(&zone, hostname, port, &live_hash, dryrun)
                    .await?,
            );
        }
        Some(PublisherKind::Azure) => {
            let azure = Azure::from_env_or_config()
                .context("Please configure Azure DNS in /etc/gentlsa/azure.cfg")?;
            let Some(zone) = azure.zone_by_name(zone_name).await? else {
                output::text("Not managed by Azure DNS. Bailing.");
                result.error = Some("not_managed_by_azure".into());
                return Ok((1, result));
            };
            result.azure = Some(
                azure
                    .prune_tlsa(&zone, hostname, port, &live_hash, dryrun)
                    .await?,
            );
        }
        None => {}
    }
    Ok((0, result))
}

#[allow(clippy::too_many_arguments)]
async fn verify(
    zone: &str,
    port: u16,
    hostname: Option<&str>,
    info: bool,
    prefix: Option<&str>,
    expiry: Option<(u32, u32)>,
    dnssec_check: bool,
    starttls: Option<StarttlsProto>,
    host_label: Option<String>,
) -> VerifyResult {
    let say = |msg: &str| {
        if output::is_json() {
            return;
        }
        if let Some(prefix) = prefix {
            println!("{prefix}: {msg}");
        } else {
            println!("{msg}");
        }
    };

    let fail = |name: String,
                live: Option<String>,
                dns: Vec<JsonTlsa>,
                info: Option<CertDetails>,
                dnssec: Option<dns::DnssecStatus>| {
        let outcome = verify_outcome(live.as_deref(), &[], &[]);
        say(&outcome.message);
        VerifyResult {
            port,
            name,
            host: host_label.clone(),
            status: outcome.status,
            message: outcome.message,
            exit: outcome.exit,
            live,
            dns,
            info,
            expires_in_days: None,
            dnssec,
        }
    };

    let host = connect_host(zone, hostname);
    verbose::step(format_args!("verify {host}:{port}"));
    let name = fqdn(zone, port, hostname);
    let (dns_record, dnssec) = if dnssec_check {
        match dns::lookup_tlsa_dnssec(&name).await {
            Ok(lookup) => (lookup.records, lookup.dnssec),
            Err(err) => {
                eprintln!("{err:#}");
                return fail(name, None, Vec::new(), None, None);
            }
        }
    } else {
        match dns::lookup_tlsa(&name).await {
            Ok(record) => (record, None),
            Err(err) => {
                eprintln!("{err:#}");
                return fail(name, None, Vec::new(), None, None);
            }
        }
    };

    let cert = match fetch_live(&host, port, starttls) {
        Ok(cert) => cert,
        Err(err) => {
            eprintln!("{err:#}");
            return fail(
                name,
                None,
                dns_record
                    .iter()
                    .map(|record| JsonTlsa::from_dns(record, None))
                    .collect(),
                None,
                dnssec,
            );
        }
    };

    let info_block = if info {
        if output::is_json() {
            match cert.details() {
                Ok(details) => Some(details),
                Err(err) => {
                    eprintln!("{err:#}");
                    return fail(
                        name,
                        None,
                        dns_record
                            .iter()
                            .map(|record| JsonTlsa::from_dns(record, None))
                            .collect(),
                        None,
                        dnssec,
                    );
                }
            }
        } else if let Err(err) = cert.print_info(hostname, &[port], true) {
            eprintln!("{err:#}");
            return fail(
                name,
                None,
                dns_record
                    .iter()
                    .map(|record| JsonTlsa::from_dns(record, None))
                    .collect(),
                None,
                dnssec,
            );
        } else {
            cert.details().ok()
        }
    } else {
        None
    };

    let host_hash = match cert.spki_sha256_hex() {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("{err:#}");
            return fail(
                name,
                None,
                dns_record
                    .iter()
                    .map(|record| JsonTlsa::from_dns(record, None))
                    .collect(),
                info_block,
                dnssec,
            );
        }
    };

    let matched: Vec<Option<bool>> = dns_record
        .iter()
        .map(|record| cert.matches_tlsa(record))
        .collect();
    let dns = dns_record
        .iter()
        .zip(&matched)
        .map(|(record, matched)| JsonTlsa::from_dns_matched(record, *matched))
        .collect();

    let lifetime = cert.lifetime();
    verbose::step(format_args!(
        "certificate {}",
        expiry_phrase(lifetime.days_left, lifetime.not_yet_valid)
    ));

    let mut outcome = verify_outcome(Some(&host_hash), &dns_record, &matched);
    match outcome.exit {
        0 => verbose::step("presented chain matches a DNS TLSA record"),
        2 => verbose::step(format_args!(
            "no DNS TLSA record matches the presented chain (leaf SPKI SHA-256 {host_hash})"
        )),
        _ => verbose::step(format_args!("no TLSA records at {name}")),
    }
    if let Some((warn, critical)) = expiry {
        outcome = apply_expiry(
            outcome,
            lifetime.days_left,
            lifetime.not_yet_valid,
            warn,
            critical,
        );
    }
    outcome = apply_dnssec(outcome, dnssec);
    say(&outcome.message);
    VerifyResult {
        port,
        name,
        host: host_label,
        status: outcome.status,
        message: outcome.message,
        exit: outcome.exit,
        live: Some(host_hash),
        dns,
        info: info_block,
        expires_in_days: Some(lifetime.days_left),
        dnssec,
    }
}

async fn publish_cert(
    kind: PublisherKind,
    zone_name: &str,
    hostname: Option<&str>,
    port: u16,
    cert: &Certificate,
    info: bool,
    publisher: PublisherOpts,
) -> Result<PublishOutcome> {
    let hash = cert.spki_sha256_hex()?;
    let mode = if publisher.replace {
        PublishMode::Replace
    } else {
        PublishMode::Rollover
    };
    verbose::step(format_args!(
        "{} publish zone={zone_name} port={port} replace={} dryrun={}",
        kind.label(),
        publisher.replace,
        publisher.dryrun
    ));
    dns::warn_if_unsigned(zone_name).await;
    match kind {
        PublisherKind::Cloudflare => {
            let cf = Cloudflare::from_env_or_config()
                .context("Please install/configure Cloudflare credentials for this to work.")?;
            let Some(zone) = cf.zone_by_name(zone_name).await? else {
                output::text("Not managed by cloudflare. Bailing.");
                return Ok(PublishOutcome::NotManaged("not_managed_by_cloudflare"));
            };
            if info {
                cf.print_zone_info(&zone);
            }
            let mut report = cf
                .publish_tlsa(&zone, hostname, port, &hash, mode, publisher.dryrun)
                .await?;
            if info {
                report.info = Some(serde_json::to_value(cloudflare::ZoneInfo::from_zone(
                    &zone,
                ))?);
            }
            Ok(PublishOutcome::Published(report))
        }
        PublisherKind::Nsupdate => {
            let ns = Nsupdate::from_env_or_config()
                .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
            if info {
                ns.print_info();
            }
            let mut report = ns
                .publish_tlsa(zone_name, hostname, port, &hash, mode, publisher.dryrun)
                .await?;
            if info {
                report.info = Some(serde_json::to_value(ns.info())?);
            }
            Ok(PublishOutcome::Published(report))
        }
        PublisherKind::Route53 => {
            let r53 = Route53::from_env_or_config()
                .context("Please configure Route 53 in /etc/gentlsa/route53.cfg")?;
            let Some(zone) = r53.zone_by_name(zone_name).await? else {
                output::text("Not managed by Route 53. Bailing.");
                return Ok(PublishOutcome::NotManaged("not_managed_by_route53"));
            };
            if info {
                r53.print_zone_info(&zone);
            }
            let mut report = r53
                .publish_tlsa(&zone, hostname, port, &hash, mode, publisher.dryrun)
                .await?;
            if info {
                report.info = Some(serde_json::to_value(route53::ZoneInfo {
                    id: zone.id,
                    name: zone.name,
                    private: zone.private,
                })?);
            }
            Ok(PublishOutcome::Published(report))
        }
        PublisherKind::Google => {
            let gcloud = Google::from_env_or_config()
                .context("Please configure Google Cloud DNS in /etc/gentlsa/google.cfg")?;
            let Some(zone) = gcloud.zone_by_name(zone_name).await? else {
                output::text("Not managed by Google Cloud DNS. Bailing.");
                return Ok(PublishOutcome::NotManaged("not_managed_by_google"));
            };
            if info {
                gcloud.print_zone_info(&zone);
            }
            let mut report = gcloud
                .publish_tlsa(&zone, hostname, port, &hash, mode, publisher.dryrun)
                .await?;
            if info {
                report.info = Some(serde_json::to_value(google::ZoneInfo {
                    project: gcloud.project().to_string(),
                    name: zone.name,
                    dns_name: zone.dns_name,
                    id: zone.id,
                })?);
            }
            Ok(PublishOutcome::Published(report))
        }
        PublisherKind::Azure => {
            let azure = Azure::from_env_or_config()
                .context("Please configure Azure DNS in /etc/gentlsa/azure.cfg")?;
            let Some(zone) = azure.zone_by_name(zone_name).await? else {
                output::text("Not managed by Azure DNS. Bailing.");
                return Ok(PublishOutcome::NotManaged("not_managed_by_azure"));
            };
            if info {
                azure.print_zone_info(&zone);
            }
            let mut report = azure
                .publish_tlsa(&zone, hostname, port, &hash, mode, publisher.dryrun)
                .await?;
            if info {
                report.info = Some(serde_json::to_value(azure::ZoneInfo {
                    subscription: azure.subscription().to_string(),
                    resource_group: zone.resource_group,
                    name: zone.name,
                    id: zone.id,
                })?);
            }
            Ok(PublishOutcome::Published(report))
        }
    }
}

async fn nsupdate_cmd(info: bool) -> Result<u8> {
    verbose::step(format_args!("nsupdate info={info}"));
    let ns = Nsupdate::from_env_or_config()
        .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
    if !output::is_json() {
        ns.print_info();
    }
    if output::is_json() {
        let info = ns.info();
        output::emit(&Report::Nsupdate {
            server: info.server,
            key_name: info.key_name,
            algorithm: info.algorithm,
            ttl: info.ttl,
        })?;
    }
    Ok(0)
}

async fn cloudflare_cmd(info: bool, listzones: bool) -> Result<u8> {
    let show_zones = listzones || !info;
    verbose::step(format_args!(
        "cloudflare info={info} listzones={show_zones}"
    ));
    let cf = Cloudflare::from_env_or_config()
        .context("Please install/configure Cloudflare credentials for this to work.")?;

    let auth = if info {
        output::text(">>> Cloudflare Information:");
        output::text(format!("Auth: {}", cf.auth_label()));
        Some(cf.auth_label().to_string())
    } else {
        None
    };

    let zones = if show_zones {
        let zones = cf.list_zones().await?;
        if output::is_json() {
            Some(
                zones
                    .into_iter()
                    .map(|zone| ZoneRef {
                        id: zone.id,
                        name: zone.name,
                    })
                    .collect(),
            )
        } else if zones.is_empty() {
            println!("No Cloudflare zones found.");
            Some(Vec::new())
        } else {
            println!(">>> Cloudflare Zones:");
            for zone in &zones {
                println!("{}  {}", zone.id, zone.name);
            }
            Some(
                zones
                    .into_iter()
                    .map(|zone| ZoneRef {
                        id: zone.id,
                        name: zone.name,
                    })
                    .collect(),
            )
        }
    } else {
        None
    };

    if output::is_json() {
        output::emit(&Report::Cloudflare { auth, zones })?;
    }
    Ok(0)
}

async fn route53_cmd(info: bool, listzones: bool) -> Result<u8> {
    let show_zones = listzones || !info;
    verbose::step(format_args!("route53 info={info} listzones={show_zones}"));
    let r53 = Route53::from_env_or_config()
        .context("Please configure Route 53 in /etc/gentlsa/route53.cfg")?;

    let auth = if info {
        output::text(">>> Route 53 Information:");
        output::text(format!("Auth: {}", r53.auth_label()));
        Some(r53.auth_label())
    } else {
        None
    };

    let zones = if show_zones {
        let zones = r53.list_zones().await?;
        if output::is_json() {
            Some(zones.into_iter().map(route53_zone_ref).collect())
        } else if zones.is_empty() {
            println!("No Route 53 hosted zones found.");
            Some(Vec::new())
        } else {
            println!(">>> Route 53 Hosted Zones:");
            for zone in &zones {
                println!("{}  {}", zone.id, zone.name);
            }
            Some(zones.into_iter().map(route53_zone_ref).collect())
        }
    } else {
        None
    };

    if output::is_json() {
        output::emit(&Report::Route53 { auth, zones })?;
    }
    Ok(0)
}

async fn google_cmd(info: bool, listzones: bool) -> Result<u8> {
    let show_zones = listzones || !info;
    verbose::step(format_args!("google info={info} listzones={show_zones}"));
    let gcloud = Google::from_env_or_config()
        .context("Please configure Google Cloud DNS in /etc/gentlsa/google.cfg")?;

    let (auth, project) = if info {
        output::text(">>> Google Cloud DNS Information:");
        output::text(format!("Auth: {}", gcloud.auth_label()));
        output::text(format!("Project: {}", gcloud.project()));
        (
            Some(gcloud.auth_label()),
            Some(gcloud.project().to_string()),
        )
    } else {
        (None, None)
    };

    let zones = if show_zones {
        let zones = gcloud.list_zones().await?;
        if output::is_json() {
            Some(zones.into_iter().map(google_zone_ref).collect())
        } else if zones.is_empty() {
            println!("No Google Cloud DNS managed zones found.");
            Some(Vec::new())
        } else {
            println!(">>> Google Cloud DNS Zones:");
            for zone in &zones {
                println!("{}  {}", zone.name, zone.dns_name);
            }
            Some(zones.into_iter().map(google_zone_ref).collect())
        }
    } else {
        None
    };

    if output::is_json() {
        output::emit(&Report::Google {
            auth,
            project,
            zones,
        })?;
    }
    Ok(0)
}

fn route53_zone_ref(zone: route53::HostedZone) -> ZoneRef {
    ZoneRef {
        id: zone.id,
        name: zone.name.trim_end_matches('.').to_string(),
    }
}

fn google_zone_ref(zone: google::ManagedZone) -> ZoneRef {
    ZoneRef {
        id: zone.name,
        name: zone.dns_name.trim_end_matches('.').to_string(),
    }
}

async fn azure_cmd(info: bool, listzones: bool) -> Result<u8> {
    let show_zones = listzones || !info;
    verbose::step(format_args!("azure info={info} listzones={show_zones}"));
    let azure = Azure::from_env_or_config()
        .context("Please configure Azure DNS in /etc/gentlsa/azure.cfg")?;

    let (auth, subscription) = if info {
        output::text(">>> Azure DNS Information:");
        output::text(format!("Auth: {}", azure.auth_label()));
        output::text(format!("Subscription: {}", azure.subscription()));
        (
            Some(azure.auth_label()),
            Some(azure.subscription().to_string()),
        )
    } else {
        (None, None)
    };

    let zones = if show_zones {
        let zones = azure.list_zones().await?;
        if output::is_json() {
            Some(zones.into_iter().map(azure_zone_ref).collect())
        } else if zones.is_empty() {
            println!("No Azure DNS zones found.");
            Some(Vec::new())
        } else {
            println!(">>> Azure DNS Zones:");
            for zone in &zones {
                println!("{}  {}", zone.resource_group, zone.name);
            }
            Some(zones.into_iter().map(azure_zone_ref).collect())
        }
    } else {
        None
    };

    if output::is_json() {
        output::emit(&Report::Azure {
            auth,
            subscription,
            zones,
        })?;
    }
    Ok(0)
}

fn azure_zone_ref(zone: azure::DnsZone) -> ZoneRef {
    ZoneRef {
        id: zone.id,
        name: zone.name.trim_end_matches('.').to_string(),
    }
}
