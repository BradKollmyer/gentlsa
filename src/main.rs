mod cert;
mod cli;
mod cloudflare;
mod dns;
mod nsupdate;
mod output;
mod publish;
mod report;
mod tlsa;
mod verbose;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::cert::{CertDetails, Certificate, fetch_live};
use crate::cli::{Cli, Command};
use crate::cloudflare::Client as Cloudflare;
use crate::nsupdate::Config as Nsupdate;
use crate::publish::{PublishMode, PublishReport};
use crate::report::{
    CloudflareList, DnsName, FileRecord, GenerateResult, JsonTlsa, LiveHash, NsupdateList,
    PruneResult, Report, VerifyResult, ZoneRef, verify_outcome, worst_verify_exit,
};
use crate::tlsa::{connect_host, fqdn};

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

    match cli.command {
        Command::Generate {
            zone,
            ports,
            hostname,
            info,
            cloudflare,
            nsupdate,
            replace,
            dryrun,
        } => {
            let publisher = PublisherOpts {
                cloudflare,
                nsupdate,
                replace,
                dryrun,
            };
            publisher.require_replace()?;
            let mut code = 0;
            let mut results = Vec::new();
            for port in ports.as_slice() {
                let (port_code, result) =
                    generate(&zone, *port, hostname.as_deref(), info, publisher).await?;
                code = port_code;
                results.push(result);
            }
            if output::is_json() {
                output::emit(&Report::Generate {
                    zone,
                    hostname,
                    results,
                })?;
            }
            Ok(code)
        }
        Command::List {
            zone,
            ports,
            hostname,
            cloudflare,
            nsupdate,
            info,
        } => {
            list(
                &zone,
                ports.as_ref().map(cli::Ports::as_slice).unwrap_or(&[]),
                hostname.as_deref(),
                cloudflare,
                nsupdate,
                info,
            )
            .await
        }
        Command::Prune {
            zone,
            ports,
            hostname,
            cloudflare,
            nsupdate,
            dryrun,
        } => {
            let mut code = 0;
            let mut results = Vec::new();
            for port in ports.as_slice() {
                let (port_code, result) = prune(
                    &zone,
                    *port,
                    hostname.as_deref(),
                    cloudflare,
                    nsupdate,
                    dryrun,
                )
                .await?;
                code = port_code;
                results.push(result);
            }
            if output::is_json() {
                output::emit(&Report::Prune {
                    zone,
                    hostname,
                    results,
                })?;
            }
            Ok(code)
        }
        Command::Verify {
            zone,
            ports,
            hostname,
            info,
        } => {
            let ports = ports.as_slice();
            let multi = ports.len() > 1;
            let mut results = Vec::new();
            for port in ports {
                results.push(verify(&zone, *port, hostname.as_deref(), info, multi).await);
            }
            let worst = worst_verify_exit(results.iter().map(|result| result.exit));
            if output::is_json() {
                output::emit(&Report::Verify {
                    zone,
                    hostname,
                    results,
                    exit: worst,
                })?;
            }
            Ok(worst)
        }
        Command::Cloudflare { info, listzones } => cloudflare_cmd(info, listzones).await,
        Command::Nsupdate { info } => nsupdate_cmd(info).await,
        Command::File {
            certfile,
            zone,
            hostname,
            ports,
            info,
            cloudflare,
            nsupdate,
            replace,
            dryrun,
        } => {
            let publisher = PublisherOpts {
                cloudflare,
                nsupdate,
                replace,
                dryrun,
            };
            publisher.require_replace()?;
            let ports = ports.as_ref().map(cli::Ports::as_slice).unwrap_or(&[]);
            verbose::step(format_args!("file {}", certfile.display()));
            let cert = Certificate::from_file(&certfile)?;
            if !output::is_json() {
                cert.print_info(hostname.as_deref(), ports, info)?;
            }

            let mut code = 0;
            let mut cf_reports = Vec::new();
            let mut ns_reports = Vec::new();
            let mut error = None;
            if publisher.active() {
                let zone = zone.as_deref().with_context(|| {
                    if publisher.nsupdate {
                        "--zone is required with --nsupdate"
                    } else {
                        "--zone is required with --cloudflare"
                    }
                })?;
                if ports.is_empty() {
                    anyhow::bail!(if publisher.nsupdate {
                        "--port is required with --nsupdate"
                    } else {
                        "--port is required with --cloudflare"
                    });
                }
                for port in ports {
                    if publisher.cloudflare {
                        match update_cloudflare(
                            zone,
                            hostname.as_deref(),
                            *port,
                            &cert,
                            info,
                            publisher,
                        )
                        .await?
                        {
                            UpdateCf::Published(report) => cf_reports.push(report),
                            UpdateCf::NotManaged => {
                                error = Some("not_managed_by_cloudflare".into());
                                code = 1;
                                break;
                            }
                        }
                    } else {
                        ns_reports.push(
                            update_nsupdate(
                                zone,
                                hostname.as_deref(),
                                *port,
                                &cert,
                                info,
                                publisher,
                            )
                            .await?,
                        );
                    }
                }
            }

            if output::is_json() {
                let hash = cert.spki_sha256_hex()?;
                verbose::step(format_args!("SPKI SHA-256 {hash}"));
                output::emit(&Report::File {
                    path: certfile.display().to_string(),
                    usage: tlsa::USAGE,
                    selector: tlsa::SELECTOR,
                    matching: tlsa::MATCHING,
                    certificate: hash,
                    info: if info { Some(cert.details()?) } else { None },
                    records: ports
                        .iter()
                        .map(|port| FileRecord {
                            port: *port,
                            owner: tlsa::owner_name(*port, hostname.as_deref()),
                        })
                        .collect(),
                    cloudflare: cf_reports,
                    nsupdate: ns_reports,
                    error,
                })?;
            }
            Ok(code)
        }
    }
}

#[derive(Clone, Copy)]
struct PublisherOpts {
    cloudflare: bool,
    nsupdate: bool,
    replace: bool,
    dryrun: bool,
}

impl PublisherOpts {
    fn active(self) -> bool {
        self.cloudflare || self.nsupdate
    }

    fn require_replace(self) -> Result<()> {
        if self.replace && !self.active() {
            anyhow::bail!("--replace requires --cloudflare or --nsupdate");
        }
        Ok(())
    }
}

async fn generate(
    zone: &str,
    port: u16,
    hostname: Option<&str>,
    info: bool,
    publisher: PublisherOpts,
) -> Result<(u8, GenerateResult)> {
    let host = connect_host(zone, hostname);
    verbose::step(format_args!("generate {host}:{port}"));
    let cert = fetch_live(&host, port)?;
    if !output::is_json() {
        cert.print_info(hostname, &[port], info)?;
    }
    let hash = cert.spki_sha256_hex()?;
    let mut result = GenerateResult::from_cert(
        port,
        host,
        hostname,
        hash,
        if info { Some(cert.details()?) } else { None },
    );

    if publisher.nsupdate {
        result.nsupdate =
            Some(update_nsupdate(zone, hostname, port, &cert, info, publisher).await?);
        return Ok((0, result));
    }

    if !publisher.cloudflare {
        return Ok((0, result));
    }

    match update_cloudflare(zone, hostname, port, &cert, info, publisher).await? {
        UpdateCf::Published(report) => {
            result.cloudflare = Some(report);
            Ok((0, result))
        }
        UpdateCf::NotManaged => {
            result.error = Some("not_managed_by_cloudflare".into());
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

async fn live_hash(zone: &str, port: u16, hostname: Option<&str>) -> Option<String> {
    let host = connect_host(zone, hostname);
    let cert = fetch_live(&host, port).ok()?;
    cert.spki_sha256_hex().ok()
}

async fn list(
    zone_name: &str,
    ports: &[u16],
    hostname: Option<&str>,
    use_cloudflare: bool,
    use_nsupdate: bool,
    info: bool,
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
        "list {zone_name} ports={ports_label} hostname={} cloudflare={use_cloudflare} nsupdate={use_nsupdate} info={info}",
        hostname.unwrap_or("(none)")
    ));

    let mut error = None;
    let cf_listed = if use_cloudflare {
        let cf = Cloudflare::from_env_or_config()
            .context("Please install/configure Cloudflare credentials for this to work.")?;
        let Some(zone) = cf.zone_by_name(zone_name).await? else {
            output::text("Not managed by cloudflare. Bailing.");
            error = Some("not_managed_by_cloudflare".into());
            if output::is_json() {
                output::emit(&Report::List {
                    zone: zone_name.to_string(),
                    hostname: hostname.map(str::to_string),
                    ports: ports.to_vec(),
                    live: Vec::new(),
                    dns: Vec::new(),
                    cloudflare: None,
                    nsupdate: None,
                    note: None,
                    error,
                })?;
            }
            return Ok(1);
        };
        let records = cf.list_tlsa(&zone, hostname, ports).await?;
        Some((zone.name, records))
    } else {
        None
    };

    let ns_listed = if use_nsupdate {
        let ns = Nsupdate::from_env_or_config()
            .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
        let (records, axfr_note) = ns.list_tlsa(zone_name, hostname, ports).await?;
        Some((ns.server_label(), records, axfr_note))
    } else {
        None
    };

    let dns_names = if !ports.is_empty() {
        ports
            .iter()
            .map(|port| fqdn(zone_name, *port, hostname))
            .collect()
    } else if let Some((_, records)) = &cf_listed {
        unique_names(records.iter().map(|record| record.name.clone()))
    } else if let Some((_, records, _)) = &ns_listed {
        unique_names(records.iter().map(|record| record.name.clone()))
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
            if let Some(hash) = live_hash(zone_name, port, hostname).await {
                hashes.insert(port, hash);
            }
        }
        hashes
    } else {
        std::collections::BTreeMap::new()
    };

    let note =
        if ports.is_empty() && dns_names.is_empty() && cf_listed.is_none() && ns_listed.is_none() {
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
                        .map(|record| {
                            JsonTlsa::from_dns(record, live)
                        })
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

    let cloudflare = cf_listed.as_ref().map(|(zone, records)| CloudflareList {
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

    let nsupdate = ns_listed
        .as_ref()
        .map(|(server, records, axfr_note)| NsupdateList {
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
            note: axfr_note.clone(),
        });

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
    Ok(0)
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
    use_cloudflare: bool,
    use_nsupdate: bool,
    dryrun: bool,
) -> Result<(u8, PruneResult)> {
    let host = connect_host(zone_name, hostname);
    verbose::step(format_args!(
        "prune {host}:{port} cloudflare={use_cloudflare} nsupdate={use_nsupdate} dryrun={dryrun}"
    ));
    let cert = fetch_live(&host, port)?;
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
        error: None,
    };

    if use_nsupdate {
        let ns = Nsupdate::from_env_or_config()
            .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
        result.nsupdate = Some(
            ns.prune_tlsa(zone_name, hostname, port, &live_hash, dryrun)
                .await?,
        );
        return Ok((0, result));
    }

    if !use_cloudflare {
        return Ok((0, result));
    }

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
    Ok((0, result))
}

async fn verify(
    zone: &str,
    port: u16,
    hostname: Option<&str>,
    info: bool,
    prefix: bool,
) -> VerifyResult {
    let say = |msg: &str| {
        if output::is_json() {
            return;
        }
        if prefix {
            println!("{port}: {msg}");
        } else {
            println!("{msg}");
        }
    };

    let fail =
        |name: String, live: Option<String>, dns: Vec<JsonTlsa>, info: Option<CertDetails>| {
            let outcome = verify_outcome(live.as_deref(), &[]);
            say(&outcome.message);
            VerifyResult {
                port,
                name,
                status: outcome.status,
                message: outcome.message,
                exit: outcome.exit,
                live,
                dns,
                info,
            }
        };

    let host = connect_host(zone, hostname);
    verbose::step(format_args!("verify {host}:{port}"));
    let name = fqdn(zone, port, hostname);
    let dns_record = match dns::lookup_tlsa(&name).await {
        Ok(record) => record,
        Err(err) => {
            eprintln!("{err:#}");
            return fail(name, None, Vec::new(), None);
        }
    };

    let cert = match fetch_live(&host, port) {
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
            );
        }
    };

    let dns = dns_record
        .iter()
        .map(|record| {
            JsonTlsa::from_dns(record, Some(&host_hash))
        })
        .collect();

    let outcome = verify_outcome(Some(&host_hash), &dns_record);
    match outcome.exit {
        0 => verbose::step("live hash matches a DNS TLSA record"),
        2 => verbose::step(format_args!(
            "live hash {host_hash} does not match any DNS TLSA record"
        )),
        _ => verbose::step(format_args!("no TLSA records at {name}")),
    }
    say(&outcome.message);
    VerifyResult {
        port,
        name,
        status: outcome.status,
        message: outcome.message,
        exit: outcome.exit,
        live: Some(host_hash),
        dns,
        info: info_block,
    }
}

enum UpdateCf {
    Published(PublishReport),
    NotManaged,
}

async fn update_cloudflare(
    zone_name: &str,
    hostname: Option<&str>,
    port: u16,
    cert: &Certificate,
    info: bool,
    publisher: PublisherOpts,
) -> Result<UpdateCf> {
    verbose::step(format_args!(
        "Cloudflare publish zone={zone_name} port={port} replace={} dryrun={}",
        publisher.replace, publisher.dryrun
    ));
    let cf = Cloudflare::from_env_or_config()
        .context("Please install/configure Cloudflare credentials for this to work.")?;
    let Some(zone) = cf.zone_by_name(zone_name).await? else {
        output::text("Not managed by cloudflare. Bailing.");
        return Ok(UpdateCf::NotManaged);
    };
    if info {
        cf.print_zone_info(&zone);
    }
    let hash = cert.spki_sha256_hex()?;
    let mode = if publisher.replace {
        PublishMode::Replace
    } else {
        PublishMode::Rollover
    };
    let mut report = cf
        .publish_tlsa(&zone, hostname, port, &hash, mode, publisher.dryrun)
        .await?;
    if info {
        report.info = Some(serde_json::to_value(cloudflare::ZoneInfo::from_zone(
            &zone,
        ))?);
    }
    Ok(UpdateCf::Published(report))
}

async fn update_nsupdate(
    zone_name: &str,
    hostname: Option<&str>,
    port: u16,
    cert: &Certificate,
    info: bool,
    publisher: PublisherOpts,
) -> Result<PublishReport> {
    verbose::step(format_args!(
        "nsupdate publish zone={zone_name} port={port} replace={} dryrun={}",
        publisher.replace, publisher.dryrun
    ));
    let ns = Nsupdate::from_env_or_config()
        .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
    if info {
        ns.print_info();
    }
    let hash = cert.spki_sha256_hex()?;
    let mode = if publisher.replace {
        PublishMode::Replace
    } else {
        PublishMode::Rollover
    };
    let mut report = ns
        .publish_tlsa(zone_name, hostname, port, &hash, mode, publisher.dryrun)
        .await?;
    if info {
        report.info = Some(serde_json::to_value(ns.info())?);
    }
    Ok(report)
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
