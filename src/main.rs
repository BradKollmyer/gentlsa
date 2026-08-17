mod cert;
mod cli;
mod cloudflare;
mod dns;
mod tlsa;
mod verbose;

use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use crate::cert::{Certificate, fetch_live};
use crate::cli::{Cli, Command};
use crate::cloudflare::Client as Cloudflare;
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

    match cli.command {
        Command::Generate {
            zone,
            ports,
            hostname,
            info,
            cloudflare,
            replace,
            dryrun,
        } => {
            let mut code = 0;
            for port in ports.as_slice() {
                code = generate(
                    &zone,
                    *port,
                    hostname.as_deref(),
                    info,
                    cloudflare,
                    replace,
                    dryrun,
                )
                .await?;
            }
            Ok(code)
        }
        Command::List {
            zone,
            ports,
            hostname,
            cloudflare,
            info,
        } => {
            list(
                &zone,
                ports.as_ref().map(cli::Ports::as_slice).unwrap_or(&[]),
                hostname.as_deref(),
                cloudflare,
                info,
            )
            .await
        }
        Command::Prune {
            zone,
            ports,
            hostname,
            cloudflare,
            dryrun,
        } => {
            let mut code = 0;
            for port in ports.as_slice() {
                code = prune(&zone, *port, hostname.as_deref(), cloudflare, dryrun).await?;
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
            let mut worst = 0;
            for port in ports {
                let code = verify(&zone, *port, hostname.as_deref(), info, multi).await;
                if code > worst {
                    worst = code;
                }
            }
            Ok(worst)
        }
        Command::Cloudflare { info, listzones } => cloudflare_cmd(info, listzones).await,
        Command::File {
            certfile,
            zone,
            hostname,
            ports,
            info,
            cloudflare,
            replace,
            dryrun,
        } => {
            let ports = ports.as_ref().map(cli::Ports::as_slice).unwrap_or(&[]);
            verbose::step(format_args!("file {}", certfile.display()));
            let cert = Certificate::from_file(&certfile)?;
            cert.print_info(hostname.as_deref(), ports, info)?;
            if cloudflare {
                let zone = zone
                    .as_deref()
                    .context("--zone is required with --cloudflare")?;
                if ports.is_empty() {
                    anyhow::bail!("--port is required with --cloudflare");
                }
                let mut code = 0;
                for port in ports {
                    code = update_cloudflare(
                        zone,
                        hostname.as_deref(),
                        *port,
                        &cert,
                        info,
                        replace,
                        dryrun,
                    )
                    .await?;
                }
                return Ok(code);
            }
            Ok(0)
        }
    }
}

async fn generate(
    zone: &str,
    port: u16,
    hostname: Option<&str>,
    info: bool,
    use_cloudflare: bool,
    replace: bool,
    dryrun: bool,
) -> Result<u8> {
    let host = connect_host(zone, hostname);
    verbose::step(format_args!("generate {host}:{port}"));
    let cert = fetch_live(&host, port)?;
    cert.print_info(hostname, &[port], info)?;

    if use_cloudflare {
        return update_cloudflare(zone, hostname, port, &cert, info, replace, dryrun).await;
    }
    Ok(0)
}

fn hash_tag(live_hash: Option<&str>, record_hash: &str) -> &'static str {
    match live_hash {
        Some(live) if tlsa::hashes_equal(live, record_hash) => " (current)",
        Some(_) => " (stale)",
        None => "",
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
        "list {zone_name} ports={ports_label} hostname={} cloudflare={use_cloudflare} info={info}",
        hostname.unwrap_or("(none)")
    ));

    let cf_listed = if use_cloudflare {
        let cf = Cloudflare::from_env_or_config()
            .context("Please install/configure Cloudflare credentials for this to work.")?;
        let Some(zone) = cf.zone_by_name(zone_name).await? else {
            println!("Not managed by cloudflare. Bailing.");
            return Ok(1);
        };
        let records = cf.list_tlsa(&zone, hostname, ports).await?;
        Some((zone.name, records))
    } else {
        None
    };

    let dns_names = if !ports.is_empty() {
        ports
            .iter()
            .map(|port| fqdn(zone_name, *port, hostname))
            .collect()
    } else if let Some((_, records)) = &cf_listed {
        let mut names = Vec::new();
        for record in records {
            if !names
                .iter()
                .any(|name: &String| name.eq_ignore_ascii_case(&record.name))
            {
                names.push(record.name.clone());
            }
        }
        names
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

    for (port, hash) in &live_by_port {
        println!("Live _{port}._tcp TLSA 3 1 1 {hash}");
    }

    if ports.is_empty() && dns_names.is_empty() && cf_listed.is_none() {
        println!(">>> DNS");
        println!("(no port specified; pass 443 or 25,465 to query public DNS)");
    } else if dns_names.is_empty() {
        println!(">>> DNS");
        println!("(none)");
    } else {
        for name in &dns_names {
            let port = tlsa::port_from_owner(name);
            let live = port
                .and_then(|port| live_by_port.get(&port))
                .map(String::as_str);
            println!(">>> DNS {name}");
            match dns::lookup_tlsa(name).await {
                Ok(records) if records.is_empty() => println!("(none)"),
                Ok(records) => {
                    for record in records {
                        println!("{}{}", record, hash_tag(live, &record.certificate));
                    }
                }
                Err(err) => {
                    eprintln!("{err:#}");
                    println!("(lookup failed)");
                }
            }
        }
    }

    if let Some((zone, records)) = &cf_listed {
        println!(">>> Cloudflare {zone}");
        if records.is_empty() {
            println!("(none)");
        } else {
            for record in records {
                let live = tlsa::port_from_owner(&record.name)
                    .and_then(|port| live_by_port.get(&port))
                    .map(String::as_str);
                println!(
                    "{}  {}  {}{}",
                    record.id,
                    record.name,
                    record.to_text(),
                    hash_tag(live, &record.certificate)
                );
            }
        }
    }
    Ok(0)
}

async fn prune(
    zone_name: &str,
    port: u16,
    hostname: Option<&str>,
    use_cloudflare: bool,
    dryrun: bool,
) -> Result<u8> {
    let host = connect_host(zone_name, hostname);
    verbose::step(format_args!(
        "prune {host}:{port} cloudflare={use_cloudflare} dryrun={dryrun}"
    ));
    let cert = fetch_live(&host, port)?;
    let live_hash = cert.spki_sha256_hex()?;
    verbose::step(format_args!("live SPKI SHA-256 {live_hash}"));
    println!("Live TLSA 3 1 1 {live_hash}");

    let name = fqdn(zone_name, port, hostname);
    match dns::lookup_tlsa(&name).await {
        Ok(records) if records.is_empty() => println!("DNS: no TLSA records for {name}"),
        Ok(records) => {
            for record in &records {
                let stale = !tlsa::hashes_equal(&live_hash, &record.certificate);
                println!(
                    "DNS: {} {}",
                    record,
                    if stale { "(stale)" } else { "(current)" }
                );
            }
        }
        Err(err) => eprintln!("{err:#}"),
    }

    if use_cloudflare {
        let cf = Cloudflare::from_env_or_config()
            .context("Please install/configure Cloudflare credentials for this to work.")?;
        let Some(zone) = cf.zone_by_name(zone_name).await? else {
            println!("Not managed by cloudflare. Bailing.");
            return Ok(1);
        };
        cf.prune_tlsa(&zone, hostname, port, &live_hash, dryrun)
            .await?;
    }
    Ok(0)
}

async fn verify(zone: &str, port: u16, hostname: Option<&str>, info: bool, prefix: bool) -> u8 {
    let say = |msg: &str| {
        if prefix {
            println!("{port}: {msg}");
        } else {
            println!("{msg}");
        }
    };

    let host = connect_host(zone, hostname);
    verbose::step(format_args!("verify {host}:{port}"));
    let name = fqdn(zone, port, hostname);
    let dns_record = match dns::lookup_tlsa(&name).await {
        Ok(record) => record,
        Err(err) => {
            eprintln!("{err:#}");
            say("UNKNOWN - Something went wrong. Check logs");
            return 3;
        }
    };

    let cert = match fetch_live(&host, port) {
        Ok(cert) => cert,
        Err(err) => {
            eprintln!("{err:#}");
            say("UNKNOWN - Something went wrong. Check logs");
            return 3;
        }
    };

    if info && let Err(err) = cert.print_info(hostname, &[port], true) {
        eprintln!("{err:#}");
        say("UNKNOWN - Something went wrong. Check logs");
        return 3;
    }

    let host_hash = match cert.spki_sha256_hex() {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("{err:#}");
            say("UNKNOWN - Something went wrong. Check logs");
            return 3;
        }
    };

    if dns_record.is_empty() {
        verbose::step(format_args!("no TLSA records at {name}"));
        say("UNKNOWN - Something went wrong. Check logs");
        return 3;
    }

    if dns_record
        .iter()
        .any(|record| tlsa::hashes_equal(&host_hash, &record.certificate))
    {
        verbose::step("live hash matches a DNS TLSA record");
        say("OK - TLSA is valid");
        0
    } else {
        verbose::step(format_args!(
            "live hash {host_hash} does not match any DNS TLSA record"
        ));
        let dns_text = dns_record
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        say(&format!("ERROR - TLSA invalid: {host_hash} != {dns_text}"));
        2
    }
}

async fn update_cloudflare(
    zone_name: &str,
    hostname: Option<&str>,
    port: u16,
    cert: &Certificate,
    info: bool,
    replace: bool,
    dryrun: bool,
) -> Result<u8> {
    verbose::step(format_args!(
        "Cloudflare publish zone={zone_name} port={port} replace={replace} dryrun={dryrun}"
    ));
    let cf = Cloudflare::from_env_or_config()
        .context("Please install/configure Cloudflare credentials for this to work.")?;
    let Some(zone) = cf.zone_by_name(zone_name).await? else {
        println!("Not managed by cloudflare. Bailing.");
        return Ok(1);
    };
    if info {
        cf.print_zone_info(&zone);
    }
    let hash = cert.spki_sha256_hex()?;
    let mode = if replace {
        cloudflare::PublishMode::Replace
    } else {
        cloudflare::PublishMode::Rollover
    };
    cf.publish_tlsa(&zone, hostname, port, &hash, mode, dryrun)
        .await?;
    Ok(0)
}

async fn cloudflare_cmd(info: bool, listzones: bool) -> Result<u8> {
    verbose::step(format_args!(
        "cloudflare info={info} listzones={}",
        listzones || !info
    ));
    let cf = Cloudflare::from_env_or_config()
        .context("Please install/configure Cloudflare credentials for this to work.")?;
    if info {
        println!(">>> Cloudflare Information:");
        println!("Auth: {}", cf.auth_label());
    }

    if listzones || !info {
        let zones = cf.list_zones().await?;
        if zones.is_empty() {
            println!("No Cloudflare zones found.");
        } else {
            println!(">>> Cloudflare Zones:");
            for zone in zones {
                println!("{}  {}", zone.id, zone.name);
            }
        }
    }
    Ok(0)
}
