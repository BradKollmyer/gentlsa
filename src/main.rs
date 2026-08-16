mod cert;
mod cli;
mod cloudflare;
mod dns;
mod tlsa;

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
    match Cli::parse().command {
        Command::Generate {
            zone,
            port,
            hostname,
            info,
            cloudflare,
            dryrun,
        } => generate(&zone, port, hostname.as_deref(), info, cloudflare, dryrun).await,
        Command::Verify {
            zone,
            port,
            hostname,
            info,
        } => Ok(verify(&zone, port, hostname.as_deref(), info).await),
        Command::Cloudflare { info, listzones } => cloudflare_cmd(info, listzones).await,
        Command::File {
            certfile,
            hostname,
            port,
            info,
        } => {
            let cert = Certificate::from_file(&certfile)?;
            cert.print_info(hostname.as_deref(), port, info)?;
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
    dryrun: bool,
) -> Result<u8> {
    let host = connect_host(zone, hostname);
    let cert = fetch_live(&host, port)?;
    cert.print_info(hostname, Some(port), info)?;

    if use_cloudflare {
        return update_cloudflare(zone, hostname, port, &cert, info, dryrun).await;
    }
    Ok(0)
}

async fn verify(zone: &str, port: u16, hostname: Option<&str>, info: bool) -> u8 {
    let name = fqdn(zone, port, hostname);
    let dns_record = match dns::lookup_tlsa(&name).await {
        Ok(record) => record,
        Err(err) => {
            eprintln!("{err:#}");
            println!("UNKNOWN - Something went wrong. Check logs");
            return 3;
        }
    };

    let host = connect_host(zone, hostname);
    let cert = match fetch_live(&host, port) {
        Ok(cert) => cert,
        Err(err) => {
            eprintln!("{err:#}");
            println!("UNKNOWN - Something went wrong. Check logs");
            return 3;
        }
    };

    if info && let Err(err) = cert.print_info(hostname, Some(port), true) {
        eprintln!("{err:#}");
        println!("UNKNOWN - Something went wrong. Check logs");
        return 3;
    }

    let host_hash = match cert.spki_sha256_hex() {
        Ok(hash) => hash,
        Err(err) => {
            eprintln!("{err:#}");
            println!("UNKNOWN - Something went wrong. Check logs");
            return 3;
        }
    };

    if dns_record.is_empty() {
        println!("UNKNOWN - Something went wrong. Check logs");
        return 3;
    }

    if dns_record
        .iter()
        .any(|record| tlsa::hashes_equal(&host_hash, &record.certificate))
    {
        println!("OK - TLSA is valid");
        0
    } else {
        let dns_text = dns_record
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        println!("ERROR - TLSA invalid: {host_hash} != {dns_text}");
        2
    }
}

async fn update_cloudflare(
    zone_name: &str,
    hostname: Option<&str>,
    port: u16,
    cert: &Certificate,
    info: bool,
    dryrun: bool,
) -> Result<u8> {
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
    cf.upsert_tlsa(&zone, hostname, port, &hash, dryrun).await?;
    Ok(0)
}

async fn cloudflare_cmd(info: bool, listzones: bool) -> Result<u8> {
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
