use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Tool for TLSA/DANE
#[derive(Debug, Parser)]
#[command(
    name = "gentlsa",
    version,
    about = "Simple tool for dealing with DANE/TLSA records",
    arg_required_else_help = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a TLSA record from a live certificate
    Generate {
        zone: String,
        port: u16,
        /// Short hostname, without the zone (for example "mx")
        #[arg(long)]
        hostname: Option<String>,
        /// Print certificate details
        #[arg(long)]
        info: bool,
        /// Publish the TLSA hash in Cloudflare (adds the new hash, keeps any old one)
        #[arg(long)]
        cloudflare: bool,
        /// With --cloudflare, overwrite the existing TLSA instead of adding a rollover record
        #[arg(long, requires = "cloudflare")]
        replace: bool,
        /// With --cloudflare, print zone info but do not write records
        #[arg(long)]
        dryrun: bool,
    },
    /// List published TLSA records from DNS (and optionally Cloudflare)
    List {
        zone: String,
        port: u16,
        #[arg(long)]
        hostname: Option<String>,
        /// Also list TLSA records from Cloudflare
        #[arg(long)]
        cloudflare: bool,
        /// Compare listed hashes to the live certificate
        #[arg(long)]
        info: bool,
    },
    /// Remove stale TLSA records that no longer match the live certificate
    Prune {
        zone: String,
        port: u16,
        #[arg(long)]
        hostname: Option<String>,
        /// Delete stale records in Cloudflare
        #[arg(long)]
        cloudflare: bool,
        #[arg(long)]
        dryrun: bool,
    },
    /// Verify DNS TLSA against the live certificate (Nagios-compatible)
    Verify {
        zone: String,
        port: u16,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        info: bool,
    },
    /// Cloudflare helpers
    Cloudflare {
        /// Print Cloudflare authentication status
        #[arg(long)]
        info: bool,
        /// List zones available to the configured account
        #[arg(long)]
        listzones: bool,
    },
    /// Show TLSA info for a local certificate file
    File {
        certfile: PathBuf,
        /// Zone to publish into when using --cloudflare
        #[arg(long)]
        zone: Option<String>,
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Print certificate details (on by default for this command)
        #[arg(long, default_value_t = true)]
        info: bool,
        /// Publish this certificate's hash in Cloudflare (key rollover)
        #[arg(long)]
        cloudflare: bool,
        #[arg(long, requires = "cloudflare")]
        replace: bool,
        #[arg(long)]
        dryrun: bool,
    },
}
