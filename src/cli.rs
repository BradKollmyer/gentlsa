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
        /// Create or update the TLSA record in Cloudflare
        #[arg(long)]
        cloudflare: bool,
        /// With --cloudflare, print zone info but do not write records
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
        #[arg(long)]
        hostname: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        /// Print certificate details (on by default for this command)
        #[arg(long, default_value_t = true)]
        info: bool,
    },
}
