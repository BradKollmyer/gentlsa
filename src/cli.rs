use std::path::PathBuf;
use std::str::FromStr;

use clap::{Parser, Subcommand};

/// One port or a comma-separated list (`443` or `25,465`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ports(pub Vec<u16>);

impl Ports {
    pub fn as_slice(&self) -> &[u16] {
        &self.0
    }
}

impl FromStr for Ports {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut ports = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let port: u16 = part.parse().map_err(|_| format!("invalid port '{part}'"))?;
            if port == 0 {
                return Err("port must be 1-65535".into());
            }
            if !ports.contains(&port) {
                ports.push(port);
            }
        }
        if ports.is_empty() {
            return Err("expected at least one port".into());
        }
        Ok(Ports(ports))
    }
}

/// Tool for TLSA/DANE
#[derive(Debug, Parser)]
#[command(
    name = "gentlsa",
    version,
    about = "Simple tool for dealing with DANE/TLSA records",
    arg_required_else_help = true
)]
pub struct Cli {
    /// Print each processing step to stderr
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Emit a single JSON object on stdout instead of text
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a TLSA record from a live certificate
    Generate {
        zone: String,
        /// Service port or comma-separated list (for example 443 or 25,465)
        #[arg(value_name = "PORTS")]
        ports: Ports,
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
        /// Service port or comma-separated list. Omit to include every port.
        #[arg(value_name = "PORTS")]
        ports: Option<Ports>,
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
        /// Service port or comma-separated list (for example 443 or 25,465)
        #[arg(value_name = "PORTS")]
        ports: Ports,
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
        /// Service port or comma-separated list (for example 443 or 25,465)
        #[arg(value_name = "PORTS")]
        ports: Ports,
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
        /// Service port or comma-separated list (for example 443 or 25,465)
        #[arg(long = "port", value_name = "PORTS")]
        ports: Option<Ports>,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_and_list() {
        assert_eq!("443".parse::<Ports>().unwrap().0, vec![443]);
        assert_eq!("25,465".parse::<Ports>().unwrap().0, vec![25, 465]);
        assert_eq!(
            "25, 465, 587".parse::<Ports>().unwrap().0,
            vec![25, 465, 587]
        );
        assert_eq!("25,25,465".parse::<Ports>().unwrap().0, vec![25, 465]);
    }

    #[test]
    fn reject_empty_and_invalid() {
        assert!("".parse::<Ports>().is_err());
        assert!("abc".parse::<Ports>().is_err());
        assert!("0".parse::<Ports>().is_err());
        assert!("70000".parse::<Ports>().is_err());
    }

    #[test]
    fn clap_list_ports_optional() {
        let cli = Cli::try_parse_from(["gentlsa", "list", "example.com"]).unwrap();
        match cli.command {
            Command::List { ports, .. } => assert!(ports.is_none()),
            other => panic!("unexpected {other:?}"),
        }

        let cli = Cli::try_parse_from(["gentlsa", "list", "example.com", "25,465"]).unwrap();
        match cli.command {
            Command::List { ports, .. } => {
                assert_eq!(ports.unwrap().0, vec![25, 465]);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_generate_requires_ports() {
        assert!(Cli::try_parse_from(["gentlsa", "generate", "example.com"]).is_err());
        let cli = Cli::try_parse_from(["gentlsa", "generate", "example.com", "25,465"]).unwrap();
        match cli.command {
            Command::Generate { ports, .. } => assert_eq!(ports.0, vec![25, 465]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_file_port_list() {
        let cli = Cli::try_parse_from(["gentlsa", "file", "cert.pem", "--port", "25,465"]).unwrap();
        match cli.command {
            Command::File { ports, .. } => assert_eq!(ports.unwrap().0, vec![25, 465]),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_global_verbose() {
        let before = Cli::try_parse_from(["gentlsa", "-v", "list", "example.com"]).unwrap();
        assert!(before.verbose);

        let after = Cli::try_parse_from(["gentlsa", "generate", "example.com", "443", "--verbose"])
            .unwrap();
        assert!(after.verbose);

        let off = Cli::try_parse_from(["gentlsa", "list", "example.com"]).unwrap();
        assert!(!off.verbose);
        assert!(!off.json);
    }

    #[test]
    fn clap_global_json() {
        let before = Cli::try_parse_from(["gentlsa", "--json", "list", "example.com"]).unwrap();
        assert!(before.json);

        let after = Cli::try_parse_from(["gentlsa", "file", "cert.pem", "--json"]).unwrap();
        assert!(after.json);
    }
}
