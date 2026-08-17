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

/// Mutually exclusive publisher flags shared by generate/list/prune/file.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct PublisherFlags {
    /// Publish / list / prune via the Cloudflare API
    #[arg(long, group = "publisher")]
    pub cloudflare: bool,
    /// Publish via RFC 2136 dynamic update (TSIG)
    #[arg(long, group = "publisher")]
    pub nsupdate: bool,
    /// Publish / list / prune via Amazon Route 53
    #[arg(long, group = "publisher")]
    pub route53: bool,
    /// Publish / list / prune via Google Cloud DNS
    #[arg(long, group = "publisher")]
    pub google: bool,
}

impl PublisherFlags {
    pub fn kind(self) -> Option<crate::publish::PublisherKind> {
        use crate::publish::PublisherKind;
        if self.cloudflare {
            Some(PublisherKind::Cloudflare)
        } else if self.nsupdate {
            Some(PublisherKind::Nsupdate)
        } else if self.route53 {
            Some(PublisherKind::Route53)
        } else if self.google {
            Some(PublisherKind::Google)
        } else {
            None
        }
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
        #[command(flatten)]
        publisher: PublisherFlags,
        /// With a publisher, overwrite the existing TLSA instead of adding a rollover record
        #[arg(long)]
        replace: bool,
        /// With a publisher, print the action but do not write records
        #[arg(long)]
        dryrun: bool,
    },
    /// List published TLSA records from DNS (and optionally a publisher)
    List {
        zone: String,
        /// Service port or comma-separated list. Omit to include every port.
        #[arg(value_name = "PORTS")]
        ports: Option<Ports>,
        #[arg(long)]
        hostname: Option<String>,
        #[command(flatten)]
        publisher: PublisherFlags,
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
        #[command(flatten)]
        publisher: PublisherFlags,
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
    /// RFC 2136 / TSIG helpers
    Nsupdate {
        /// Print nsupdate server and key (never the secret)
        #[arg(long)]
        info: bool,
    },
    /// Amazon Route 53 helpers
    Route53 {
        /// Print Route 53 authentication status
        #[arg(long)]
        info: bool,
        /// List hosted zones available to the configured account
        #[arg(long)]
        listzones: bool,
    },
    /// Google Cloud DNS helpers
    Google {
        /// Print Google Cloud DNS authentication status
        #[arg(long)]
        info: bool,
        /// List managed zones in the configured project
        #[arg(long)]
        listzones: bool,
    },
    /// Show TLSA info for a local certificate file
    File {
        certfile: PathBuf,
        /// Zone to publish into when using a publisher flag
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
        #[command(flatten)]
        publisher: PublisherFlags,
        #[arg(long)]
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
    fn clap_nsupdate_conflicts_with_cloudflare() {
        assert!(
            Cli::try_parse_from([
                "gentlsa",
                "generate",
                "example.com",
                "443",
                "--cloudflare",
                "--nsupdate"
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "gentlsa",
            "generate",
            "example.com",
            "443",
            "--nsupdate",
            "--replace",
            "--dryrun",
        ])
        .unwrap();
        match cli.command {
            Command::Generate {
                publisher,
                replace,
                dryrun,
                ..
            } => {
                assert!(publisher.nsupdate);
                assert!(replace);
                assert!(dryrun);
                assert!(!publisher.cloudflare);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_hosted_publishers_conflict() {
        assert!(
            Cli::try_parse_from([
                "gentlsa",
                "generate",
                "example.com",
                "443",
                "--route53",
                "--google"
            ])
            .is_err()
        );
        let cli =
            Cli::try_parse_from(["gentlsa", "list", "example.com", "--route53"]).unwrap();
        match cli.command {
            Command::List { publisher, .. } => assert!(publisher.route53),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_nsupdate_subcommand() {
        let cli = Cli::try_parse_from(["gentlsa", "nsupdate", "--info"]).unwrap();
        match cli.command {
            Command::Nsupdate { info } => assert!(info),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_route53_and_google_subcommands() {
        let cli = Cli::try_parse_from(["gentlsa", "route53", "--info", "--listzones"]).unwrap();
        match cli.command {
            Command::Route53 { info, listzones } => {
                assert!(info);
                assert!(listzones);
            }
            other => panic!("unexpected {other:?}"),
        }

        let cli = Cli::try_parse_from(["gentlsa", "google", "--listzones"]).unwrap();
        match cli.command {
            Command::Google { info, listzones } => {
                assert!(!info);
                assert!(listzones);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn clap_global_json() {
        let before = Cli::try_parse_from(["gentlsa", "--json", "list", "example.com"]).unwrap();
        assert!(before.json);

        let after = Cli::try_parse_from(["gentlsa", "file", "cert.pem", "--json"]).unwrap();
        assert!(after.json);
    }
}
