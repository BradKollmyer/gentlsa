use serde::Serialize;

use crate::cert::CertDetails;
use crate::cloudflare::ListedTlsa;
use crate::dns::TlsaRecord;
use crate::nsupdate::ListedTlsa as NsupdateListed;
use crate::publish::{PruneReport, PublishReport};
use crate::tlsa;

#[derive(Debug, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Report {
    Generate {
        zone: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        results: Vec<GenerateResult>,
    },
    List {
        zone: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        ports: Vec<u16>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        live: Vec<LiveHash>,
        dns: Vec<DnsName>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cloudflare: Option<CloudflareList>,
        #[serde(skip_serializing_if = "Option::is_none")]
        nsupdate: Option<NsupdateList>,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Prune {
        zone: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        results: Vec<PruneResult>,
    },
    Verify {
        zone: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        results: Vec<VerifyResult>,
        exit: u8,
    },
    Cloudflare {
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        zones: Option<Vec<ZoneRef>>,
    },
    Nsupdate {
        server: String,
        key_name: String,
        algorithm: String,
        ttl: u32,
    },
    File {
        path: String,
        usage: u8,
        selector: u8,
        matching: u8,
        certificate: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        info: Option<CertDetails>,
        records: Vec<FileRecord>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        cloudflare: Vec<PublishReport>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        nsupdate: Vec<PublishReport>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

#[derive(Debug, Serialize)]
pub struct GenerateResult {
    pub port: u16,
    pub host: String,
    pub owner: String,
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<CertDetails>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsupdate: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LiveHash {
    pub port: u16,
    pub certificate: String,
}

#[derive(Debug, Serialize)]
pub struct DnsName {
    pub name: String,
    pub records: Vec<JsonTlsa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CloudflareList {
    pub zone: String,
    pub records: Vec<JsonTlsa>,
}

#[derive(Debug, Serialize)]
pub struct NsupdateList {
    pub server: String,
    pub records: Vec<JsonTlsa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct JsonTlsa {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct PruneResult {
    pub port: u16,
    pub host: String,
    pub live: String,
    pub dns: Vec<JsonTlsa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<PruneReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsupdate: Option<PruneReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct VerifyResult {
    pub port: u16,
    pub name: String,
    pub status: &'static str,
    pub message: String,
    pub exit: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<JsonTlsa>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<CertDetails>,
}

#[derive(Debug, Serialize)]
pub struct ZoneRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct FileRecord {
    pub port: u16,
    pub owner: String,
}

impl JsonTlsa {
    pub fn from_dns(record: &TlsaRecord, status: Option<&'static str>) -> Self {
        Self {
            id: None,
            name: None,
            usage: record.usage,
            selector: record.selector,
            matching: record.matching,
            certificate: record.certificate.clone(),
            status,
        }
    }

    pub fn to_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.usage, self.selector, self.matching, self.certificate
        )
    }

    pub fn from_cf(record: &ListedTlsa, status: Option<&'static str>) -> Self {
        Self {
            id: Some(record.id.clone()),
            name: Some(record.name.clone()),
            usage: record.usage,
            selector: record.selector,
            matching: record.matching,
            certificate: record.certificate.clone(),
            status,
        }
    }

    pub fn from_nsupdate(record: &NsupdateListed, status: Option<&'static str>) -> Self {
        Self {
            id: None,
            name: Some(record.name.clone()),
            usage: record.usage,
            selector: record.selector,
            matching: record.matching,
            certificate: record.certificate.clone(),
            status,
        }
    }
}

impl GenerateResult {
    pub fn from_cert(
        port: u16,
        host: String,
        hostname: Option<&str>,
        hash: String,
        info: Option<CertDetails>,
    ) -> Self {
        Self {
            port,
            host,
            owner: tlsa::owner_name(port, hostname),
            usage: tlsa::USAGE,
            selector: tlsa::SELECTOR,
            matching: tlsa::MATCHING,
            certificate: hash,
            info,
            cloudflare: None,
            nsupdate: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyOutcome {
    pub status: &'static str,
    pub message: String,
    pub exit: u8,
}

/// Nagios-style verdict from a live hash and the DNS TLSA set.
pub fn verify_outcome(live: Option<&str>, dns: &[TlsaRecord]) -> VerifyOutcome {
    const UNKNOWN: &str = "UNKNOWN - Something went wrong. Check logs";
    let Some(live) = live else {
        return VerifyOutcome {
            status: "unknown",
            message: UNKNOWN.into(),
            exit: 3,
        };
    };
    if dns.is_empty() {
        return VerifyOutcome {
            status: "unknown",
            message: UNKNOWN.into(),
            exit: 3,
        };
    }
    if dns
        .iter()
        .any(|record| tlsa::hashes_equal(live, &record.certificate))
    {
        return VerifyOutcome {
            status: "ok",
            message: "OK - TLSA is valid".into(),
            exit: 0,
        };
    }
    let dns_text = dns
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    VerifyOutcome {
        status: "error",
        message: format!("ERROR - TLSA invalid: {live} != {dns_text}"),
        exit: 2,
    }
}

pub fn worst_verify_exit(exits: impl IntoIterator<Item = u8>) -> u8 {
    exits.into_iter().max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::Certificate;
    use std::path::Path;

    #[test]
    fn file_report_json_shape() {
        let cert = Certificate::from_file(Path::new("tests/fixtures/test.example.pem")).unwrap();
        let hash = cert.spki_sha256_hex().unwrap();
        let report = Report::File {
            path: "tests/fixtures/test.example.pem".into(),
            usage: tlsa::USAGE,
            selector: tlsa::SELECTOR,
            matching: tlsa::MATCHING,
            certificate: hash.clone(),
            info: Some(cert.details().unwrap()),
            records: vec![FileRecord {
                port: 443,
                owner: tlsa::owner_name(443, None),
            }],
            cloudflare: Vec::new(),
            nsupdate: Vec::new(),
            error: None,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["command"], "file");
        assert_eq!(value["usage"], 3);
        assert_eq!(value["selector"], 1);
        assert_eq!(value["matching"], 1);
        assert_eq!(value["certificate"], hash);
        assert_eq!(value["records"][0]["owner"], "_443._tcp");
        assert_eq!(
            value["info"]["subject"],
            "C=US, O=GenTLSA Test, CN=test.example"
        );
        assert!(value.get("cloudflare").is_none());
    }

    fn tlsa(hash: &str) -> TlsaRecord {
        TlsaRecord {
            usage: tlsa::USAGE,
            selector: tlsa::SELECTOR,
            matching: tlsa::MATCHING,
            certificate: hash.into(),
        }
    }

    #[test]
    fn verify_outcome_table() {
        let live = "aabbcc";

        let ok = verify_outcome(Some(live), &[tlsa("AABBCC")]);
        assert_eq!(ok.status, "ok");
        assert_eq!(ok.exit, 0);
        assert_eq!(ok.message, "OK - TLSA is valid");

        let mixed = verify_outcome(Some(live), &[tlsa("dddddd"), tlsa("AABBCC")]);
        assert_eq!(mixed.exit, 0);

        let err = verify_outcome(Some(live), &[tlsa("dddddd")]);
        assert_eq!(err.status, "error");
        assert_eq!(err.exit, 2);
        assert!(err.message.contains(live));
        assert!(err.message.contains("3 1 1 dddddd"));

        let no_dns = verify_outcome(Some(live), &[]);
        assert_eq!((no_dns.status, no_dns.exit), ("unknown", 3));

        let no_live = verify_outcome(None, &[tlsa("AABBCC")]);
        assert_eq!((no_live.status, no_live.exit), ("unknown", 3));

        let neither = verify_outcome(None, &[]);
        assert_eq!(neither.exit, 3);
        assert_eq!(
            neither.message,
            "UNKNOWN - Something went wrong. Check logs"
        );
    }

    #[test]
    fn worst_verify_exit_takes_max() {
        assert_eq!(worst_verify_exit([0, 0]), 0);
        assert_eq!(worst_verify_exit([0, 2]), 2);
        assert_eq!(worst_verify_exit([0, 3, 2]), 3);
        assert_eq!(worst_verify_exit([2, 0, 3]), 3);
        assert_eq!(worst_verify_exit(std::iter::empty()), 0);
    }

    #[test]
    fn generate_report_json_shape() {
        let hash = "ff94ad7dfafffed26e98150947dd8b1a7d981fabf90740c574685c81d487b9a8";
        let report = Report::Generate {
            zone: "example.com".into(),
            hostname: None,
            results: vec![GenerateResult::from_cert(
                443,
                "example.com".into(),
                None,
                hash.into(),
                None,
            )],
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["command"], "generate");
        assert_eq!(value["zone"], "example.com");
        assert!(value.get("hostname").is_none());
        assert_eq!(value["results"][0]["port"], 443);
        assert_eq!(value["results"][0]["owner"], "_443._tcp");
        assert_eq!(value["results"][0]["usage"], 3);
        assert_eq!(value["results"][0]["selector"], 1);
        assert_eq!(value["results"][0]["matching"], 1);
        assert_eq!(value["results"][0]["certificate"], hash);
        assert!(value["results"][0].get("cloudflare").is_none());
        assert!(value["results"][0].get("nsupdate").is_none());
        assert!(value["results"][0].get("error").is_none());
        assert!(value["results"][0].get("info").is_none());
    }

    #[test]
    fn verify_report_json_shape() {
        let live = "aabb";
        let current = [tlsa(live)];
        let ok_outcome = verify_outcome(Some(live), &current);
        let ok = VerifyResult {
            port: 443,
            name: "_443._tcp.example.com.".into(),
            status: ok_outcome.status,
            message: ok_outcome.message,
            exit: ok_outcome.exit,
            live: Some(live.into()),
            dns: vec![JsonTlsa::from_dns(&current[0], Some("current"))],
            info: None,
        };

        let stale = [tlsa("cccc")];
        let err_outcome = verify_outcome(Some(live), &stale);
        let err = VerifyResult {
            port: 25,
            name: "_25._tcp.example.com.".into(),
            status: err_outcome.status,
            message: err_outcome.message,
            exit: err_outcome.exit,
            live: Some(live.into()),
            dns: vec![JsonTlsa::from_dns(&stale[0], Some("stale"))],
            info: None,
        };

        let report = Report::Verify {
            zone: "example.com".into(),
            hostname: None,
            results: vec![ok, err],
            exit: worst_verify_exit([0, 2]),
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["command"], "verify");
        assert_eq!(value["exit"], 2);
        assert!(value.get("hostname").is_none());
        assert_eq!(value["results"][0]["status"], "ok");
        assert_eq!(value["results"][0]["exit"], 0);
        assert_eq!(value["results"][0]["message"], "OK - TLSA is valid");
        assert_eq!(value["results"][0]["dns"][0]["status"], "current");
        assert_eq!(value["results"][1]["status"], "error");
        assert_eq!(value["results"][1]["exit"], 2);
        assert!(
            value["results"][1]["message"]
                .as_str()
                .unwrap()
                .contains("ERROR - TLSA invalid")
        );
        assert!(value["results"][0].get("info").is_none());
    }
}
