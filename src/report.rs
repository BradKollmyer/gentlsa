use serde::Serialize;

use crate::cert::CertDetails;
use crate::cloudflare::ListedTlsa;
use crate::dns::TlsaRecord;
use crate::nsupdate::ListedTlsa as NsupdateListed;
use crate::publish::{ListedTlsa as ApiListed, PruneReport, PublishReport};
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
        route53: Option<ProviderList>,
        #[serde(skip_serializing_if = "Option::is_none")]
        google: Option<ProviderList>,
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
    Route53 {
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        zones: Option<Vec<ZoneRef>>,
    },
    Google {
        #[serde(skip_serializing_if = "Option::is_none")]
        auth: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        project: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        zones: Option<Vec<ZoneRef>>,
    },
    Rollover {
        zone: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        hostname: Option<String>,
        path: String,
        certificate: String,
        ttl: u32,
        dryrun: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        job: Option<String>,
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        scheduled: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        info: Option<CertDetails>,
        publish: Vec<RolloverPublish>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reload: Option<ReloadReport>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        prune: Vec<PruneResult>,
        #[serde(skip_serializing_if = "Option::is_none")]
        next: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    Resume {
        jobs: Vec<ResumeJob>,
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
        #[serde(skip_serializing_if = "Vec::is_empty")]
        route53: Vec<PublishReport>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        google: Vec<PublishReport>,
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
    pub route53: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<PublishReport>,
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
pub struct ProviderList {
    pub zone: String,
    pub records: Vec<JsonTlsa>,
}

#[derive(Debug, Serialize)]
pub struct JsonTlsa {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub usage: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_name: Option<&'static str>,
    pub selector: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_name: Option<&'static str>,
    pub matching: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matching_name: Option<&'static str>,
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
    pub route53: Option<PruneReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<PruneReport>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i64>,
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

#[derive(Debug, Serialize)]
pub struct RolloverPublish {
    pub port: u16,
    pub owner: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nsupdate: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route53: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google: Option<PublishReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ReloadReport {
    pub command: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit: Option<i32>,
}

#[derive(Debug, Serialize)]
pub struct ResumeJob {
    pub id: String,
    pub zone: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JsonTlsa {
    fn from_fields(
        id: Option<String>,
        name: Option<String>,
        usage: u8,
        selector: u8,
        matching: u8,
        certificate: String,
        status: Option<&'static str>,
    ) -> Self {
        Self {
            id,
            name,
            usage,
            usage_name: tlsa::usage_name(usage),
            selector,
            selector_name: tlsa::selector_name(selector),
            matching,
            matching_name: tlsa::matching_name(matching),
            certificate,
            status,
        }
    }

    pub fn from_dns(record: &TlsaRecord, live: Option<&str>) -> Self {
        Self::from_fields(
            None,
            None,
            record.usage,
            record.selector,
            record.matching,
            record.certificate.clone(),
            tlsa::hash_status(
                live,
                record.usage,
                record.selector,
                record.matching,
                &record.certificate,
            ),
        )
    }

    pub fn to_text(&self) -> String {
        tlsa::rdata_text(self.usage, self.selector, self.matching, &self.certificate)
    }

    pub fn from_cf(record: &ListedTlsa, live: Option<&str>) -> Self {
        Self::from_fields(
            Some(record.id.clone()),
            Some(record.name.clone()),
            record.usage,
            record.selector,
            record.matching,
            record.certificate.clone(),
            tlsa::hash_status(
                live,
                record.usage,
                record.selector,
                record.matching,
                &record.certificate,
            ),
        )
    }

    pub fn from_nsupdate(record: &NsupdateListed, live: Option<&str>) -> Self {
        Self::from_fields(
            None,
            Some(record.name.clone()),
            record.usage,
            record.selector,
            record.matching,
            record.certificate.clone(),
            tlsa::hash_status(
                live,
                record.usage,
                record.selector,
                record.matching,
                &record.certificate,
            ),
        )
    }

    pub fn from_listed(record: &ApiListed, live: Option<&str>) -> Self {
        Self::from_fields(
            record.id.clone(),
            Some(record.name.clone()),
            record.usage,
            record.selector,
            record.matching,
            record.certificate.clone(),
            tlsa::hash_status(
                live,
                record.usage,
                record.selector,
                record.matching,
                &record.certificate,
            ),
        )
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
            route53: None,
            google: None,
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

/// After a matching TLSA hash, raise WARNING (1) or CRITICAL (2) from remaining days.
/// Hash mismatch and UNKNOWN are left unchanged so expiry cannot hide a bad TLSA.
pub fn apply_expiry(
    outcome: VerifyOutcome,
    days_left: i64,
    not_yet_valid: bool,
    warn: u32,
    critical: u32,
) -> VerifyOutcome {
    if outcome.exit != 0 {
        return outcome;
    }
    if not_yet_valid {
        return VerifyOutcome {
            status: "error",
            message: "CRITICAL - certificate is not yet valid".into(),
            exit: 2,
        };
    }
    if days_left < 0 {
        return VerifyOutcome {
            status: "error",
            message: "CRITICAL - certificate expired".into(),
            exit: 2,
        };
    }
    if days_left <= i64::from(critical) {
        return VerifyOutcome {
            status: "error",
            message: format!("CRITICAL - certificate {}", expiry_phrase(days_left)),
            exit: 2,
        };
    }
    if days_left <= i64::from(warn) {
        return VerifyOutcome {
            status: "warning",
            message: format!("WARNING - certificate {}", expiry_phrase(days_left)),
            exit: 1,
        };
    }
    outcome
}

fn expiry_phrase(days: i64) -> String {
    match days {
        0 => "expires today".into(),
        1 => "expires in 1 day".into(),
        n => format!("expires in {n} days"),
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
            route53: Vec::new(),
            google: Vec::new(),
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

    #[test]
    fn rollover_report_json_shape() {
        let cert = Certificate::from_file(Path::new("tests/fixtures/test.example.pem")).unwrap();
        let hash = cert.spki_sha256_hex().unwrap();
        let report = Report::Rollover {
            zone: "example.com".into(),
            hostname: None,
            path: "tests/fixtures/test.example.pem".into(),
            certificate: hash.clone(),
            ttl: 300,
            dryrun: true,
            job: Some("example.com_443".into()),
            scheduled: false,
            unit: None,
            info: None,
            publish: vec![RolloverPublish {
                port: 443,
                owner: tlsa::owner_name(443, None),
                cloudflare: None,
                nsupdate: None,
                route53: None,
                google: None,
                error: None,
            }],
            reload: Some(ReloadReport {
                command: "systemctl reload nginx".into(),
                status: "would_run",
                exit: None,
            }),
            prune: Vec::new(),
            next: None,
            error: None,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["command"], "rollover");
        assert_eq!(value["zone"], "example.com");
        assert_eq!(value["certificate"], hash);
        assert_eq!(value["ttl"], 300);
        assert_eq!(value["dryrun"], true);
        assert_eq!(value["publish"][0]["owner"], "_443._tcp");
        assert_eq!(value["reload"]["status"], "would_run");
        assert_eq!(value["job"], "example.com_443");
        assert!(value.get("scheduled").is_none());
        assert!(value.get("prune").is_none());
        assert!(value.get("hostname").is_none());
        assert!(value.get("next").is_none());
        assert!(value.get("error").is_none());
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
    fn apply_expiry_thresholds() {
        let ok = verify_outcome(Some("aabbcc"), &[tlsa("AABBCC")]);

        let far = apply_expiry(ok.clone(), 90, false, 14, 7);
        assert_eq!((far.status, far.exit), ("ok", 0));
        assert_eq!(far.message, "OK - TLSA is valid");

        let warn = apply_expiry(ok.clone(), 10, false, 14, 7);
        assert_eq!((warn.status, warn.exit), ("warning", 1));
        assert_eq!(warn.message, "WARNING - certificate expires in 10 days");

        let one = apply_expiry(ok.clone(), 1, false, 14, 7);
        assert_eq!(one.exit, 2);
        assert_eq!(one.message, "CRITICAL - certificate expires in 1 day");

        let today = apply_expiry(ok.clone(), 0, false, 14, 7);
        assert_eq!(today.exit, 2);
        assert_eq!(today.message, "CRITICAL - certificate expires today");

        let expired = apply_expiry(ok.clone(), -3, false, 14, 7);
        assert_eq!(expired.exit, 2);
        assert_eq!(expired.message, "CRITICAL - certificate expired");

        let not_yet = apply_expiry(ok.clone(), 89, true, 14, 7);
        assert_eq!(not_yet.exit, 2);
        assert_eq!(not_yet.message, "CRITICAL - certificate is not yet valid");

        let only_expired = apply_expiry(ok.clone(), 1, false, 0, 0);
        assert_eq!(only_expired.exit, 0);

        let at_zero = apply_expiry(ok, 0, false, 0, 0);
        assert_eq!(at_zero.exit, 2);
    }

    #[test]
    fn apply_expiry_does_not_hide_hash_mismatch() {
        let err = verify_outcome(Some("aabbcc"), &[tlsa("dddddd")]);
        let still = apply_expiry(err.clone(), 0, false, 14, 7);
        assert_eq!(still.exit, 2);
        assert_eq!(still.status, "error");
        assert!(still.message.contains("ERROR - TLSA invalid"));

        let unknown = verify_outcome(None, &[]);
        let still_unknown = apply_expiry(unknown, -1, false, 14, 7);
        assert_eq!(still_unknown.exit, 3);
    }

    #[test]
    fn worst_verify_exit_takes_max() {
        assert_eq!(worst_verify_exit([0, 0]), 0);
        assert_eq!(worst_verify_exit([0, 1]), 1);
        assert_eq!(worst_verify_exit([0, 2]), 2);
        assert_eq!(worst_verify_exit([0, 3, 2]), 3);
        assert_eq!(worst_verify_exit([1, 0, 2]), 2);
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
            dns: vec![JsonTlsa::from_dns(&current[0], Some(live))],
            info: None,
            expires_in_days: Some(90),
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
            dns: vec![JsonTlsa::from_dns(&stale[0], Some(live))],
            info: None,
            expires_in_days: Some(2),
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
        assert_eq!(value["results"][0]["expires_in_days"], 90);
        assert_eq!(value["results"][0]["dns"][0]["status"], "current");
        assert_eq!(value["results"][0]["dns"][0]["usage_name"], "DANE-EE");
        assert_eq!(value["results"][0]["dns"][0]["selector_name"], "SPKI");
        assert_eq!(value["results"][0]["dns"][0]["matching_name"], "SHA2-256");
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

    #[test]
    fn list_text_decodes_rfc7218_names() {
        let current = tlsa("aabb");
        let listed = JsonTlsa::from_dns(&current, Some("aabb"));
        assert_eq!(listed.to_text(), "3 1 1 (DANE-EE SPKI SHA2-256) aabb");
        assert_eq!(listed.status, Some("current"));
        assert_eq!(listed.usage_name, Some("DANE-EE"));

        let other = TlsaRecord {
            usage: 2,
            selector: 0,
            matching: 1,
            certificate: "cccc".into(),
        };
        let listed = JsonTlsa::from_dns(&other, Some("aabb"));
        assert_eq!(listed.to_text(), "2 0 1 (DANE-TA Cert SHA2-256) cccc");
        assert_eq!(listed.status, None);
        assert_eq!(listed.usage_name, Some("DANE-TA"));
        assert_eq!(listed.selector_name, Some("Cert"));

        let reserved = TlsaRecord {
            usage: 9,
            selector: 1,
            matching: 1,
            certificate: "dddd".into(),
        };
        let listed = JsonTlsa::from_dns(&reserved, Some("aabb"));
        assert_eq!(listed.to_text(), "9 1 1 (9 SPKI SHA2-256) dddd");
        assert!(listed.usage_name.is_none());
        let value = serde_json::to_value(&listed).unwrap();
        assert!(value.get("usage_name").is_none());
        assert_eq!(value["selector_name"], "SPKI");
    }
}
