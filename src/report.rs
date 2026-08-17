use serde::Serialize;

use crate::cert::CertDetails;
use crate::cloudflare::{ListedTlsa, PruneReport, PublishReport};
use crate::dns::TlsaRecord;
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
            error: None,
        }
    }
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
}
