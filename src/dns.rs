use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::proto::rr::rdata::TLSA;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
}

impl TlsaRecord {
    pub fn to_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.usage, self.selector, self.matching, self.certificate
        )
    }
}

impl std::fmt::Display for TlsaRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_text())
    }
}

pub async fn lookup_tlsa(name: &str) -> Result<Vec<TlsaRecord>> {
    let resolver = Resolver::builder_tokio()
        .context("failed to load system resolver config")?
        .build()
        .context("failed to build DNS resolver")?;

    let lookup = match resolver.tlsa_lookup(name).await {
        Ok(lookup) => lookup,
        Err(err) => {
            eprintln!("Exception occured: {err}");
            return Ok(Vec::new());
        }
    };

    Ok(lookup
        .answers()
        .iter()
        .filter_map(|answer| from_rdata(&answer.data))
        .collect())
}

fn from_rdata(rdata: &RData) -> Option<TlsaRecord> {
    match rdata {
        RData::TLSA(tlsa) => Some(from_tlsa(tlsa)),
        _ => None,
    }
}

fn from_tlsa(tlsa: &TLSA) -> TlsaRecord {
    TlsaRecord {
        usage: u8::from(tlsa.cert_usage),
        selector: u8::from(tlsa.selector),
        matching: u8::from(tlsa.matching),
        certificate: hex::encode(&tlsa.cert_data),
    }
}
