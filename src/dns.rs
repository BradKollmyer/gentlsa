use std::collections::BTreeSet;
use std::sync::Mutex;

use anyhow::{Context, Result};
use hickory_resolver::Resolver;
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::rr::rdata::TLSA;
use hickory_resolver::proto::rr::{RData, RecordType};

use crate::verbose;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
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
    verbose::step(format_args!("DNS TLSA lookup {name}"));
    let resolver = Resolver::builder_tokio()
        .context("failed to load system resolver config")?
        .build()
        .context("failed to build DNS resolver")?;

    let lookup = match resolver.tlsa_lookup(name).await {
        Ok(lookup) => lookup,
        Err(err) => {
            verbose::step(format_args!("DNS lookup failed: {err}"));
            eprintln!("Exception occured: {err}");
            return Ok(Vec::new());
        }
    };

    let records: Vec<TlsaRecord> = lookup
        .answers()
        .iter()
        .filter_map(|answer| from_rdata(&answer.data))
        .collect();
    verbose::step(format_args!(
        "DNS returned {} TLSA record(s)",
        records.len()
    ));
    Ok(records)
}

/// DNSSEC verdict for a TLSA RRset, validated locally from the root trust anchor.
/// A DANE client only honors TLSA records that validate as `Secure`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DnssecStatus {
    Secure,
    Insecure,
    Bogus,
    Indeterminate,
}

impl DnssecStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Secure => "secure",
            Self::Insecure => "insecure",
            Self::Bogus => "bogus",
            Self::Indeterminate => "indeterminate",
        }
    }

    fn from_proof(proof: Proof) -> Self {
        match proof {
            Proof::Secure => Self::Secure,
            Proof::Insecure => Self::Insecure,
            Proof::Bogus => Self::Bogus,
            Proof::Indeterminate => Self::Indeterminate,
        }
    }

    fn severity(self) -> u8 {
        match self {
            Self::Secure => 0,
            Self::Insecure => 1,
            Self::Indeterminate => 2,
            Self::Bogus => 3,
        }
    }
}

/// Worst verdict wins: one bogus record poisons the RRset.
fn worst_dnssec(statuses: impl IntoIterator<Item = DnssecStatus>) -> Option<DnssecStatus> {
    statuses.into_iter().max_by_key(|status| status.severity())
}

pub struct TlsaLookup {
    pub records: Vec<TlsaRecord>,
    /// `None` when the lookup failed or returned no TLSA records.
    pub dnssec: Option<DnssecStatus>,
}

/// Like [`lookup_tlsa`], but validates the response with DNSSEC and reports the verdict.
pub async fn lookup_tlsa_dnssec(name: &str) -> Result<TlsaLookup> {
    verbose::step(format_args!("DNS TLSA lookup {name} (DNSSEC validation)"));
    let mut builder = Resolver::builder_tokio().context("failed to load system resolver config")?;
    builder.options_mut().validate = true;
    let resolver = builder.build().context("failed to build DNS resolver")?;

    let lookup = match resolver.tlsa_lookup(name).await {
        Ok(lookup) => lookup,
        Err(err) => {
            verbose::step(format_args!("DNS lookup failed: {err}"));
            eprintln!("Exception occured: {err}");
            return Ok(TlsaLookup {
                records: Vec::new(),
                dnssec: None,
            });
        }
    };

    let mut records = Vec::new();
    let mut proofs = Vec::new();
    for answer in lookup.answers() {
        if let Some(record) = from_rdata(&answer.data) {
            records.push(record);
            proofs.push(DnssecStatus::from_proof(answer.proof));
        }
    }
    let dnssec = worst_dnssec(proofs);
    verbose::step(format_args!(
        "DNS returned {} TLSA record(s), DNSSEC {}",
        records.len(),
        dnssec.map_or("n/a", DnssecStatus::label)
    ));
    Ok(TlsaLookup { records, dnssec })
}

/// Warn on stderr when the zone has no DS record at its parent: without a signed
/// delegation, DANE clients cannot authenticate the TLSA records and ignore them.
/// Checks each zone once per process; lookup failures stay silent (publishing
/// must not depend on a working DS lookup).
pub async fn warn_if_unsigned(zone: &str) {
    static CHECKED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    let name = zone.trim_end_matches('.').to_ascii_lowercase();
    if !CHECKED.lock().unwrap().insert(name.clone()) {
        return;
    }
    verbose::step(format_args!("DNS DS lookup {name}"));
    let resolver = match Resolver::builder_tokio().and_then(|builder| builder.build()) {
        Ok(resolver) => resolver,
        Err(err) => {
            verbose::step(format_args!("DS lookup skipped: {err}"));
            return;
        }
    };
    match resolver.lookup(format!("{name}."), RecordType::DS).await {
        Ok(lookup) => {
            let count = lookup
                .answers()
                .iter()
                .filter(|record| matches!(&record.data, RData::DNSSEC(DNSSECRData::DS(_))))
                .count();
            if count > 0 {
                verbose::step(format_args!("zone {name} has {count} DS record(s)"));
            } else {
                warn_no_ds(&name);
            }
        }
        Err(err) if err.is_no_records_found() => warn_no_ds(&name),
        Err(err) => verbose::step(format_args!("DS lookup failed: {err}")),
    }
}

fn warn_no_ds(zone: &str) {
    eprintln!(
        "warning: {zone} has no DS record; the zone is not DNSSEC-signed, so DANE clients will ignore its TLSA records"
    );
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
