use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Mutex;

use anyhow::{Context, Result};
use hickory_resolver::proto::dnssec::Proof;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::rr::rdata::TLSA;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

use crate::timeout;
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
    let resolver = build_resolver(false)?;

    let lookup = match dns_timeout(resolver.tlsa_lookup(name)).await? {
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
    let resolver = build_resolver(true)?;

    let lookup = match dns_timeout(resolver.tlsa_lookup(name)).await? {
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

/// An MX exchange host after preference sort, null-MX skip, and de-duplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MxHost {
    pub preference: u16,
    pub host: String,
}

/// Look up MX for `zone`, lowest preference first. Null MX (RFC 7505, target ".")
/// is dropped. Duplicate targets keep the lowest preference.
pub async fn lookup_mx(zone: &str) -> Result<Vec<MxHost>> {
    let name = format!("{}.", zone.trim_end_matches('.'));
    verbose::step(format_args!("DNS MX lookup {name}"));
    let resolver = build_resolver(false)?;
    let lookup = match dns_timeout(resolver.lookup(name.clone(), RecordType::MX)).await? {
        Ok(lookup) => lookup,
        Err(err) if err.is_no_records_found() => {
            verbose::step("DNS returned 0 MX record(s)");
            return Ok(Vec::new());
        }
        Err(err) => {
            verbose::step(format_args!("MX lookup failed: {err}"));
            return Err(err).context(format!("MX lookup failed for {name}"));
        }
    };

    let mut records = Vec::new();
    for answer in lookup.answers() {
        let RData::MX(mx) = &answer.data else {
            continue;
        };
        let host = mx.exchange.to_string();
        let host = host.trim_end_matches('.');
        if host.is_empty() {
            verbose::step(format_args!(
                "skipping null MX (preference {})",
                mx.preference
            ));
            continue;
        }
        records.push((mx.preference, host.to_string()));
    }
    let hosts = normalize_mx(records);
    verbose::step(format_args!("DNS returned {} MX host(s)", hosts.len()));
    Ok(hosts)
}

fn normalize_mx(records: Vec<(u16, String)>) -> Vec<MxHost> {
    let mut hosts = Vec::new();
    for (preference, host) in records {
        let host = host.trim_end_matches('.').to_string();
        if host.is_empty() {
            continue;
        }
        if let Some(existing) = hosts
            .iter_mut()
            .find(|existing: &&mut MxHost| existing.host.eq_ignore_ascii_case(&host))
        {
            if preference < existing.preference {
                existing.preference = preference;
            }
            continue;
        }
        hosts.push(MxHost { preference, host });
    }
    hosts.sort_by(|a, b| {
        a.preference.cmp(&b.preference).then_with(|| {
            a.host
                .to_ascii_lowercase()
                .cmp(&b.host.to_ascii_lowercase())
        })
    });
    hosts
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
    if timeout::remaining().is_err() {
        verbose::step("DS lookup skipped: timed out");
        return;
    }
    let resolver = match build_resolver(false) {
        Ok(resolver) => resolver,
        Err(err) => {
            verbose::step(format_args!("DS lookup skipped: {err}"));
            return;
        }
    };
    match dns_timeout(resolver.lookup(format!("{name}."), RecordType::DS)).await {
        Err(err) => verbose::step(format_args!("DS lookup skipped: {err}")),
        Ok(Ok(lookup)) => {
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
        Ok(Err(err)) if err.is_no_records_found() => warn_no_ds(&name),
        Ok(Err(err)) => verbose::step(format_args!("DS lookup failed: {err}")),
    }
}

fn build_resolver(validate: bool) -> Result<TokioResolver> {
    let mut builder = Resolver::builder_tokio().context("failed to load system resolver config")?;
    if validate {
        builder.options_mut().validate = true;
    }
    if let Ok(left) = timeout::remaining() {
        let opts = builder.options_mut();
        opts.timeout = left;
        opts.attempts = 1;
    }
    builder.build().context("failed to build DNS resolver")
}

async fn dns_timeout<T, E, F>(fut: F) -> Result<std::result::Result<T, E>>
where
    F: Future<Output = std::result::Result<T, E>>,
{
    let left = timeout::remaining()?;
    match tokio::time::timeout(left, fut).await {
        Ok(inner) => Ok(inner),
        Err(_) => Err(timeout::expired_error()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_mx_sorts_dedups_and_drops_null() {
        let hosts = normalize_mx(vec![
            (20, "b.example.com.".into()),
            (10, "a.example.com".into()),
            (5, ".".into()),
            (30, "A.example.com".into()),
            (15, "c.example.net".into()),
        ]);
        assert_eq!(
            hosts
                .iter()
                .map(|h| (h.preference, h.host.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (10, "a.example.com"),
                (15, "c.example.net"),
                (20, "b.example.com"),
            ]
        );
    }
}
