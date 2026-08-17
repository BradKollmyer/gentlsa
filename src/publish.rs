use serde::Serialize;

use crate::tlsa;

/// Add the live hash if it is missing; keep any existing hashes.
/// `--replace` overwrites the first matching 3 1 1 record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishMode {
    Rollover,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishAction {
    AlreadyPublished,
    Added,
    Replaced,
    WouldAdd,
    WouldReplace,
}

#[derive(Debug, Clone, Serialize)]
pub struct PublishReport {
    pub zone: String,
    pub owner: String,
    pub action: PublishAction,
    pub mode: PublishMode,
    pub dryrun: bool,
    pub existing: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PruneReport {
    pub zone: String,
    pub dryrun: bool,
    pub stale: Vec<String>,
}

/// DANE-EE / SPKI / SHA-256 view used to decide rollover vs replace vs prune.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaneTlsa {
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
}

impl DaneTlsa {
    pub fn is_dane_ee_spki_sha256(&self) -> bool {
        tlsa::is_dane_ee_spki_sha256(self.usage, self.selector, self.matching)
    }

    pub fn hash_matches(&self, live: &str) -> bool {
        tlsa::hashes_equal(live, &self.certificate)
    }
}

pub fn publish_action(
    ours: &[DaneTlsa],
    certificate: &str,
    mode: PublishMode,
    dryrun: bool,
) -> PublishAction {
    if ours
        .iter()
        .any(|record| record.hash_matches(certificate) && record.is_dane_ee_spki_sha256())
    {
        return PublishAction::AlreadyPublished;
    }
    if mode == PublishMode::Replace && ours.iter().any(DaneTlsa::is_dane_ee_spki_sha256) {
        return if dryrun {
            PublishAction::WouldReplace
        } else {
            PublishAction::Replaced
        };
    }
    if dryrun {
        PublishAction::WouldAdd
    } else {
        PublishAction::Added
    }
}

pub fn stale_dane<'a>(records: &'a [DaneTlsa], live_hash: &str) -> Vec<&'a DaneTlsa> {
    records
        .iter()
        .filter(|record| record.is_dane_ee_spki_sha256() && !record.hash_matches(live_hash))
        .collect()
}

pub fn names_equal(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

pub fn owner_names(zone: &str, hostname: Option<&str>, port: u16) -> Vec<String> {
    let zone = zone.trim_end_matches('.');
    let mut names = vec![format!("_{port}._tcp.{zone}")];
    if let Some(host) = hostname.filter(|host| !host.is_empty()) {
        names.push(format!("_{port}._tcp.{host}.{zone}"));
    }
    names
}

/// Host labels after `_<port>._tcp` and before the zone, if the name is a TLSA owner.
pub fn owner_host<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
    let name = name.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if name.len() <= zone.len() {
        return None;
    }
    let (head, tail) = name.split_at(name.len() - zone.len());
    if !tail.eq_ignore_ascii_case(zone) {
        return None;
    }
    let rest = head.trim_end_matches('.');
    let rest = rest.strip_prefix('_')?;
    let (_, rest) = rest.split_once('.')?;
    rest.strip_prefix("_tcp")
        .map(|s| s.strip_prefix('.').unwrap_or(""))
}

pub fn record_matches_filter(
    name: &str,
    zone: &str,
    hostname: Option<&str>,
    ports: &[u16],
) -> bool {
    if !ports.is_empty() {
        return ports
            .iter()
            .flat_map(|port| owner_names(zone, hostname, *port))
            .any(|expected| names_equal(&expected, name));
    }
    let Some(host) = hostname.filter(|host| !host.is_empty()) else {
        return true;
    };
    owner_host(name, zone)
        .is_some_and(|labels| labels.is_empty() || labels.eq_ignore_ascii_case(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dane(hash: &str) -> DaneTlsa {
        DaneTlsa {
            usage: 3,
            selector: 1,
            matching: 1,
            certificate: hash.into(),
        }
    }

    fn other(hash: &str) -> DaneTlsa {
        DaneTlsa {
            usage: 2,
            selector: 1,
            matching: 1,
            certificate: hash.into(),
        }
    }

    #[test]
    fn publish_action_table() {
        let ours = [dane("AA")];

        assert_eq!(
            publish_action(&ours, "aa", PublishMode::Rollover, false),
            PublishAction::AlreadyPublished
        );
        assert_eq!(
            publish_action(&ours, "aa", PublishMode::Replace, true),
            PublishAction::AlreadyPublished
        );

        assert_eq!(
            publish_action(&ours, "bb", PublishMode::Rollover, false),
            PublishAction::Added
        );
        assert_eq!(
            publish_action(&ours, "bb", PublishMode::Rollover, true),
            PublishAction::WouldAdd
        );

        assert_eq!(
            publish_action(&ours, "bb", PublishMode::Replace, false),
            PublishAction::Replaced
        );
        assert_eq!(
            publish_action(&ours, "bb", PublishMode::Replace, true),
            PublishAction::WouldReplace
        );

        assert_eq!(
            publish_action(&[], "aa", PublishMode::Replace, false),
            PublishAction::Added
        );
        assert_eq!(
            publish_action(&[], "aa", PublishMode::Rollover, true),
            PublishAction::WouldAdd
        );
        assert_eq!(
            publish_action(&[other("AA")], "bb", PublishMode::Replace, false),
            PublishAction::Added
        );
    }

    #[test]
    fn prune_only_stale_dane_ee() {
        let current = dane("AA");
        let stale = dane("BB");
        let other_selector = DaneTlsa {
            usage: 3,
            selector: 0,
            matching: 1,
            certificate: "DD".into(),
        };
        let records = [current, stale, other_selector];
        let found = stale_dane(&records, "aa");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].certificate, "BB");
        assert!(stale_dane(&[dane("aa")], "AA").is_empty());
    }

    #[test]
    fn owner_names_and_filter() {
        assert_eq!(
            owner_names("example.org.", Some("mx"), 25),
            vec!["_25._tcp.example.org", "_25._tcp.mx.example.org"]
        );
        assert!(record_matches_filter(
            "_25._tcp.mx.example.org.",
            "example.org",
            Some("mx"),
            &[25, 465]
        ));
        assert!(!record_matches_filter(
            "_443._tcp.example.org",
            "example.org",
            None,
            &[25, 465]
        ));
        assert!(record_matches_filter(
            "_25._tcp.mx.example.org",
            "example.org",
            None,
            &[]
        ));
        assert!(!record_matches_filter(
            "_25._tcp.www.example.org",
            "example.org",
            Some("mx"),
            &[]
        ));
    }

    #[test]
    fn names_equal_ignores_dot_and_case() {
        assert!(names_equal(
            "_443._tcp.Example.ORG.",
            "_443._tcp.example.org"
        ));
        assert!(!names_equal(
            "_443._tcp.example.org",
            "_25._tcp.example.org"
        ));
    }
}
