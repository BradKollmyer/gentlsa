/// DANE-EE / SPKI / SHA-256 — the record this tool generates.
pub const USAGE: u8 = 3;
pub const SELECTOR: u8 = 1;
pub const MATCHING: u8 = 1;

/// RFC 7218 certificate usage name, if assigned.
pub fn usage_name(usage: u8) -> Option<&'static str> {
    match usage {
        0 => Some("PKIX-TA"),
        1 => Some("PKIX-EE"),
        2 => Some("DANE-TA"),
        3 => Some("DANE-EE"),
        255 => Some("PrivCert"),
        _ => None,
    }
}

/// RFC 7218 selector name, if assigned.
pub fn selector_name(selector: u8) -> Option<&'static str> {
    match selector {
        0 => Some("Cert"),
        1 => Some("SPKI"),
        255 => Some("PrivSel"),
        _ => None,
    }
}

/// RFC 7218 matching-type name, if assigned.
pub fn matching_name(matching: u8) -> Option<&'static str> {
    match matching {
        0 => Some("Full"),
        1 => Some("SHA2-256"),
        2 => Some("SHA2-512"),
        255 => Some("PrivMatch"),
        _ => None,
    }
}

pub fn is_dane_ee_spki_sha256(usage: u8, selector: u8, matching: u8) -> bool {
    usage == USAGE && selector == SELECTOR && matching == MATCHING
}

fn named(value: u8, name: Option<&'static str>) -> String {
    name.map(str::to_string).unwrap_or_else(|| value.to_string())
}

/// `DANE-EE SPKI SHA2-256`, or the raw number for an unassigned value.
pub fn params_label(usage: u8, selector: u8, matching: u8) -> String {
    format!(
        "{} {} {}",
        named(usage, usage_name(usage)),
        named(selector, selector_name(selector)),
        named(matching, matching_name(matching))
    )
}

/// Wire rdata plus decoded names, for list output.
pub fn rdata_text(usage: u8, selector: u8, matching: u8, certificate: &str) -> String {
    format!(
        "{usage} {selector} {matching} ({}) {certificate}",
        params_label(usage, selector, matching)
    )
}

pub fn owner_name(port: u16, hostname: Option<&str>) -> String {
    match hostname {
        Some(host) if !host.is_empty() => format!("_{port}._tcp.{host}"),
        _ => format!("_{port}._tcp"),
    }
}

pub fn fqdn(zone: &str, port: u16, hostname: Option<&str>) -> String {
    let zone = zone.trim_end_matches('.');
    format!("{}.{zone}.", owner_name(port, hostname))
}

pub fn connect_host(zone: &str, hostname: Option<&str>) -> String {
    match hostname {
        Some(host) if !host.is_empty() => format!("{host}.{zone}"),
        _ => zone.to_string(),
    }
}

/// Port from a TLSA owner name such as `_25._tcp.mx.example.org`.
pub fn port_from_owner(name: &str) -> Option<u16> {
    let name = name.trim_end_matches('.');
    let rest = name.strip_prefix('_')?;
    let (port, rest) = rest.split_once('.')?;
    if !rest.starts_with("_tcp") {
        return None;
    }
    port.parse().ok()
}

pub fn uses_starttls(port: u16) -> bool {
    matches!(port, 25 | 587)
}

pub fn record_line(owner: &str, hash: &str) -> String {
    format!("{owner} TLSA {USAGE} {SELECTOR} {MATCHING} {hash}")
}

pub fn hashes_equal(live: &str, dns: &str) -> bool {
    live.eq_ignore_ascii_case(dns)
}

/// Current/stale only for the generated 3 1 1 type; other parameters are not comparable.
pub fn hash_status(
    live: Option<&str>,
    usage: u8,
    selector: u8,
    matching: u8,
    record_hash: &str,
) -> Option<&'static str> {
    if !is_dane_ee_spki_sha256(usage, selector, matching) {
        return None;
    }
    match live {
        Some(live) if hashes_equal(live, record_hash) => Some("current"),
        Some(_) => Some("stale"),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_without_hostname() {
        assert_eq!(owner_name(443, None), "_443._tcp");
    }

    #[test]
    fn owner_with_hostname() {
        assert_eq!(owner_name(25, Some("mx")), "_25._tcp.mx");
    }

    #[test]
    fn fqdn_and_connect_host() {
        assert_eq!(fqdn("example.org", 443, None), "_443._tcp.example.org.");
        assert_eq!(
            fqdn("example.org.", 25, Some("mx")),
            "_25._tcp.mx.example.org."
        );
        assert_eq!(connect_host("example.org", None), "example.org");
        assert_eq!(connect_host("example.org", Some("mx")), "mx.example.org");
    }

    #[test]
    fn starttls_ports() {
        assert!(uses_starttls(25));
        assert!(uses_starttls(587));
        assert!(!uses_starttls(443));
        assert!(!uses_starttls(465));
    }

    #[test]
    fn port_from_owner_name() {
        assert_eq!(port_from_owner("_443._tcp.example.org."), Some(443));
        assert_eq!(port_from_owner("_25._tcp.mx.example.org"), Some(25));
        assert_eq!(port_from_owner("example.org"), None);
        assert_eq!(port_from_owner("_www._tcp.example.org"), None);
    }

    #[test]
    fn hashes_equal_is_case_insensitive() {
        assert!(hashes_equal("aaBB", "AAbb"));
        assert!(hashes_equal("deadbeef", "deadbeef"));
        assert!(!hashes_equal("aa", "ab"));
        assert!(!hashes_equal("aa", "aaa"));
    }

    #[test]
    fn rfc7218_names() {
        assert_eq!(usage_name(0), Some("PKIX-TA"));
        assert_eq!(usage_name(1), Some("PKIX-EE"));
        assert_eq!(usage_name(2), Some("DANE-TA"));
        assert_eq!(usage_name(3), Some("DANE-EE"));
        assert_eq!(usage_name(255), Some("PrivCert"));
        assert_eq!(usage_name(4), None);

        assert_eq!(selector_name(0), Some("Cert"));
        assert_eq!(selector_name(1), Some("SPKI"));
        assert_eq!(selector_name(255), Some("PrivSel"));
        assert_eq!(selector_name(2), None);

        assert_eq!(matching_name(0), Some("Full"));
        assert_eq!(matching_name(1), Some("SHA2-256"));
        assert_eq!(matching_name(2), Some("SHA2-512"));
        assert_eq!(matching_name(255), Some("PrivMatch"));
        assert_eq!(matching_name(3), None);
    }

    #[test]
    fn decoded_list_text() {
        assert_eq!(
            rdata_text(3, 1, 1, "aabb"),
            "3 1 1 (DANE-EE SPKI SHA2-256) aabb"
        );
        assert_eq!(
            rdata_text(2, 0, 1, "cccc"),
            "2 0 1 (DANE-TA Cert SHA2-256) cccc"
        );
        assert_eq!(
            rdata_text(9, 1, 1, "dddd"),
            "9 1 1 (9 SPKI SHA2-256) dddd"
        );
        assert!(is_dane_ee_spki_sha256(3, 1, 1));
        assert!(!is_dane_ee_spki_sha256(2, 1, 1));
        assert_eq!(hash_status(Some("aa"), 3, 1, 1, "AA"), Some("current"));
        assert_eq!(hash_status(Some("aa"), 3, 1, 1, "bb"), Some("stale"));
        assert_eq!(hash_status(Some("aa"), 2, 0, 1, "aa"), None);
    }
}
