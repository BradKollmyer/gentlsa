/// DANE-EE / SPKI / SHA-256 — the record this tool generates.
pub const USAGE: u8 = 3;
pub const SELECTOR: u8 = 1;
pub const MATCHING: u8 = 1;

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
}
