use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use hickory_net::client::{Client, ClientHandle};
use hickory_net::proto::op::ResponseCode;
use hickory_net::proto::rr::rdata::tlsa::{CertUsage, Matching, Selector, TLSA};
use hickory_net::proto::rr::rdata::tsig::TsigAlgorithm;
use hickory_net::proto::rr::{DNSClass, Name, RData, Record, RecordType, TSigner};
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_net::tcp::TcpClientStream;
use hickory_net::xfer::DnsMultiplexer;
use serde::Serialize;

use crate::output;
use crate::publish::{self, DaneTlsa, PruneReport, PublishAction, PublishMode, PublishReport};
use crate::tlsa;
use crate::verbose;

const DEFAULT_PORT: u16 = 53;
const DEFAULT_TTL: u32 = 3600;
const TSIG_FUDGE_SECS: u16 = 300;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Config {
    pub server: String,
    pub port: u16,
    pub key_name: String,
    secret: Vec<u8>,
    pub algorithm: TsigAlgorithm,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub server: String,
    pub key_name: String,
    pub algorithm: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListedTlsa {
    pub name: String,
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
}

impl Config {
    pub fn from_env_or_config() -> Result<Self> {
        verbose::step("loading nsupdate credentials");
        let (mut cfg, source) = load_config()?.unwrap_or_else(|| (PartialConfig::default(), None));
        overlay_env(&mut cfg)?;
        let loaded = cfg
            .into_config()
            .context("Please configure nsupdate in /etc/gentlsa/nsupdate.cfg")?;
        match source {
            Some(path) => verbose::step(format_args!(
                "nsupdate config from {} (env overrides applied)",
                path.display()
            )),
            None => verbose::step("nsupdate config from environment"),
        }
        verbose::step(format_args!(
            "nsupdate server={} key={} alg={}",
            loaded.server_label(),
            loaded.key_name,
            loaded.algorithm_label()
        ));
        Ok(loaded)
    }

    pub fn server_label(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    pub fn algorithm_label(&self) -> String {
        self.algorithm.to_string()
    }

    pub fn info(&self) -> ServerInfo {
        ServerInfo {
            server: self.server_label(),
            key_name: self.key_name.clone(),
            algorithm: self.algorithm_label(),
            ttl: self.ttl,
        }
    }

    pub fn print_info(&self) {
        output::text(">>> nsupdate Information:");
        output::text(format!("Server: {}", self.server_label()));
        output::text(format!("Key name: {}", self.key_name));
        output::text(format!("Algorithm: {}", self.algorithm_label()));
        output::text(format!("TTL: {}", self.ttl));
    }

    fn tsigner(&self) -> Result<TSigner> {
        let name = parse_name(&self.key_name).context("invalid TSIG key name")?;
        TSigner::new(
            self.secret.clone(),
            self.algorithm.clone(),
            name,
            TSIG_FUDGE_SECS,
        )
        .context("failed to build TSIG signer")
    }

    async fn resolve_addr(&self) -> Result<SocketAddr> {
        verbose::step(format_args!(
            "resolving nsupdate server {}",
            self.server_label()
        ));
        tokio::net::lookup_host((self.server.as_str(), self.port))
            .await
            .with_context(|| format!("failed to resolve {}", self.server_label()))?
            .next()
            .with_context(|| format!("no addresses for {}", self.server_label()))
    }

    async fn connect(&self) -> Result<Client<TokioRuntimeProvider>> {
        let addr = self.resolve_addr().await?;
        verbose::step(format_args!("connecting to nsupdate server {addr} (TCP)"));
        let signer = self.tsigner()?;
        let provider = TokioRuntimeProvider::new();
        let (stream_fut, handle) =
            TcpClientStream::new(addr, None, Some(CONNECT_TIMEOUT), provider);
        let stream = stream_fut
            .await
            .with_context(|| format!("failed to connect to {addr}"))?;
        let mux = DnsMultiplexer::new(stream, handle).with_signer(signer);
        let (client, bg) = Client::<TokioRuntimeProvider>::from_sender(mux);
        tokio::spawn(bg);
        Ok(client)
    }
}

impl Config {
    pub async fn list_tlsa(
        &self,
        zone: &str,
        hostname: Option<&str>,
        ports: &[u16],
    ) -> Result<(Vec<ListedTlsa>, Option<String>)> {
        if ports.is_empty() {
            match self.axfr_tlsa(zone).await {
                Ok(records) => {
                    let filtered = records
                        .into_iter()
                        .filter(|record| {
                            publish::record_matches_filter(&record.name, zone, hostname, ports)
                        })
                        .collect();
                    Ok((filtered, None))
                }
                Err(err) => {
                    verbose::step(format_args!("AXFR failed: {err:#}"));
                    Ok((
                        Vec::new(),
                        Some(
                            "AXFR failed or is not permitted; pass 443 or 25,465 to query the primary"
                                .to_string(),
                        ),
                    ))
                }
            }
        } else {
            let mut records = Vec::new();
            for port in ports {
                records.extend(self.query_owner(zone, hostname, *port).await?);
            }
            Ok((records, None))
        }
    }

    pub async fn publish_tlsa(
        &self,
        zone: &str,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
        mode: PublishMode,
        dryrun: bool,
    ) -> Result<PublishReport> {
        let owner = tlsa::owner_name(port, hostname);
        let mode_label = match mode {
            PublishMode::Replace => "replace",
            PublishMode::Rollover => "rollover",
        };
        verbose::step(format_args!(
            "nsupdate publish {owner} mode={mode_label} dryrun={dryrun}"
        ));
        let ours = self.query_owner(zone, hostname, port).await?;
        verbose::step(format_args!(
            "found {} existing TLSA record(s) for {owner}",
            ours.len()
        ));
        let dane: Vec<DaneTlsa> = ours.iter().map(ListedTlsa::to_dane).collect();
        let action = publish::publish_action(&dane, certificate, mode, dryrun);

        let report = |action: PublishAction| PublishReport {
            zone: zone.trim_end_matches('.').to_string(),
            owner: owner.clone(),
            action,
            mode,
            dryrun,
            existing: ours.len(),
            info: None,
        };

        if action == PublishAction::AlreadyPublished {
            verbose::step("live hash already published, skipping");
            output::text(format!(
                "nsupdate: TLSA already published for {} ({owner})",
                zone.trim_end_matches('.')
            ));
            return Ok(report(action));
        }

        if mode == PublishMode::Rollover && !ours.is_empty() {
            output::text(format!(
                "nsupdate: keeping {} existing TLSA record(s) for rollover",
                ours.len()
            ));
        }

        match action {
            PublishAction::WouldReplace => {
                output::text(format!(
                    "nsupdate: dry run, would replace TLSA {owner} on {}",
                    self.server_label()
                ));
                Ok(report(action))
            }
            PublishAction::WouldAdd => {
                output::text(format!(
                    "nsupdate: dry run, would add {owner} TLSA on {}",
                    self.server_label()
                ));
                Ok(report(action))
            }
            PublishAction::Replaced => {
                let existing = ours
                    .iter()
                    .find(|record| record.to_dane().is_dane_ee_spki_sha256())
                    .expect("replace action requires an existing 3 1 1 record");
                self.delete_hash(zone, hostname, port, &existing.certificate)
                    .await?;
                self.add_hash(zone, hostname, port, certificate).await?;
                output::text(format!(
                    "nsupdate: TLSA record updated for {}",
                    zone.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::Added => {
                self.add_hash(zone, hostname, port, certificate).await?;
                output::text(format!(
                    "nsupdate: TLSA record added for {}",
                    zone.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::AlreadyPublished => unreachable!("handled above"),
        }
    }

    pub async fn prune_tlsa(
        &self,
        zone: &str,
        hostname: Option<&str>,
        port: u16,
        live_hash: &str,
        dryrun: bool,
    ) -> Result<PruneReport> {
        verbose::step(format_args!(
            "nsupdate prune stale TLSA for {} port {port} dryrun={dryrun}",
            tlsa::owner_name(port, hostname)
        ));
        let ours = self.query_owner(zone, hostname, port).await?;
        let dane: Vec<DaneTlsa> = ours.iter().map(ListedTlsa::to_dane).collect();
        let stale = publish::stale_dane(&dane, live_hash);
        verbose::step(format_args!("{} stale TLSA record(s)", stale.len()));
        let hashes: Vec<String> = stale
            .iter()
            .map(|record| record.certificate.clone())
            .collect();

        if stale.is_empty() {
            output::text(format!(
                "nsupdate: no stale TLSA records for {}",
                zone.trim_end_matches('.')
            ));
            return Ok(PruneReport {
                zone: zone.trim_end_matches('.').to_string(),
                dryrun,
                stale: hashes,
            });
        }

        for hash in &hashes {
            if dryrun {
                output::text(format!("nsupdate: dry run, would delete stale TLSA {hash}"));
                continue;
            }
            self.delete_hash(zone, hostname, port, hash).await?;
            output::text(format!("nsupdate: deleted stale TLSA {hash}"));
        }
        Ok(PruneReport {
            zone: zone.trim_end_matches('.').to_string(),
            dryrun,
            stale: hashes,
        })
    }

    async fn query_owner(
        &self,
        zone: &str,
        hostname: Option<&str>,
        port: u16,
    ) -> Result<Vec<ListedTlsa>> {
        let fqdn = tlsa::fqdn(zone, port, hostname);
        let name = parse_name(&fqdn)?;
        verbose::step(format_args!("nsupdate TLSA query {fqdn}"));
        let mut client = self.connect().await?;
        let response = client
            .query(name, DNSClass::IN, RecordType::TLSA)
            .await
            .with_context(|| format!("TLSA query failed for {fqdn}"))?;
        check_response("query", response.metadata.response_code)?;
        Ok(response
            .answers
            .iter()
            .filter_map(listed_from_record)
            .collect())
    }

    async fn axfr_tlsa(&self, zone: &str) -> Result<Vec<ListedTlsa>> {
        let origin = parse_name(zone)?;
        verbose::step(format_args!("nsupdate AXFR {zone}"));
        let mut client = self.connect().await?;
        let mut stream = client.zone_transfer(origin, None);
        let mut records = Vec::new();
        while let Some(item) = stream.next().await {
            let response = item.context("AXFR failed")?;
            check_response("AXFR", response.metadata.response_code)?;
            records.extend(response.answers.iter().filter_map(listed_from_record));
        }
        verbose::step(format_args!(
            "AXFR returned {} TLSA record(s)",
            records.len()
        ));
        Ok(records)
    }

    async fn add_hash(
        &self,
        zone: &str,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
    ) -> Result<()> {
        let record = tlsa_record(zone, hostname, port, certificate, self.ttl)?;
        let origin = parse_name(zone)?;
        verbose::step(format_args!(
            "nsupdate UPDATE add {} TLSA",
            tlsa::owner_name(port, hostname)
        ));
        let mut client = self.connect().await?;
        let response = client
            .append(record, origin, false)
            .await
            .context("nsupdate add failed")?;
        check_response("add", response.metadata.response_code)
    }

    async fn delete_hash(
        &self,
        zone: &str,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
    ) -> Result<()> {
        let record = tlsa_record(zone, hostname, port, certificate, 0)?;
        let origin = parse_name(zone)?;
        verbose::step(format_args!(
            "nsupdate UPDATE delete {} TLSA {}",
            tlsa::owner_name(port, hostname),
            certificate
        ));
        let mut client = self.connect().await?;
        let response = client
            .delete_by_rdata(record, origin)
            .await
            .context("nsupdate delete failed")?;
        check_response("delete", response.metadata.response_code)
    }
}

impl ListedTlsa {
    fn to_dane(&self) -> DaneTlsa {
        DaneTlsa {
            usage: self.usage,
            selector: self.selector,
            matching: self.matching,
            certificate: self.certificate.clone(),
        }
    }
}

fn listed_from_record(record: &Record) -> Option<ListedTlsa> {
    let RData::TLSA(tlsa) = &record.data else {
        return None;
    };
    Some(ListedTlsa {
        name: record.name.to_string(),
        usage: u8::from(tlsa.cert_usage),
        selector: u8::from(tlsa.selector),
        matching: u8::from(tlsa.matching),
        certificate: hex::encode(&tlsa.cert_data),
    })
}

fn tlsa_record(
    zone: &str,
    hostname: Option<&str>,
    port: u16,
    certificate: &str,
    ttl: u32,
) -> Result<Record> {
    let name = parse_name(&tlsa::fqdn(zone, port, hostname))?;
    let cert_data = hex::decode(certificate).context("invalid TLSA hash")?;
    let rdata = RData::TLSA(TLSA::new(
        CertUsage::from(tlsa::USAGE),
        Selector::from(tlsa::SELECTOR),
        Matching::from(tlsa::MATCHING),
        cert_data,
    ));
    Ok(Record::from_rdata(name, ttl, rdata))
}

fn parse_name(name: &str) -> Result<Name> {
    let name = name.trim();
    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    };
    Name::from_str(&fqdn).with_context(|| format!("invalid DNS name {name}"))
}

fn check_response(op: &str, code: ResponseCode) -> Result<()> {
    if code == ResponseCode::NoError {
        return Ok(());
    }
    bail!("nsupdate {op} failed: {code}");
}

#[derive(Debug, Default, Clone)]
struct PartialConfig {
    server: Option<String>,
    port: Option<u16>,
    key_name: Option<String>,
    secret: Option<String>,
    algorithm: Option<String>,
    ttl: Option<u32>,
}

impl PartialConfig {
    fn into_config(self) -> Result<Config> {
        let server = self.server.filter(|value| !value.is_empty()).context(
            "nsupdate server is required (server= in nsupdate.cfg or GENTLSA_NSUPDATE_SERVER)",
        )?;
        let key_name = self
            .key_name
            .filter(|value| !value.is_empty())
            .context(
                "nsupdate key-name is required (key-name= in nsupdate.cfg or GENTLSA_NSUPDATE_KEY_NAME)",
            )?;
        let secret_raw = self.secret.filter(|value| !value.is_empty()).context(
            "nsupdate secret is required (secret= in nsupdate.cfg or GENTLSA_NSUPDATE_SECRET)",
        )?;
        let secret = decode_secret(&secret_raw)?;
        let algorithm = parse_algorithm(self.algorithm.as_deref().unwrap_or("hmac-sha256"))?;
        if !algorithm.supported() {
            bail!(
                "TSIG algorithm {algorithm} is not supported (use hmac-sha256, hmac-sha384, or hmac-sha512)"
            );
        }
        Ok(Config {
            server,
            port: self.port.unwrap_or(DEFAULT_PORT),
            key_name,
            secret,
            algorithm,
            ttl: self.ttl.unwrap_or(DEFAULT_TTL),
        })
    }
}

fn load_config() -> Result<Option<(PartialConfig, Option<PathBuf>)>> {
    for path in config_paths() {
        if let Some(cfg) = load_config_from(&path)? {
            return Ok(Some((cfg, Some(path))));
        }
    }
    Ok(None)
}

fn load_config_from(path: &Path) -> Result<Option<PartialConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let conf = ini::Ini::load_from_file(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Some(partial_from_ini(&conf)))
}

fn partial_from_ini(conf: &ini::Ini) -> PartialConfig {
    let section = conf
        .section(Some("Nsupdate"))
        .or_else(|| conf.section(Some("nsupdate")))
        .or_else(|| conf.section(Some("NSUpdate")));
    let Some(section) = section else {
        return PartialConfig::default();
    };
    PartialConfig {
        server: first_key(section, &["server", "host", "nameserver", "ns"]),
        port: first_key(section, &["port"]).and_then(|value| value.parse().ok()),
        key_name: first_key(section, &["key-name", "key_name", "keyname", "name"]),
        secret: first_key(section, &["secret", "key", "key-secret"]),
        algorithm: first_key(section, &["algorithm", "alg", "hmac"]),
        ttl: first_key(section, &["ttl"]).and_then(|value| value.parse().ok()),
    }
}

fn first_key(section: &ini::Properties, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| section.get(key))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn overlay_env(cfg: &mut PartialConfig) -> Result<()> {
    if let Some(server) = env_value(&["GENTLSA_NSUPDATE_SERVER"])? {
        cfg.server = Some(server);
    }
    if let Some(port) = env_value(&["GENTLSA_NSUPDATE_PORT"])? {
        cfg.port = Some(
            port.parse()
                .with_context(|| format!("invalid GENTLSA_NSUPDATE_PORT {port}"))?,
        );
    }
    if let Some(key_name) = env_value(&["GENTLSA_NSUPDATE_KEY_NAME"])? {
        cfg.key_name = Some(key_name);
    }
    if let Some(secret) = env_value(&["GENTLSA_NSUPDATE_SECRET"])? {
        cfg.secret = Some(secret);
    }
    if let Some(algorithm) = env_value(&["GENTLSA_NSUPDATE_ALGORITHM"])? {
        cfg.algorithm = Some(algorithm);
    }
    if let Some(ttl) = env_value(&["GENTLSA_NSUPDATE_TTL"])? {
        cfg.ttl = Some(
            ttl.parse()
                .with_context(|| format!("invalid GENTLSA_NSUPDATE_TTL {ttl}"))?,
        );
    }
    Ok(())
}

fn env_value(keys: &[&str]) -> Result<Option<String>> {
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Ok(Some(value));
            }
        }
    }
    Ok(None)
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/gentlsa/nsupdate.cfg")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".gentlsa").join("nsupdate.cfg"));
    }
    paths
}

fn parse_algorithm(raw: &str) -> Result<TsigAlgorithm> {
    let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
    let algorithm = match normalized.as_str() {
        "hmac-sha256" | "sha256" | "hmacsha256" => TsigAlgorithm::HmacSha256,
        "hmac-sha384" | "sha384" | "hmacsha384" => TsigAlgorithm::HmacSha384,
        "hmac-sha512" | "sha512" | "hmacsha512" => TsigAlgorithm::HmacSha512,
        "hmac-sha512-256" | "hmacsha512-256" => TsigAlgorithm::HmacSha512_256,
        other => {
            bail!("unknown TSIG algorithm '{other}' (use hmac-sha256, hmac-sha384, or hmac-sha512)")
        }
    };
    Ok(algorithm)
}

fn decode_secret(raw: &str) -> Result<Vec<u8>> {
    let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        bail!("nsupdate secret is empty");
    }
    if cleaned.len() >= 16
        && cleaned.len().is_multiple_of(2)
        && cleaned.chars().all(|c| c.is_ascii_hexdigit())
    {
        return hex::decode(&cleaned).context("invalid hex TSIG secret");
    }
    data_encoding::BASE64
        .decode(cleaned.as_bytes())
        .or_else(|_| data_encoding::BASE64_NOPAD.decode(cleaned.as_bytes()))
        .context("nsupdate secret must be base64 (BIND key format) or hex")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_algorithm_aliases() {
        assert_eq!(
            parse_algorithm("HMAC-SHA256").unwrap(),
            TsigAlgorithm::HmacSha256
        );
        assert_eq!(
            parse_algorithm("sha384").unwrap(),
            TsigAlgorithm::HmacSha384
        );
        assert_eq!(
            parse_algorithm("hmac_sha512").unwrap(),
            TsigAlgorithm::HmacSha512
        );
        assert!(parse_algorithm("hmac-md5").is_err());
    }

    #[test]
    fn decode_secret_base64_and_hex() {
        let bytes = decode_secret("AQIDBAUGBwgJCgsMDQ4PEA==").unwrap();
        assert_eq!(bytes, (1u8..=16).collect::<Vec<_>>());

        let hexed = decode_secret("0102030405060708090a0b0c0d0e0f10").unwrap();
        assert_eq!(hexed, bytes);
    }

    #[test]
    fn ini_reads_aliases() {
        let conf = ini::Ini::load_from_str(
            "[nsupdate]\n\
             nameserver = ns1.example.com\n\
             key_name = gentlsa-update.\n\
             key = AQIDBAUGBwgJCgsMDQ4PEA==\n\
             hmac = sha256\n\
             ttl = 120\n",
        )
        .unwrap();
        let partial = partial_from_ini(&conf);
        let cfg = partial.into_config().unwrap();
        assert_eq!(cfg.server, "ns1.example.com");
        assert_eq!(cfg.port, 53);
        assert_eq!(cfg.key_name, "gentlsa-update.");
        assert_eq!(cfg.algorithm, TsigAlgorithm::HmacSha256);
        assert_eq!(cfg.ttl, 120);
        assert_eq!(cfg.secret.len(), 16);
    }

    #[test]
    fn missing_required_fields() {
        let conf = ini::Ini::load_from_str("[Nsupdate]\nserver = ns1.example.com\n").unwrap();
        assert!(partial_from_ini(&conf).into_config().is_err());
    }

    #[test]
    fn listed_owner_filter_uses_shared_rules() {
        let rec = ListedTlsa {
            name: "_25._tcp.mx.example.org.".into(),
            usage: 3,
            selector: 1,
            matching: 1,
            certificate: "aa".into(),
        };
        assert!(publish::record_matches_filter(
            &rec.name,
            "example.org",
            Some("mx"),
            &[25]
        ));
        assert!(publish::names_equal(&rec.name, "_25._tcp.mx.example.org"));
    }

    #[test]
    fn config_paths_prefer_etc_gentlsa() {
        let paths = config_paths();
        assert_eq!(paths[0], PathBuf::from("/etc/gentlsa/nsupdate.cfg"));
        assert!(paths.iter().any(|path| {
            path.file_name().is_some_and(|name| name == "nsupdate.cfg")
                && path
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .is_some_and(|name| name == ".gentlsa")
        }));
    }
}
