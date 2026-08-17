use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::output;
use crate::publish::{
    self, DaneTlsa, PruneReport, PublishAction, PublishMode, PublishReport, names_equal,
};
use crate::tlsa;
use crate::verbose;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Clone)]
enum Auth {
    Token(String),
    Key { email: String, key: String },
}

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    auth_label: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: String,
}

#[derive(Debug, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub name_servers: Vec<String>,
    pub owner: Option<ZoneOwner>,
    pub account: Option<ZoneAccount>,
}

#[derive(Debug, Deserialize)]
pub struct ZoneOwner {
    pub email: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ZoneAccount {
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    data: Option<TlsaData>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListedTlsa {
    pub id: String,
    pub name: String,
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZoneInfo {
    pub name: String,
    pub id: String,
    pub owner: String,
    pub name_servers: Vec<String>,
}

impl ZoneInfo {
    pub fn from_zone(zone: &Zone) -> Self {
        Self {
            name: zone.name.clone(),
            id: zone.id.clone(),
            owner: zone.owner_label(),
            name_servers: zone.name_servers.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct TlsaPayload {
    name: String,
    #[serde(rename = "type")]
    record_type: &'static str,
    ttl: u32,
    data: TlsaData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsaData {
    usage: u8,
    selector: u8,
    matching_type: u8,
    certificate: String,
}

impl Zone {
    pub fn owner_label(&self) -> String {
        self.owner
            .as_ref()
            .and_then(|owner| owner.email.clone())
            .or_else(|| {
                self.account
                    .as_ref()
                    .and_then(|account| account.name.clone())
            })
            .unwrap_or_else(|| "(unknown)".to_string())
    }
}

impl Client {
    pub fn from_env_or_config() -> Result<Self> {
        verbose::step("loading Cloudflare credentials");
        let auth = load_auth()?;
        let auth_label = match &auth {
            Auth::Token(_) => "API token".to_string(),
            Auth::Key { email, .. } => format!("global API key ({email})"),
        };
        verbose::step(format_args!("Cloudflare auth: {auth_label}"));
        let http = reqwest::Client::builder()
            .default_headers(auth_headers(&auth)?)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { http, auth_label })
    }

    pub fn auth_label(&self) -> &str {
        &self.auth_label
    }

    pub async fn list_zones(&self) -> Result<Vec<Zone>> {
        self.get_result("/zones").await
    }

    pub async fn zone_by_name(&self, name: &str) -> Result<Option<Zone>> {
        verbose::step(format_args!("looking up Cloudflare zone {name}"));
        let zones: Vec<Zone> = self
            .get_result(&format!("/zones?name={name}"))
            .await
            .with_context(|| format!("failed to look up Cloudflare zone {name}"))?;
        let zone = zones.into_iter().next();
        match &zone {
            Some(zone) => verbose::step(format_args!("found zone {} ({})", zone.name, zone.id)),
            None => verbose::step(format_args!("no Cloudflare zone named {name}")),
        }
        Ok(zone)
    }

    pub async fn list_tlsa(
        &self,
        zone: &Zone,
        hostname: Option<&str>,
        ports: &[u16],
    ) -> Result<Vec<ListedTlsa>> {
        let records = self.tlsa_records(zone).await?;
        Ok(records
            .into_iter()
            .filter(|record| record_matches(&record.name, zone, hostname, ports))
            .filter_map(|record| {
                let data = record.data?;
                Some(ListedTlsa {
                    id: record.id,
                    name: record.name,
                    usage: data.usage,
                    selector: data.selector,
                    matching: data.matching_type,
                    certificate: data.certificate,
                })
            })
            .collect())
    }

    pub async fn publish_tlsa(
        &self,
        zone: &Zone,
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
            "publish {owner} mode={mode_label} dryrun={dryrun}"
        ));
        let expected = expected_names(zone, hostname, port);
        let records = self.tlsa_records(zone).await?;
        let ours: Vec<&DnsRecord> = records
            .iter()
            .filter(|record| record.matches_owner(&expected))
            .collect();
        verbose::step(format_args!(
            "found {} existing TLSA record(s) for {owner}",
            ours.len()
        ));

        let report = |action: PublishAction| PublishReport {
            zone: zone.name.clone(),
            owner: owner.clone(),
            action,
            mode,
            dryrun,
            existing: ours.len(),
            info: None,
        };

        let dane: Vec<DaneTlsa> = ours.iter().filter_map(|record| record.to_dane()).collect();
        let action = publish::publish_action(&dane, certificate, mode, dryrun);
        if action == PublishAction::AlreadyPublished {
            verbose::step("live hash already published, skipping");
            output::text(format!(
                "Cloudflare: TLSA already published for {} ({owner})",
                zone.name
            ));
            return Ok(report(action));
        }

        if mode == PublishMode::Rollover && !ours.is_empty() {
            output::text(format!(
                "Cloudflare: keeping {} existing TLSA record(s) for rollover",
                ours.len()
            ));
        }

        let payload = tlsa_payload(&owner, certificate);
        match action {
            PublishAction::Replaced | PublishAction::WouldReplace => {
                let existing = ours
                    .iter()
                    .find(|record| record.is_dane_ee_spki_sha256())
                    .copied()
                    .expect("replace action requires an existing 3 1 1 record");
                if action == PublishAction::WouldReplace {
                    output::text(format!(
                        "Cloudflare: dry run, would replace TLSA {} on {}",
                        existing.id, zone.name
                    ));
                    return Ok(report(action));
                }
                let _: DnsRecord = self
                    .put_result(
                        &format!("/zones/{}/dns_records/{}", zone.id, existing.id),
                        &payload,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "Something went screwy: {} - Error: update failed",
                            zone.name
                        )
                    })?;
                output::text(format!("Cloudflare: TLSA record updated for {}", zone.name));
                Ok(report(action))
            }
            PublishAction::Added | PublishAction::WouldAdd => {
                if action == PublishAction::WouldAdd {
                    output::text(format!(
                        "Cloudflare: dry run, would add {owner} TLSA for {}",
                        zone.name
                    ));
                    return Ok(report(action));
                }
                let _: DnsRecord = self
                    .post_result(&format!("/zones/{}/dns_records", zone.id), &payload)
                    .await
                    .with_context(|| {
                        format!(
                            "Something went screwy: {} - Error: create failed",
                            zone.name
                        )
                    })?;
                output::text(format!("Cloudflare: TLSA record added for {}", zone.name));
                Ok(report(action))
            }
            PublishAction::AlreadyPublished => unreachable!("handled above"),
        }
    }

    pub async fn prune_tlsa(
        &self,
        zone: &Zone,
        hostname: Option<&str>,
        port: u16,
        live_hash: &str,
        dryrun: bool,
    ) -> Result<PruneReport> {
        verbose::step(format_args!(
            "prune stale TLSA for {} port {port} dryrun={dryrun}",
            tlsa::owner_name(port, hostname)
        ));
        let expected = expected_names(zone, hostname, port);
        let records = self.tlsa_records(zone).await?;
        let stale = stale_cf_tlsa(&records, &expected, live_hash);
        verbose::step(format_args!("{} stale TLSA record(s)", stale.len()));

        let hashes: Vec<String> = stale
            .iter()
            .map(|record| {
                record
                    .data
                    .as_ref()
                    .map(|data| data.certificate.clone())
                    .unwrap_or_else(|| "?".into())
            })
            .collect();

        if stale.is_empty() {
            output::text(format!(
                "Cloudflare: no stale TLSA records for {}",
                zone.name
            ));
            return Ok(PruneReport {
                zone: zone.name.clone(),
                dryrun,
                stale: hashes,
            });
        }

        for (record, hash) in stale.iter().zip(&hashes) {
            if dryrun {
                output::text(format!(
                    "Cloudflare: dry run, would delete stale TLSA {hash}"
                ));
                continue;
            }
            self.delete(&format!("/zones/{}/dns_records/{}", zone.id, record.id))
                .await
                .with_context(|| {
                    format!(
                        "Something went screwy: {} - Error: delete failed",
                        zone.name
                    )
                })?;
            output::text(format!("Cloudflare: deleted stale TLSA {hash}"));
        }
        Ok(PruneReport {
            zone: zone.name.clone(),
            dryrun,
            stale: hashes,
        })
    }

    async fn tlsa_records(&self, zone: &Zone) -> Result<Vec<DnsRecord>> {
        verbose::step("listing Cloudflare TLSA records");
        self.get_result(&format!("/zones/{}/dns_records?type=TLSA", zone.id))
            .await
            .context("failed to list Cloudflare TLSA records")
    }

    pub fn print_zone_info(&self, zone: &Zone) {
        output::text(">>> Cloudflare Information:");
        output::text(format!("Zone name: {}", zone.name));
        output::text(format!("Zone ID: {}", zone.id));
        output::text(format!("Zone owner: {}", zone.owner_label()));
        output::text(format!("Name servers: {:?}", zone.name_servers));
    }

    async fn get_result<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        verbose::step(format_args!("Cloudflare GET {path}"));
        let response = self
            .http
            .get(format!("{API_BASE}{path}"))
            .send()
            .await
            .with_context(|| format!("Cloudflare GET {path} failed"))?;
        parse_response(response).await
    }

    async fn post_result<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        verbose::step(format_args!("Cloudflare POST {path}"));
        let response = self
            .http
            .post(format!("{API_BASE}{path}"))
            .json(body)
            .send()
            .await
            .with_context(|| format!("Cloudflare POST {path} failed"))?;
        parse_response(response).await
    }

    async fn put_result<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        verbose::step(format_args!("Cloudflare PUT {path}"));
        let response = self
            .http
            .put(format!("{API_BASE}{path}"))
            .json(body)
            .send()
            .await
            .with_context(|| format!("Cloudflare PUT {path} failed"))?;
        parse_response(response).await
    }

    async fn delete(&self, path: &str) -> Result<()> {
        verbose::step(format_args!("Cloudflare DELETE {path}"));
        let response = self
            .http
            .delete(format!("{API_BASE}{path}"))
            .send()
            .await
            .with_context(|| format!("Cloudflare DELETE {path} failed"))?;
        let status = response.status();
        let parsed: ApiResponse<serde_json::Value> = response
            .json()
            .await
            .with_context(|| format!("Cloudflare returned a non-JSON response ({status})"))?;
        if !parsed.success {
            let messages = parsed
                .errors
                .into_iter()
                .map(|err| err.message)
                .collect::<Vec<_>>()
                .join("; ");
            bail!("Cloudflare API error ({status}): {messages}");
        }
        Ok(())
    }
}

fn expected_names(zone: &Zone, hostname: Option<&str>, port: u16) -> Vec<String> {
    publish::owner_names(&zone.name, hostname, port)
}

fn record_matches(name: &str, zone: &Zone, hostname: Option<&str>, ports: &[u16]) -> bool {
    publish::record_matches_filter(name, &zone.name, hostname, ports)
}

fn stale_cf_tlsa<'a>(
    records: &'a [DnsRecord],
    expected: &[String],
    live_hash: &str,
) -> Vec<&'a DnsRecord> {
    records
        .iter()
        .filter(|record| {
            record.matches_owner(expected)
                && record.is_dane_ee_spki_sha256()
                && !record.hash_matches(live_hash)
        })
        .collect()
}

fn tlsa_payload(owner: &str, certificate: &str) -> TlsaPayload {
    TlsaPayload {
        name: owner.to_string(),
        record_type: "TLSA",
        ttl: 1,
        data: TlsaData {
            usage: tlsa::USAGE,
            selector: tlsa::SELECTOR,
            matching_type: tlsa::MATCHING,
            certificate: certificate.to_string(),
        },
    }
}

impl DnsRecord {
    fn matches_owner(&self, expected: &[String]) -> bool {
        self.record_type == "TLSA" && expected.iter().any(|name| names_equal(name, &self.name))
    }

    fn is_dane_ee_spki_sha256(&self) -> bool {
        self.to_dane()
            .is_some_and(|dane| dane.is_dane_ee_spki_sha256())
    }

    fn hash_matches(&self, live: &str) -> bool {
        self.to_dane().is_some_and(|dane| dane.hash_matches(live))
    }

    fn to_dane(&self) -> Option<DaneTlsa> {
        let data = self.data.as_ref()?;
        Some(DaneTlsa {
            usage: data.usage,
            selector: data.selector,
            matching: data.matching_type,
            certificate: data.certificate.clone(),
        })
    }
}

async fn parse_response<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let parsed: ApiResponse<T> = response
        .json()
        .await
        .with_context(|| format!("Cloudflare returned a non-JSON response ({status})"))?;
    if !parsed.success {
        let messages = parsed
            .errors
            .into_iter()
            .map(|err| err.message)
            .collect::<Vec<_>>()
            .join("; ");
        bail!("Cloudflare API error ({status}): {messages}");
    }
    parsed
        .result
        .ok_or_else(|| anyhow::anyhow!("Cloudflare API returned no result"))
}

fn auth_headers(auth: &Auth) -> Result<HeaderMap> {
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));
    match auth {
        Auth::Token(token) => {
            let value = format!("Bearer {token}");
            headers.insert(
                "Authorization",
                HeaderValue::from_str(&value).context("invalid API token")?,
            );
        }
        Auth::Key { email, key } => {
            headers.insert(
                "X-Auth-Email",
                HeaderValue::from_str(email).context("invalid Cloudflare email")?,
            );
            headers.insert(
                "X-Auth-Key",
                HeaderValue::from_str(key).context("invalid Cloudflare API key")?,
            );
        }
    }
    Ok(headers)
}

fn load_auth() -> Result<Auth> {
    if let Ok(token) = first_env(&["CF_API_TOKEN", "CLOUDFLARE_API_TOKEN"]) {
        verbose::step("Cloudflare credentials from CF_API_TOKEN / CLOUDFLARE_API_TOKEN");
        return Ok(Auth::Token(token));
    }

    let email = first_env(&["CF_API_EMAIL", "CLOUDFLARE_EMAIL"]).ok();
    let key = first_env(&["CF_API_KEY", "CLOUDFLARE_API_KEY"]).ok();
    if let (Some(email), Some(key)) = (email, key) {
        verbose::step("Cloudflare credentials from CF_API_EMAIL / CF_API_KEY");
        return Ok(Auth::Key { email, key });
    }

    if let Some((auth, path)) = load_config_auth()? {
        verbose::step(format_args!(
            "Cloudflare credentials from {}",
            path.display()
        ));
        return Ok(auth);
    }

    bail!(
        "Please configure Cloudflare credentials in /etc/gentlsa/cloudflare.cfg \
         or CF_API_TOKEN / CF_API_EMAIL+CF_API_KEY"
    )
}

fn load_config_auth() -> Result<Option<(Auth, PathBuf)>> {
    for path in config_paths() {
        if let Some(auth) = load_config_auth_from(&path)? {
            return Ok(Some((auth, path)));
        }
    }
    Ok(None)
}

fn load_config_auth_from(path: &Path) -> Result<Option<Auth>> {
    if !path.exists() {
        return Ok(None);
    }

    let conf = ini::Ini::load_from_file(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    Ok(auth_from_ini(&conf))
}

fn auth_from_ini(conf: &ini::Ini) -> Option<Auth> {
    let section = conf
        .section(Some("CloudFlare"))
        .or_else(|| conf.section(Some("Cloudflare")))?;

    let token = section
        .get("api_token")
        .or_else(|| section.get("apitoken"))
        .or_else(|| section.get("token"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let email = section
        .get("email")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

    match (email, token) {
        (Some(email), Some(token)) => Some(Auth::Key { email, key: token }),
        (None, Some(token)) => Some(Auth::Token(token)),
        _ => None,
    }
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/gentlsa/cloudflare.cfg")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".cloudflare").join("cloudflare.cfg"));
    }
    paths
}

fn first_env(keys: &[&str]) -> Result<String> {
    for key in keys {
        if let Ok(value) = std::env::var(key) {
            let value = value.trim().to_string();
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    bail!("none of {} set", keys.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(name: &str, hash: &str) -> DnsRecord {
        record_data(name, hash, 3, 1, 1)
    }

    fn record_data(name: &str, hash: &str, usage: u8, selector: u8, matching: u8) -> DnsRecord {
        DnsRecord {
            id: "id".into(),
            name: name.into(),
            record_type: "TLSA".into(),
            data: Some(TlsaData {
                usage,
                selector,
                matching_type: matching,
                certificate: hash.into(),
            }),
        }
    }

    fn example_zone() -> Zone {
        Zone {
            id: "z".into(),
            name: "example.org".into(),
            name_servers: vec![],
            owner: None,
            account: None,
        }
    }

    #[test]
    fn owner_and_hash_matching() {
        let zone = example_zone();
        let names = expected_names(&zone, Some("mx"), 25);
        let rec = record("_25._tcp.mx.example.org", "AA");
        assert!(rec.matches_owner(&names));
        assert!(rec.is_dane_ee_spki_sha256());
        assert!(rec.hash_matches("aa"));
        assert!(!rec.hash_matches("bb"));
    }

    #[test]
    fn list_filter_any_or_selected_ports() {
        let zone = example_zone();
        assert!(record_matches("_443._tcp.example.org", &zone, None, &[]));
        assert!(record_matches("_25._tcp.mx.example.org", &zone, None, &[]));
        assert!(record_matches(
            "_25._tcp.mx.example.org",
            &zone,
            Some("mx"),
            &[]
        ));
        assert!(!record_matches(
            "_25._tcp.www.example.org",
            &zone,
            Some("mx"),
            &[]
        ));
        assert!(record_matches(
            "_25._tcp.mx.example.org",
            &zone,
            Some("mx"),
            &[25, 465]
        ));
        assert!(!record_matches(
            "_443._tcp.example.org",
            &zone,
            None,
            &[25, 465]
        ));
        assert!(record_matches(
            "_465._tcp.example.org",
            &zone,
            None,
            &[25, 465]
        ));
    }

    #[test]
    fn prune_only_stale_dane_ee() {
        let zone = example_zone();
        let expected = expected_names(&zone, Some("mx"), 25);
        let current = record("_25._tcp.mx.example.org", "AA");
        let stale = record("_25._tcp.mx.example.org", "BB");
        let other_port = record("_443._tcp.example.org", "CC");
        let other_selector = record_data("_25._tcp.mx.example.org", "DD", 3, 0, 1);

        let records = [current, stale, other_port, other_selector];
        let found = stale_cf_tlsa(&records, &expected, "aa");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].data.as_ref().map(|data| data.certificate.as_str()),
            Some("BB")
        );

        let current_only = [record("_25._tcp.mx.example.org", "aa")];
        let none = stale_cf_tlsa(&current_only, &expected, "AA");
        assert!(none.is_empty());
    }

    #[test]
    fn config_paths_prefer_etc_gentlsa() {
        let paths = config_paths();
        assert_eq!(paths[0], PathBuf::from("/etc/gentlsa/cloudflare.cfg"));
        assert!(paths.iter().any(|path| {
            path.file_name()
                .is_some_and(|name| name == "cloudflare.cfg")
                && path
                    .parent()
                    .and_then(|parent| parent.file_name())
                    .is_some_and(|name| name == ".cloudflare")
        }));
    }

    #[test]
    fn auth_from_ini_token_only() {
        let conf = ini::Ini::load_from_str("[CloudFlare]\ntoken = abc\n").unwrap();
        match auth_from_ini(&conf) {
            Some(Auth::Token(token)) => assert_eq!(token, "abc"),
            other => panic!("expected token auth, got {other:?}"),
        }
    }

    #[test]
    fn auth_from_ini_accepts_aliases_and_email() {
        let conf = ini::Ini::load_from_str(
            "[Cloudflare]\nemail = ops@example.com\napi_token = global-key\n",
        )
        .unwrap();
        match auth_from_ini(&conf) {
            Some(Auth::Key { email, key }) => {
                assert_eq!(email, "ops@example.com");
                assert_eq!(key, "global-key");
            }
            other => panic!("expected key auth, got {other:?}"),
        }
    }

    #[test]
    fn auth_from_ini_ignores_empty_or_missing() {
        let missing = ini::Ini::load_from_str("[other]\ntoken = abc\n").unwrap();
        assert!(auth_from_ini(&missing).is_none());

        let empty = ini::Ini::load_from_str("[CloudFlare]\ntoken = \n").unwrap();
        assert!(auth_from_ini(&empty).is_none());
    }
}
