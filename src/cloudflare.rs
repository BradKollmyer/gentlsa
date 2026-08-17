use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone)]
pub struct ListedTlsa {
    pub id: String,
    pub name: String,
    pub usage: u8,
    pub selector: u8,
    pub matching: u8,
    pub certificate: String,
}

impl ListedTlsa {
    pub fn to_text(&self) -> String {
        format!(
            "{} {} {} {}",
            self.usage, self.selector, self.matching, self.certificate
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishMode {
    /// Add the live hash if it is missing; keep any existing hashes.
    Rollover,
    /// Overwrite the first matching 3 1 1 record (legacy behavior).
    Replace,
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
    ) -> Result<()> {
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

        if ours
            .iter()
            .any(|record| record.hash_matches(certificate) && record.is_dane_ee_spki_sha256())
        {
            verbose::step("live hash already published, skipping");
            println!(
                "Cloudflare: TLSA already published for {} ({owner})",
                zone.name
            );
            return Ok(());
        }

        let payload = tlsa_payload(&owner, certificate);

        match mode {
            PublishMode::Replace => {
                if let Some(existing) = ours
                    .iter()
                    .find(|record| record.is_dane_ee_spki_sha256())
                    .copied()
                {
                    if dryrun {
                        println!(
                            "Cloudflare: dry run, would replace TLSA {} on {}",
                            existing.id, zone.name
                        );
                        return Ok(());
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
                    println!("Cloudflare: TLSA record updated for {}", zone.name);
                    return Ok(());
                }
            }
            PublishMode::Rollover => {
                if !ours.is_empty() {
                    println!(
                        "Cloudflare: keeping {} existing TLSA record(s) for rollover",
                        ours.len()
                    );
                }
            }
        }

        if dryrun {
            println!(
                "Cloudflare: dry run, would add {owner} TLSA for {}",
                zone.name
            );
            return Ok(());
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
        println!("Cloudflare: TLSA record added for {}", zone.name);
        Ok(())
    }

    pub async fn prune_tlsa(
        &self,
        zone: &Zone,
        hostname: Option<&str>,
        port: u16,
        live_hash: &str,
        dryrun: bool,
    ) -> Result<usize> {
        verbose::step(format_args!(
            "prune stale TLSA for {} port {port} dryrun={dryrun}",
            tlsa::owner_name(port, hostname)
        ));
        let expected = expected_names(zone, hostname, port);
        let records = self.tlsa_records(zone).await?;
        let stale: Vec<&DnsRecord> = records
            .iter()
            .filter(|record| {
                record.matches_owner(&expected)
                    && record.is_dane_ee_spki_sha256()
                    && !record.hash_matches(live_hash)
            })
            .collect();
        verbose::step(format_args!("{} stale TLSA record(s)", stale.len()));

        if stale.is_empty() {
            println!("Cloudflare: no stale TLSA records for {}", zone.name);
            return Ok(0);
        }

        for record in &stale {
            let hash = record
                .data
                .as_ref()
                .map(|data| data.certificate.as_str())
                .unwrap_or("?");
            if dryrun {
                println!("Cloudflare: dry run, would delete stale TLSA {hash}");
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
            println!("Cloudflare: deleted stale TLSA {hash}");
        }
        Ok(stale.len())
    }

    async fn tlsa_records(&self, zone: &Zone) -> Result<Vec<DnsRecord>> {
        verbose::step("listing Cloudflare TLSA records");
        self.get_result(&format!("/zones/{}/dns_records?type=TLSA", zone.id))
            .await
            .context("failed to list Cloudflare TLSA records")
    }

    pub fn print_zone_info(&self, zone: &Zone) {
        println!(">>> Cloudflare Information:");
        println!("Zone name: {}", zone.name);
        println!("Zone ID: {}", zone.id);
        println!("Zone owner: {}", zone.owner_label());
        println!("Name servers: {:?}", zone.name_servers);
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
    let mut names = vec![format!("_{port}._tcp.{}", zone.name)];
    if let Some(host) = hostname.filter(|host| !host.is_empty()) {
        names.push(format!("_{port}._tcp.{host}.{}", zone.name));
    }
    names
}

fn record_matches(name: &str, zone: &Zone, hostname: Option<&str>, ports: &[u16]) -> bool {
    if !ports.is_empty() {
        return expected_names_for_ports(zone, hostname, ports)
            .iter()
            .any(|expected| expected.eq_ignore_ascii_case(name));
    }
    let Some(host) = hostname.filter(|host| !host.is_empty()) else {
        return true;
    };
    owner_host(name, &zone.name)
        .is_some_and(|labels| labels.is_empty() || labels.eq_ignore_ascii_case(host))
}

fn expected_names_for_ports(zone: &Zone, hostname: Option<&str>, ports: &[u16]) -> Vec<String> {
    ports
        .iter()
        .flat_map(|port| expected_names(zone, hostname, *port))
        .collect()
}

/// Host labels after `_<port>._tcp` and before the zone, if the name is a TLSA owner.
fn owner_host<'a>(name: &'a str, zone: &str) -> Option<&'a str> {
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
        self.record_type == "TLSA"
            && expected
                .iter()
                .any(|name| name.eq_ignore_ascii_case(&self.name))
    }

    fn is_dane_ee_spki_sha256(&self) -> bool {
        self.data.as_ref().is_some_and(|data| {
            data.usage == tlsa::USAGE
                && data.selector == tlsa::SELECTOR
                && data.matching_type == tlsa::MATCHING
        })
    }

    fn hash_matches(&self, live: &str) -> bool {
        self.data
            .as_ref()
            .is_some_and(|data| tlsa::hashes_equal(live, &data.certificate))
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

    if let Some(auth) = load_config_auth()? {
        verbose::step(format_args!(
            "Cloudflare credentials from {}",
            config_path().display()
        ));
        return Ok(auth);
    }

    bail!(
        "Please configure Cloudflare credentials in ~/.cloudflare/cloudflare.cfg \
         or CF_API_TOKEN / CF_API_EMAIL+CF_API_KEY"
    )
}

fn load_config_auth() -> Result<Option<Auth>> {
    let path = config_path();
    if !path.exists() {
        return Ok(None);
    }

    let conf = ini::Ini::load_from_file(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let section = conf
        .section(Some("CloudFlare"))
        .or_else(|| conf.section(Some("Cloudflare")));

    let Some(section) = section else {
        return Ok(None);
    };

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
        (Some(email), Some(token)) => Ok(Some(Auth::Key { email, key: token })),
        (None, Some(token)) => Ok(Some(Auth::Token(token))),
        _ => Ok(None),
    }
}

fn config_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".cloudflare")
        .join("cloudflare.cfg")
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
        DnsRecord {
            id: "id".into(),
            name: name.into(),
            record_type: "TLSA".into(),
            data: Some(TlsaData {
                usage: 3,
                selector: 1,
                matching_type: 1,
                certificate: hash.into(),
            }),
        }
    }

    #[test]
    fn owner_and_hash_matching() {
        let zone = Zone {
            id: "z".into(),
            name: "example.org".into(),
            name_servers: vec![],
            owner: None,
            account: None,
        };
        let names = expected_names(&zone, Some("mx"), 25);
        let rec = record("_25._tcp.mx.example.org", "AA");
        assert!(rec.matches_owner(&names));
        assert!(rec.is_dane_ee_spki_sha256());
        assert!(rec.hash_matches("aa"));
        assert!(!rec.hash_matches("bb"));
    }

    #[test]
    fn list_filter_any_or_selected_ports() {
        let zone = Zone {
            id: "z".into(),
            name: "example.org".into(),
            name_servers: vec![],
            owner: None,
            account: None,
        };
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
}
