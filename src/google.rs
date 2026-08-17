use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::output;
use crate::publish::{
    self, DaneTlsa, ListedTlsa, PruneReport, PublishAction, PublishMode, PublishReport,
};
use crate::tlsa;
use crate::verbose;

const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const API_BASE: &str = "https://dns.googleapis.com/dns/v1";
const SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";
const DEFAULT_TTL: u32 = 3600;

#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    project: String,
    client_email: String,
    private_key: String,
    ttl: u32,
    token: tokio::sync::Mutex<Option<CachedToken>>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZoneInfo {
    pub project: String,
    pub name: String,
    pub dns_name: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct ManagedZone {
    pub name: String,
    pub dns_name: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    #[serde(default)]
    project_id: String,
    client_email: String,
    private_key: String,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct ZonesResponse {
    #[serde(default, rename = "managedZones")]
    managed_zones: Vec<ZoneJson>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZoneJson {
    name: String,
    #[serde(rename = "dnsName")]
    dns_name: String,
    #[serde(default)]
    id: String,
}

#[derive(Debug, Deserialize)]
struct RrsetsResponse {
    #[serde(default)]
    rrsets: Vec<Rrset>,
    #[serde(default, rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rrset {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    #[serde(default)]
    ttl: u32,
    #[serde(default)]
    rrdatas: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ChangeRequest {
    additions: Vec<Rrset>,
    deletions: Vec<Rrset>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    message: Option<String>,
}

impl Client {
    pub fn from_env_or_config() -> Result<Self> {
        verbose::step("loading Google Cloud DNS credentials");
        let loaded = load_config()?;
        verbose::step(format_args!(
            "Google Cloud DNS project={} account={}",
            loaded.project, loaded.client_email
        ));
        let http = reqwest::Client::builder()
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            project: loaded.project,
            client_email: loaded.client_email,
            private_key: loaded.private_key,
            ttl: loaded.ttl,
            token: tokio::sync::Mutex::new(None),
        })
    }

    pub fn auth_label(&self) -> String {
        format!("service account {}", self.client_email)
    }

    pub fn project(&self) -> &str {
        &self.project
    }

    pub async fn list_zones(&self) -> Result<Vec<ManagedZone>> {
        let mut zones = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let mut path = format!("/projects/{}/managedZones", self.project);
            if let Some(token) = &page {
                path.push_str(&format!("?pageToken={}", urlencoding(token)));
            }
            let parsed: ZonesResponse = self.get_json(&path).await?;
            zones.extend(parsed.managed_zones.into_iter().map(ManagedZone::from));
            match parsed.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) => page = Some(token),
                None => break,
            }
        }
        Ok(zones)
    }

    pub async fn zone_by_name(&self, name: &str) -> Result<Option<ManagedZone>> {
        let dns = trailing_dot(name);
        verbose::step(format_args!("looking up Google Cloud DNS zone {dns}"));
        let path = format!(
            "/projects/{}/managedZones?dnsName={}",
            self.project,
            urlencoding(&dns)
        );
        let parsed: ZonesResponse = self.get_json(&path).await?;
        let zone = parsed
            .managed_zones
            .into_iter()
            .map(ManagedZone::from)
            .find(|zone| {
                publish::names_equal(&zone.dns_name, name) || publish::names_equal(&zone.name, name)
            });
        match &zone {
            Some(zone) => {
                verbose::step(format_args!("found zone {} ({})", zone.dns_name, zone.name))
            }
            None => verbose::step(format_args!("no Google Cloud DNS zone named {name}")),
        }
        Ok(zone)
    }

    pub async fn list_tlsa(
        &self,
        zone: &ManagedZone,
        hostname: Option<&str>,
        ports: &[u16],
    ) -> Result<Vec<ListedTlsa>> {
        let records = self.tlsa_records(zone).await?;
        Ok(records
            .into_iter()
            .filter(|record| {
                publish::record_matches_filter(&record.name, &zone.dns_name, hostname, ports)
            })
            .collect())
    }

    pub async fn publish_tlsa(
        &self,
        zone: &ManagedZone,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
        mode: PublishMode,
        dryrun: bool,
    ) -> Result<PublishReport> {
        let owner = tlsa::owner_name(port, hostname);
        let fqdn = publish::fqdn_owner(&zone.dns_name, hostname, port);
        verbose::step(format_args!(
            "Google Cloud DNS publish {owner} mode={mode:?} dryrun={dryrun}"
        ));
        let current = self.rrset_for_owner(zone, &fqdn).await?;
        let dane = current.as_ref().map(Rrset::to_dane).unwrap_or_default();
        let action = publish::publish_action(&dane, certificate, mode, dryrun);
        let report = |action: PublishAction| PublishReport {
            zone: zone.dns_name.trim_end_matches('.').to_string(),
            owner: owner.clone(),
            action,
            mode,
            dryrun,
            existing: dane.len(),
            info: None,
        };

        if action == PublishAction::AlreadyPublished {
            verbose::step("live hash already published, skipping");
            output::text(format!(
                "Google Cloud DNS: TLSA already published for {} ({owner})",
                zone.dns_name.trim_end_matches('.')
            ));
            return Ok(report(action));
        }
        if mode == PublishMode::Rollover && !dane.is_empty() {
            output::text(format!(
                "Google Cloud DNS: keeping {} existing TLSA record(s) for rollover",
                dane.len()
            ));
        }

        match action {
            PublishAction::WouldAdd => {
                output::text(format!(
                    "Google Cloud DNS: dry run, would add {owner} TLSA for {}",
                    zone.dns_name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::WouldReplace => {
                output::text(format!(
                    "Google Cloud DNS: dry run, would replace TLSA {owner} on {}",
                    zone.dns_name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::Added | PublishAction::Replaced => {
                let next = publish::rrset_after_publish(&dane, certificate, action);
                self.apply_rrset(zone, &fqdn, current.as_ref(), &next)
                    .await?;
                let verb = if action == PublishAction::Replaced {
                    "updated"
                } else {
                    "added"
                };
                output::text(format!(
                    "Google Cloud DNS: TLSA record {verb} for {}",
                    zone.dns_name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::AlreadyPublished => unreachable!("handled above"),
        }
    }

    pub async fn prune_tlsa(
        &self,
        zone: &ManagedZone,
        hostname: Option<&str>,
        port: u16,
        live_hash: &str,
        dryrun: bool,
    ) -> Result<PruneReport> {
        let fqdn = publish::fqdn_owner(&zone.dns_name, hostname, port);
        verbose::step(format_args!(
            "Google Cloud DNS prune stale TLSA for {fqdn} dryrun={dryrun}"
        ));
        let current = self.rrset_for_owner(zone, &fqdn).await?;
        let dane = current.as_ref().map(Rrset::to_dane).unwrap_or_default();
        let stale = publish::stale_dane(&dane, live_hash);
        let hashes: Vec<String> = stale
            .iter()
            .map(|record| record.certificate.clone())
            .collect();
        if stale.is_empty() {
            output::text(format!(
                "Google Cloud DNS: no stale TLSA records for {}",
                zone.dns_name.trim_end_matches('.')
            ));
            return Ok(PruneReport {
                zone: zone.dns_name.trim_end_matches('.').to_string(),
                dryrun,
                stale: hashes,
            });
        }
        if dryrun {
            for hash in &hashes {
                output::text(format!(
                    "Google Cloud DNS: dry run, would delete stale TLSA {hash}"
                ));
            }
        } else {
            let next = publish::rrset_after_prune(&dane, live_hash);
            self.apply_rrset(zone, &fqdn, current.as_ref(), &next)
                .await?;
            for hash in &hashes {
                output::text(format!("Google Cloud DNS: deleted stale TLSA {hash}"));
            }
        }
        Ok(PruneReport {
            zone: zone.dns_name.trim_end_matches('.').to_string(),
            dryrun,
            stale: hashes,
        })
    }

    pub fn print_zone_info(&self, zone: &ManagedZone) {
        output::text(">>> Google Cloud DNS Information:");
        output::text(format!("Project: {}", self.project));
        output::text(format!("Zone name: {}", zone.name));
        output::text(format!("DNS name: {}", zone.dns_name));
        output::text(format!("Zone ID: {}", zone.id));
    }

    async fn tlsa_records(&self, zone: &ManagedZone) -> Result<Vec<ListedTlsa>> {
        verbose::step("listing Google Cloud DNS TLSA records");
        let mut records = Vec::new();
        let mut page: Option<String> = None;
        loop {
            let mut path = format!(
                "/projects/{}/managedZones/{}/rrsets?type=TLSA",
                self.project, zone.name
            );
            if let Some(token) = &page {
                path.push_str("&pageToken=");
                path.push_str(&urlencoding(token));
            }
            let parsed: RrsetsResponse = self.get_json(&path).await?;
            records.extend(parsed.rrsets.iter().flat_map(Rrset::to_listed));
            match parsed.next_page_token.filter(|token| !token.is_empty()) {
                Some(token) => page = Some(token),
                None => break,
            }
        }
        verbose::step(format_args!(
            "Google Cloud DNS returned {} TLSA value(s)",
            records.len()
        ));
        Ok(records)
    }

    async fn rrset_for_owner(&self, zone: &ManagedZone, fqdn: &str) -> Result<Option<Rrset>> {
        let path = format!(
            "/projects/{}/managedZones/{}/rrsets?name={}&type=TLSA",
            self.project,
            zone.name,
            urlencoding(fqdn)
        );
        let parsed: RrsetsResponse = self.get_json(&path).await?;
        Ok(parsed.rrsets.into_iter().next())
    }

    async fn apply_rrset(
        &self,
        zone: &ManagedZone,
        fqdn: &str,
        current: Option<&Rrset>,
        next: &[DaneTlsa],
    ) -> Result<()> {
        let mut change = ChangeRequest {
            additions: Vec::new(),
            deletions: Vec::new(),
        };
        if let Some(current) = current {
            change.deletions.push(current.clone());
        }
        if !next.is_empty() {
            change
                .additions
                .push(Rrset::from_dane(fqdn, self.ttl, next));
        }
        if change.additions.is_empty() && change.deletions.is_empty() {
            return Ok(());
        }
        verbose::step(format_args!("Google Cloud DNS change {fqdn}"));
        let path = format!(
            "/projects/{}/managedZones/{}/changes",
            self.project, zone.name
        );
        self.post_json(&path, &change).await
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let token = self.access_token().await?;
        verbose::step(format_args!("Google Cloud DNS GET {path}"));
        let response = self
            .http
            .get(format!("{API_BASE}{path}"))
            .bearer_auth(token)
            .send()
            .await
            .with_context(|| format!("Google Cloud DNS GET {path} failed"))?;
        parse_json(response).await
    }

    async fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let token = self.access_token().await?;
        verbose::step(format_args!("Google Cloud DNS POST {path}"));
        let response = self
            .http
            .post(format!("{API_BASE}{path}"))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .with_context(|| format!("Google Cloud DNS POST {path} failed"))?;
        if response.status().is_success() {
            return Ok(());
        }
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ApiErrorBody>(&text)
            .ok()
            .and_then(|body| body.error.and_then(|err| err.message))
            .unwrap_or(text);
        bail!("Google Cloud DNS API error ({status}): {message}")
    }

    async fn access_token(&self) -> Result<String> {
        let mut guard = self.token.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.expires_at.saturating_duration_since(Instant::now()) > Duration::from_secs(60)
        {
            return Ok(cached.access_token.clone());
        }
        verbose::step("requesting Google OAuth access token");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_secs();
        let claims = JwtClaims {
            iss: self.client_email.clone(),
            scope: SCOPE.to_string(),
            aud: TOKEN_URL.to_string(),
            iat: now,
            exp: now + 3600,
        };
        let key = EncodingKey::from_rsa_pem(self.private_key.as_bytes())
            .context("invalid Google service-account private key")?;
        let assertion = jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
            .context("failed to sign Google JWT")?;
        let response = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .context("Google token request failed")?;
        let parsed: TokenResponse = parse_json(response).await?;
        let expires_in = if parsed.expires_in == 0 {
            3600
        } else {
            parsed.expires_in
        };
        *guard = Some(CachedToken {
            access_token: parsed.access_token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in),
        });
        Ok(parsed.access_token)
    }
}

impl From<ZoneJson> for ManagedZone {
    fn from(zone: ZoneJson) -> Self {
        Self {
            name: zone.name,
            dns_name: zone.dns_name,
            id: zone.id,
        }
    }
}

impl Rrset {
    fn to_dane(&self) -> Vec<DaneTlsa> {
        self.rrdatas
            .iter()
            .filter_map(|rdata| {
                ListedTlsa::from_rdata(self.name.clone(), rdata, None)
                    .map(|listed| listed.to_dane())
            })
            .collect()
    }

    fn to_listed(&self) -> Vec<ListedTlsa> {
        self.rrdatas
            .iter()
            .filter_map(|rdata| ListedTlsa::from_rdata(self.name.clone(), rdata, None))
            .collect()
    }

    fn from_dane(name: &str, ttl: u32, records: &[DaneTlsa]) -> Self {
        Self {
            name: name.to_string(),
            record_type: "TLSA".into(),
            ttl,
            rrdatas: records.iter().map(publish::format_tlsa_rdata).collect(),
        }
    }
}

struct Loaded {
    project: String,
    client_email: String,
    private_key: String,
    ttl: u32,
}

fn load_config() -> Result<Loaded> {
    let creds_path = env_value(&[
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GENTLSA_GOOGLE_CREDENTIALS",
    ])
    .map(PathBuf::from)
    .or_else(config_credential_path)
    .context(
        "Please configure Google Cloud DNS: set GOOGLE_APPLICATION_CREDENTIALS \
         to a service-account JSON file, or credentials= in /etc/gentlsa/google.cfg",
    )?;

    let raw = std::fs::read_to_string(&creds_path)
        .with_context(|| format!("failed to read {}", creds_path.display()))?;
    let account: ServiceAccount = serde_json::from_str(&raw).with_context(|| {
        format!(
            "{} is not a service-account JSON file",
            creds_path.display()
        )
    })?;
    if account.client_email.is_empty() || account.private_key.is_empty() {
        bail!(
            "{} is missing client_email/private_key (need a service account key)",
            creds_path.display()
        );
    }

    let project = env_value(&[
        "GENTLSA_GOOGLE_PROJECT",
        "GOOGLE_CLOUD_PROJECT",
        "GCLOUD_PROJECT",
    ])
    .or_else(config_project)
    .or_else(|| {
        if account.project_id.is_empty() {
            None
        } else {
            Some(account.project_id.clone())
        }
    })
    .context(
        "Google Cloud project is required (project= in google.cfg, \
         GENTLSA_GOOGLE_PROJECT, or project_id in the service-account JSON)",
    )?;

    Ok(Loaded {
        project,
        client_email: account.client_email,
        private_key: account.private_key,
        ttl: config_ttl().unwrap_or(DEFAULT_TTL),
    })
}

fn config_ini() -> Option<(ini::Ini, PathBuf)> {
    for path in config_paths() {
        if path.exists()
            && let Ok(conf) = ini::Ini::load_from_file(&path)
        {
            return Some((conf, path));
        }
    }
    None
}

fn google_section(conf: &ini::Ini) -> Option<&ini::Properties> {
    conf.section(Some("Google"))
        .or_else(|| conf.section(Some("google")))
        .or_else(|| conf.section(Some("GCP")))
}

fn config_credential_path() -> Option<PathBuf> {
    let (conf, _) = config_ini()?;
    let section = google_section(&conf)?;
    section
        .get("credentials")
        .or_else(|| section.get("credentials_file"))
        .or_else(|| section.get("key_file"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn config_project() -> Option<String> {
    let (conf, _) = config_ini()?;
    let section = google_section(&conf)?;
    section
        .get("project")
        .or_else(|| section.get("project_id"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn config_ttl() -> Option<u32> {
    let (conf, _) = config_ini()?;
    let section = google_section(&conf)?;
    section.get("ttl")?.trim().parse().ok()
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/gentlsa/google.cfg")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".gentlsa").join("google.cfg"));
    }
    paths
}

fn env_value(keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn trailing_dot(name: &str) -> String {
    let name = name.trim();
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

async fn parse_json<T: for<'de> Deserialize<'de>>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let text = response
        .text()
        .await
        .with_context(|| format!("Google Cloud DNS returned a non-text response ({status})"))?;
    if !status.is_success() {
        let message = serde_json::from_str::<ApiErrorBody>(&text)
            .ok()
            .and_then(|body| body.error.and_then(|err| err.message))
            .unwrap_or(text);
        bail!("Google Cloud DNS API error ({status}): {message}");
    }
    serde_json::from_str(&text).context("Google Cloud DNS returned invalid JSON")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rrset_roundtrip() {
        let dane = [publish::live_dane("AABB")];
        let set = Rrset::from_dane("_443._tcp.example.com.", 3600, &dane);
        assert_eq!(set.rrdatas, ["3 1 1 aabb"]);
        let listed = set.to_listed();
        assert_eq!(listed[0].certificate, "aabb");
        assert_eq!(listed[0].name, "_443._tcp.example.com.");
    }

    #[test]
    fn config_paths_prefer_etc() {
        assert_eq!(config_paths()[0], PathBuf::from("/etc/gentlsa/google.cfg"));
    }
}
