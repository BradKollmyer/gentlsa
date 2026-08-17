use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::output;
use crate::publish::{
    self, DaneTlsa, ListedTlsa, PruneReport, PublishAction, PublishMode, PublishReport,
};
use crate::tlsa;
use crate::verbose;

const TOKEN_HOST: &str = "https://login.microsoftonline.com";
const API_BASE: &str = "https://management.azure.com";
const SCOPE: &str = "https://management.azure.com/.default";
const ZONES_API: &str = "2018-05-01";
const TLSA_API: &str = "2023-07-01-preview";
const DEFAULT_TTL: u32 = 3600;

#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    subscription: String,
    resource_group: Option<String>,
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
    pub subscription: String,
    pub resource_group: String,
    pub name: String,
    pub id: String,
}

#[derive(Debug, Clone)]
pub struct DnsZone {
    pub id: String,
    pub name: String,
    pub resource_group: String,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct TokenErrorBody {
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>"))]
struct ListResponse<T> {
    #[serde(default)]
    value: Vec<T>,
    #[serde(default, rename = "nextLink")]
    next_link: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ZoneJson {
    #[serde(default)]
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct RecordSetJson {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: String,
    #[serde(default)]
    properties: RecordSetProperties,
}

#[derive(Debug, Default, Deserialize)]
struct RecordSetProperties {
    #[serde(default)]
    fqdn: Option<String>,
    #[serde(default, rename = "TLSARecords")]
    tlsa_records: Vec<TlsaJson>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsaJson {
    usage: u8,
    selector: u8,
    #[serde(rename = "matchingType")]
    matching_type: u8,
    #[serde(rename = "certAssociationData")]
    cert_association_data: String,
}

#[derive(Debug, Serialize)]
struct RecordSetBody {
    properties: RecordSetBodyProperties,
}

#[derive(Debug, Serialize)]
struct RecordSetBodyProperties {
    #[serde(rename = "TTL")]
    ttl: u32,
    #[serde(rename = "TLSARecords")]
    tlsa_records: Vec<TlsaJson>,
}

#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error: Option<ApiError>,
}

#[derive(Debug, Deserialize)]
struct ApiError {
    code: Option<String>,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ServicePrincipalFile {
    #[serde(default, alias = "tenant", alias = "tenantId")]
    tenant_id: String,
    #[serde(default, alias = "appId", alias = "app_id", alias = "clientId")]
    client_id: String,
    #[serde(default, alias = "password", alias = "clientSecret", alias = "secret")]
    client_secret: String,
    #[serde(default, alias = "subscriptionId")]
    subscription_id: String,
}

impl Client {
    pub fn from_env_or_config() -> Result<Self> {
        verbose::step("loading Azure DNS credentials");
        let loaded = load_config()?;
        verbose::step(format_args!(
            "Azure DNS subscription={} tenant={} client={}",
            loaded.subscription,
            prefix(&loaded.tenant_id, 8),
            prefix(&loaded.client_id, 8)
        ));
        let http = reqwest::Client::builder()
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            tenant_id: loaded.tenant_id,
            client_id: loaded.client_id,
            client_secret: loaded.client_secret,
            subscription: loaded.subscription,
            resource_group: loaded.resource_group,
            ttl: loaded.ttl,
            token: tokio::sync::Mutex::new(None),
        })
    }

    pub fn auth_label(&self) -> String {
        format!("service principal {}…", prefix(&self.client_id, 8))
    }

    pub fn subscription(&self) -> &str {
        &self.subscription
    }

    pub async fn list_zones(&self) -> Result<Vec<DnsZone>> {
        let mut zones = Vec::new();
        let mut url = Some(if let Some(rg) = &self.resource_group {
            format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones?api-version={ZONES_API}",
                self.subscription,
                urlencoding(rg)
            )
        } else {
            format!(
                "/subscriptions/{}/providers/Microsoft.Network/dnszones?api-version={ZONES_API}",
                self.subscription
            )
        });
        while let Some(path) = url {
            let parsed: ListResponse<ZoneJson> = self.get_json(&path).await?;
            zones.extend(parsed.value.into_iter().filter_map(DnsZone::from_json));
            url = parsed.next_link.filter(|link| !link.is_empty());
        }
        Ok(zones)
    }

    pub async fn zone_by_name(&self, name: &str) -> Result<Option<DnsZone>> {
        let dns = name.trim_end_matches('.');
        verbose::step(format_args!("looking up Azure DNS zone {dns}"));
        if let Some(rg) = &self.resource_group {
            let path = format!(
                "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}?api-version={ZONES_API}",
                self.subscription,
                urlencoding(rg),
                urlencoding(dns)
            );
            match self.get_json_optional::<ZoneJson>(&path).await? {
                Some(json) => {
                    let zone = DnsZone::from_json(json).or_else(|| {
                        Some(DnsZone {
                            id: String::new(),
                            name: dns.to_string(),
                            resource_group: rg.clone(),
                        })
                    });
                    if let Some(zone) = &zone {
                        verbose::step(format_args!(
                            "found zone {} ({})",
                            zone.name, zone.resource_group
                        ));
                    }
                    return Ok(zone);
                }
                None => {
                    verbose::step(format_args!(
                        "no Azure DNS zone named {name} in resource group {rg}"
                    ));
                    return Ok(None);
                }
            }
        }
        let zone = self
            .list_zones()
            .await?
            .into_iter()
            .find(|zone| publish::names_equal(&zone.name, name));
        match &zone {
            Some(zone) => verbose::step(format_args!(
                "found zone {} ({})",
                zone.name, zone.resource_group
            )),
            None => verbose::step(format_args!("no Azure DNS zone named {name}")),
        }
        Ok(zone)
    }

    pub async fn list_tlsa(
        &self,
        zone: &DnsZone,
        hostname: Option<&str>,
        ports: &[u16],
    ) -> Result<Vec<ListedTlsa>> {
        let records = self.tlsa_records(zone).await?;
        Ok(records
            .into_iter()
            .filter(|record| {
                publish::record_matches_filter(&record.name, &zone.name, hostname, ports)
            })
            .collect())
    }

    pub async fn publish_tlsa(
        &self,
        zone: &DnsZone,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
        mode: PublishMode,
        dryrun: bool,
    ) -> Result<PublishReport> {
        let owner = tlsa::owner_name(port, hostname);
        verbose::step(format_args!(
            "Azure DNS publish {owner} mode={mode:?} dryrun={dryrun}"
        ));
        let current = self.rrset_for_owner(zone, &owner).await?;
        let dane = current
            .as_ref()
            .map(RecordSetJson::to_dane)
            .unwrap_or_default();
        let action = publish::publish_action(&dane, certificate, mode, dryrun);
        let report = |action: PublishAction| PublishReport {
            zone: zone.name.trim_end_matches('.').to_string(),
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
                "Azure DNS: TLSA already published for {} ({owner})",
                zone.name.trim_end_matches('.')
            ));
            return Ok(report(action));
        }
        if mode == PublishMode::Rollover && !dane.is_empty() {
            output::text(format!(
                "Azure DNS: keeping {} existing TLSA record(s) for rollover",
                dane.len()
            ));
        }

        match action {
            PublishAction::WouldAdd => {
                output::text(format!(
                    "Azure DNS: dry run, would add {owner} TLSA for {}",
                    zone.name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::WouldReplace => {
                output::text(format!(
                    "Azure DNS: dry run, would replace TLSA {owner} on {}",
                    zone.name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::Added | PublishAction::Replaced => {
                let next = publish::rrset_after_publish(&dane, certificate, action);
                self.apply_rrset(zone, &owner, &next).await?;
                let verb = if action == PublishAction::Replaced {
                    "updated"
                } else {
                    "added"
                };
                output::text(format!(
                    "Azure DNS: TLSA record {verb} for {}",
                    zone.name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::AlreadyPublished => unreachable!("handled above"),
        }
    }

    pub async fn prune_tlsa(
        &self,
        zone: &DnsZone,
        hostname: Option<&str>,
        port: u16,
        live_hash: &str,
        dryrun: bool,
    ) -> Result<PruneReport> {
        let owner = tlsa::owner_name(port, hostname);
        let fqdn = publish::fqdn_owner(&zone.name, hostname, port);
        verbose::step(format_args!(
            "Azure DNS prune stale TLSA for {fqdn} dryrun={dryrun}"
        ));
        let current = self.rrset_for_owner(zone, &owner).await?;
        let dane = current
            .as_ref()
            .map(RecordSetJson::to_dane)
            .unwrap_or_default();
        let stale = publish::stale_dane(&dane, live_hash);
        let hashes: Vec<String> = stale
            .iter()
            .map(|record| record.certificate.clone())
            .collect();
        if stale.is_empty() {
            output::text(format!(
                "Azure DNS: no stale TLSA records for {}",
                zone.name.trim_end_matches('.')
            ));
            return Ok(PruneReport {
                zone: zone.name.trim_end_matches('.').to_string(),
                dryrun,
                stale: hashes,
            });
        }
        if dryrun {
            for hash in &hashes {
                output::text(format!(
                    "Azure DNS: dry run, would delete stale TLSA {hash}"
                ));
            }
        } else {
            let next = publish::rrset_after_prune(&dane, live_hash);
            self.apply_rrset(zone, &owner, &next).await?;
            for hash in &hashes {
                output::text(format!("Azure DNS: deleted stale TLSA {hash}"));
            }
        }
        Ok(PruneReport {
            zone: zone.name.trim_end_matches('.').to_string(),
            dryrun,
            stale: hashes,
        })
    }

    pub fn print_zone_info(&self, zone: &DnsZone) {
        output::text(">>> Azure DNS Information:");
        output::text(format!("Subscription: {}", self.subscription));
        output::text(format!("Resource group: {}", zone.resource_group));
        output::text(format!("Zone name: {}", zone.name));
        if !zone.id.is_empty() {
            output::text(format!("Resource ID: {}", zone.id));
        }
    }

    async fn tlsa_records(&self, zone: &DnsZone) -> Result<Vec<ListedTlsa>> {
        verbose::step("listing Azure DNS TLSA records");
        let mut records = Vec::new();
        let mut url = Some(format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TLSA?api-version={TLSA_API}",
            self.subscription,
            urlencoding(&zone.resource_group),
            urlencoding(zone.name.trim_end_matches('.'))
        ));
        while let Some(path) = url {
            let parsed: ListResponse<RecordSetJson> = self.get_json(&path).await?;
            records.extend(
                parsed
                    .value
                    .iter()
                    .flat_map(|set| set.to_listed(&zone.name)),
            );
            url = parsed.next_link.filter(|link| !link.is_empty());
        }
        verbose::step(format_args!(
            "Azure DNS returned {} TLSA value(s)",
            records.len()
        ));
        Ok(records)
    }

    async fn rrset_for_owner(&self, zone: &DnsZone, owner: &str) -> Result<Option<RecordSetJson>> {
        let path = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TLSA/{}?api-version={TLSA_API}",
            self.subscription,
            urlencoding(&zone.resource_group),
            urlencoding(zone.name.trim_end_matches('.')),
            urlencoding(owner)
        );
        self.get_json_optional(&path).await
    }

    async fn apply_rrset(&self, zone: &DnsZone, owner: &str, next: &[DaneTlsa]) -> Result<()> {
        let path = format!(
            "/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/TLSA/{}?api-version={TLSA_API}",
            self.subscription,
            urlencoding(&zone.resource_group),
            urlencoding(zone.name.trim_end_matches('.')),
            urlencoding(owner)
        );
        if next.is_empty() {
            verbose::step(format_args!("Azure DNS DELETE {owner}"));
            return self.delete(&path).await;
        }
        verbose::step(format_args!(
            "Azure DNS PUT {owner} ({} value(s))",
            next.len()
        ));
        let body = RecordSetBody {
            properties: RecordSetBodyProperties {
                ttl: self.ttl,
                tlsa_records: next.iter().map(TlsaJson::from_dane).collect(),
            },
        };
        self.put_json(&path, &body).await
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let response = self.send("GET", path, None).await?;
        parse_json(response).await
    }

    async fn get_json_optional<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<Option<T>> {
        let response = self.send("GET", path, None).await?;
        if response.status().as_u16() == 404 {
            return Ok(None);
        }
        parse_json(response).await.map(Some)
    }

    async fn put_json<T: Serialize>(&self, path: &str, body: &T) -> Result<()> {
        let payload = serde_json::to_vec(body).context("failed to encode Azure DNS request")?;
        let response = self.send("PUT", path, Some(payload)).await?;
        if response.status().is_success() {
            return Ok(());
        }
        Err(api_error(response).await)
    }

    async fn delete(&self, path: &str) -> Result<()> {
        let response = self.send("DELETE", path, None).await?;
        if response.status().is_success() || response.status().as_u16() == 404 {
            return Ok(());
        }
        Err(api_error(response).await)
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response> {
        let token = self.access_token().await?;
        let url = if path.starts_with("https://") {
            path.to_string()
        } else {
            format!("{API_BASE}{path}")
        };
        verbose::step(format_args!("Azure DNS {method} {path}"));
        let mut builder = match method {
            "GET" => self.http.get(&url),
            "PUT" => self.http.put(&url),
            "DELETE" => self.http.delete(&url),
            other => bail!("unsupported HTTP method {other}"),
        };
        builder = builder.bearer_auth(token);
        if let Some(body) = body {
            builder = builder
                .header("content-type", "application/json")
                .body(body);
        }
        builder
            .send()
            .await
            .with_context(|| format!("Azure DNS {method} {path} failed"))
    }

    async fn access_token(&self) -> Result<String> {
        let mut guard = self.token.lock().await;
        if let Some(cached) = guard.as_ref()
            && cached.expires_at.saturating_duration_since(Instant::now()) > Duration::from_secs(60)
        {
            return Ok(cached.access_token.clone());
        }
        verbose::step("requesting Azure AD access token");
        let url = format!("{TOKEN_HOST}/{}/oauth2/v2.0/token", self.tenant_id);
        let response = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("scope", SCOPE),
            ])
            .send()
            .await
            .context("Azure token request failed")?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Azure token endpoint returned a non-text response")?;
        if !status.is_success() {
            let parsed = serde_json::from_str::<TokenErrorBody>(&text).ok();
            let message = parsed
                .as_ref()
                .and_then(|body| body.error_description.clone())
                .or_else(|| parsed.and_then(|body| body.error))
                .unwrap_or(text);
            bail!("Azure AD token error ({status}): {message}");
        }
        let parsed: TokenResponse =
            serde_json::from_str(&text).context("Azure AD returned invalid token JSON")?;
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

impl DnsZone {
    fn from_json(zone: ZoneJson) -> Option<Self> {
        let resource_group = resource_group_from_id(&zone.id)?;
        Some(Self {
            id: zone.id,
            name: zone.name,
            resource_group,
        })
    }
}

impl RecordSetJson {
    fn to_dane(&self) -> Vec<DaneTlsa> {
        self.properties
            .tlsa_records
            .iter()
            .map(TlsaJson::to_dane)
            .collect()
    }

    fn to_listed(&self, zone: &str) -> Vec<ListedTlsa> {
        let name = self
            .properties
            .fqdn
            .clone()
            .filter(|fqdn| !fqdn.is_empty())
            .unwrap_or_else(|| fqdn_from_relative(&self.name, zone));
        self.properties
            .tlsa_records
            .iter()
            .map(|record| ListedTlsa {
                id: self.id.clone(),
                name: name.clone(),
                usage: record.usage,
                selector: record.selector,
                matching: record.matching_type,
                certificate: record.cert_association_data.to_ascii_lowercase(),
            })
            .collect()
    }
}

impl TlsaJson {
    fn to_dane(&self) -> DaneTlsa {
        DaneTlsa {
            usage: self.usage,
            selector: self.selector,
            matching: self.matching_type,
            certificate: self.cert_association_data.to_ascii_lowercase(),
        }
    }

    fn from_dane(record: &DaneTlsa) -> Self {
        Self {
            usage: record.usage,
            selector: record.selector,
            matching_type: record.matching,
            cert_association_data: record.certificate.clone(),
        }
    }
}

struct Loaded {
    tenant_id: String,
    client_id: String,
    client_secret: String,
    subscription: String,
    resource_group: Option<String>,
    ttl: u32,
}

fn load_config() -> Result<Loaded> {
    let file = load_credential_file()?;
    let tenant_id = env_value(&["AZURE_TENANT_ID", "GENTLSA_AZURE_TENANT_ID"])
        .or_else(|| file.as_ref().and_then(|file| file.tenant_id.clone()))
        .context(
            "Please configure Azure DNS: set AZURE_TENANT_ID, or tenant_id= in /etc/gentlsa/azure.cfg",
        )?;
    let client_id = env_value(&["AZURE_CLIENT_ID", "GENTLSA_AZURE_CLIENT_ID"])
        .or_else(|| file.as_ref().and_then(|file| file.client_id.clone()))
        .context(
            "Please configure Azure DNS: set AZURE_CLIENT_ID, or client_id= in /etc/gentlsa/azure.cfg",
        )?;
    let client_secret = env_value(&["AZURE_CLIENT_SECRET", "GENTLSA_AZURE_CLIENT_SECRET"])
        .or_else(|| file.as_ref().and_then(|file| file.client_secret.clone()))
        .context(
            "Please configure Azure DNS: set AZURE_CLIENT_SECRET, or client_secret= in /etc/gentlsa/azure.cfg",
        )?;
    let subscription = env_value(&["AZURE_SUBSCRIPTION_ID", "GENTLSA_AZURE_SUBSCRIPTION_ID"])
        .or_else(|| file.as_ref().and_then(|file| file.subscription.clone()))
        .context(
            "Please configure Azure DNS: set AZURE_SUBSCRIPTION_ID, or subscription_id= in /etc/gentlsa/azure.cfg",
        )?;
    let resource_group = env_value(&["AZURE_RESOURCE_GROUP", "GENTLSA_AZURE_RESOURCE_GROUP"])
        .or_else(|| file.as_ref().and_then(|file| file.resource_group.clone()));
    Ok(Loaded {
        tenant_id,
        client_id,
        client_secret,
        subscription,
        resource_group,
        ttl: file
            .as_ref()
            .and_then(|file| file.ttl)
            .unwrap_or(DEFAULT_TTL),
    })
}

struct FileCreds {
    tenant_id: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    subscription: Option<String>,
    resource_group: Option<String>,
    ttl: Option<u32>,
}

fn load_credential_file() -> Result<Option<FileCreds>> {
    if let Some(path) = env_value(&["GENTLSA_AZURE_CREDENTIALS", "AZURE_CREDENTIALS"])
        .map(PathBuf::from)
        .or_else(config_credential_path)
        && path.exists()
    {
        return Ok(Some(creds_from_json(&path)?));
    }
    load_ini_credentials()
}

fn creds_from_json(path: &PathBuf) -> Result<FileCreds> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let parsed: ServicePrincipalFile = serde_json::from_str(&raw).with_context(|| {
        format!(
            "{} is not an Azure service-principal JSON file",
            path.display()
        )
    })?;
    if parsed.tenant_id.is_empty() || parsed.client_id.is_empty() || parsed.client_secret.is_empty()
    {
        bail!(
            "{} is missing tenant/client/secret (need an Azure service principal key)",
            path.display()
        );
    }
    Ok(FileCreds {
        tenant_id: nonempty(parsed.tenant_id),
        client_id: nonempty(parsed.client_id),
        client_secret: nonempty(parsed.client_secret),
        subscription: nonempty(parsed.subscription_id),
        resource_group: None,
        ttl: config_ttl(),
    })
}

fn load_ini_credentials() -> Result<Option<FileCreds>> {
    let Some((conf, _)) = config_ini() else {
        return Ok(None);
    };
    let Some(section) = azure_section(&conf) else {
        return Ok(None);
    };
    Ok(Some(FileCreds {
        tenant_id: section_get(section, &["tenant_id", "tenant", "tenant-id"]),
        client_id: section_get(
            section,
            &["client_id", "client-id", "app_id", "application_id"],
        ),
        client_secret: section_get(
            section,
            &["client_secret", "client-secret", "secret", "password"],
        ),
        subscription: section_get(
            section,
            &["subscription_id", "subscription-id", "subscription"],
        ),
        resource_group: section_get(
            section,
            &["resource_group", "resource-group", "resourceGroup"],
        ),
        ttl: section
            .get("ttl")
            .and_then(|value| value.trim().parse().ok()),
    }))
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

fn azure_section(conf: &ini::Ini) -> Option<&ini::Properties> {
    conf.section(Some("Azure"))
        .or_else(|| conf.section(Some("azure")))
        .or_else(|| conf.section(Some("AzureDNS")))
}

fn config_credential_path() -> Option<PathBuf> {
    let (conf, _) = config_ini()?;
    let section = azure_section(&conf)?;
    section
        .get("credentials")
        .or_else(|| section.get("credentials_file"))
        .or_else(|| section.get("key_file"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn config_ttl() -> Option<u32> {
    let (conf, _) = config_ini()?;
    let section = azure_section(&conf)?;
    section.get("ttl")?.trim().parse().ok()
}

fn section_get(section: &ini::Properties, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| section.get(key))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/gentlsa/azure.cfg")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".gentlsa").join("azure.cfg"));
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

fn nonempty(value: String) -> Option<String> {
    let value = value.trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

fn prefix(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

fn resource_group_from_id(id: &str) -> Option<String> {
    let mut parts = id.split('/');
    while let Some(part) = parts.next() {
        if part.eq_ignore_ascii_case("resourceGroups") {
            return parts
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
        }
    }
    None
}

fn fqdn_from_relative(relative: &str, zone: &str) -> String {
    let relative = relative.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if relative.is_empty() || relative == "@" {
        format!("{zone}.")
    } else {
        format!("{relative}.{zone}.")
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
        .with_context(|| format!("Azure DNS returned a non-text response ({status})"))?;
    if !status.is_success() {
        return Err(decode_error(status, &text));
    }
    serde_json::from_str(&text).context("Azure DNS returned invalid JSON")
}

async fn api_error(response: reqwest::Response) -> anyhow::Error {
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    decode_error(status, &text)
}

fn decode_error(status: reqwest::StatusCode, text: &str) -> anyhow::Error {
    let message = serde_json::from_str::<ApiErrorBody>(text)
        .ok()
        .and_then(|body| body.error)
        .and_then(|err| match (err.code, err.message) {
            (Some(code), Some(message)) => Some(format!("{code}: {message}")),
            (None, Some(message)) => Some(message),
            (Some(code), None) => Some(code),
            (None, None) => None,
        })
        .unwrap_or_else(|| text.to_string());
    anyhow::anyhow!("Azure DNS API error ({status}): {message}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_resource_group_from_id() {
        assert_eq!(
            resource_group_from_id(
                "/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Network/dnszones/example.com"
            )
            .as_deref(),
            Some("rg1")
        );
        assert_eq!(
            resource_group_from_id(
                "/subscriptions/sub/resourcegroups/DnsRg/providers/Microsoft.Network/dnsZones/example.com"
            )
            .as_deref(),
            Some("DnsRg")
        );
        assert!(
            resource_group_from_id(
                "/subscriptions/sub/providers/Microsoft.Network/dnszones/example.com"
            )
            .is_none()
        );
    }

    #[test]
    fn tlsa_roundtrip() {
        let dane = publish::live_dane("AABB");
        let json = TlsaJson::from_dane(&dane);
        assert_eq!(json.usage, 3);
        assert_eq!(json.selector, 1);
        assert_eq!(json.matching_type, 1);
        assert_eq!(json.cert_association_data, "aabb");
        let back = json.to_dane();
        assert_eq!(back.certificate, "aabb");
    }

    #[test]
    fn listed_from_record_set() {
        let set = RecordSetJson {
            id: Some("rec-1".into()),
            name: "_443._tcp".into(),
            properties: RecordSetProperties {
                fqdn: Some("_443._tcp.example.com.".into()),
                tlsa_records: vec![TlsaJson {
                    usage: 3,
                    selector: 1,
                    matching_type: 1,
                    cert_association_data: "AABB".into(),
                }],
            },
        };
        let listed = set.to_listed("example.com");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "_443._tcp.example.com.");
        assert_eq!(listed[0].certificate, "aabb");
        assert_eq!(listed[0].id.as_deref(), Some("rec-1"));
    }

    #[test]
    fn fqdn_from_relative_name() {
        assert_eq!(
            fqdn_from_relative("_443._tcp", "example.com"),
            "_443._tcp.example.com."
        );
        assert_eq!(fqdn_from_relative("@", "example.com."), "example.com.");
    }

    #[test]
    fn config_paths_prefer_etc() {
        assert_eq!(config_paths()[0], PathBuf::from("/etc/gentlsa/azure.cfg"));
    }

    #[test]
    fn service_principal_json_aliases() {
        let parsed: ServicePrincipalFile = serde_json::from_str(
            r#"{
                "tenantId": "tid",
                "appId": "cid",
                "password": "secret",
                "subscriptionId": "sub"
            }"#,
        )
        .unwrap();
        assert_eq!(parsed.tenant_id, "tid");
        assert_eq!(parsed.client_id, "cid");
        assert_eq!(parsed.client_secret, "secret");
        assert_eq!(parsed.subscription_id, "sub");
    }
}
