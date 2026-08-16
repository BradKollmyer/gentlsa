use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

use crate::tlsa;

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

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
}

#[derive(Debug, Serialize)]
struct TlsaPayload {
    name: String,
    #[serde(rename = "type")]
    record_type: &'static str,
    ttl: u32,
    data: TlsaData,
}

#[derive(Debug, Serialize)]
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
        let auth = load_auth()?;
        let auth_label = match &auth {
            Auth::Token(_) => "API token".to_string(),
            Auth::Key { email, .. } => format!("global API key ({email})"),
        };
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
        let zones: Vec<Zone> = self
            .get_result(&format!("/zones?name={name}"))
            .await
            .with_context(|| format!("failed to look up Cloudflare zone {name}"))?;
        Ok(zones.into_iter().next())
    }

    pub async fn upsert_tlsa(
        &self,
        zone: &Zone,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
        dryrun: bool,
    ) -> Result<()> {
        let owner = tlsa::owner_name(port, hostname);
        let payload = TlsaPayload {
            name: owner.clone(),
            record_type: "TLSA",
            ttl: 1,
            data: TlsaData {
                usage: tlsa::USAGE,
                selector: tlsa::SELECTOR,
                matching_type: tlsa::MATCHING,
                certificate: certificate.to_string(),
            },
        };

        if dryrun {
            println!(
                "Cloudflare: dry run, would write {owner} TLSA for {}",
                zone.name
            );
            return Ok(());
        }

        let records: Vec<DnsRecord> = self
            .get_result(&format!("/zones/{}/dns_records?type=TLSA", zone.id))
            .await
            .context("failed to list Cloudflare TLSA records")?;

        let expected_names = [
            format!("_{port}._tcp.{}", zone.name),
            match hostname {
                Some(host) if !host.is_empty() => format!("_{port}._tcp.{host}.{}", zone.name),
                _ => String::new(),
            },
        ];

        if let Some(existing) = records.iter().find(|record| {
            record.record_type == "TLSA"
                && expected_names
                    .iter()
                    .any(|name| !name.is_empty() && name.eq_ignore_ascii_case(&record.name))
        }) {
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

    pub fn print_zone_info(&self, zone: &Zone) {
        println!(">>> Cloudflare Information:");
        println!("Zone name: {}", zone.name);
        println!("Zone ID: {}", zone.id);
        println!("Zone owner: {}", zone.owner_label());
        println!("Name servers: {:?}", zone.name_servers);
    }

    async fn get_result<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
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
        let response = self
            .http
            .put(format!("{API_BASE}{path}"))
            .json(body)
            .send()
            .await
            .with_context(|| format!("Cloudflare PUT {path} failed"))?;
        parse_response(response).await
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
        return Ok(Auth::Token(token));
    }

    let email = first_env(&["CF_API_EMAIL", "CLOUDFLARE_EMAIL"]).ok();
    let key = first_env(&["CF_API_KEY", "CLOUDFLARE_API_KEY"]).ok();
    if let (Some(email), Some(key)) = (email, key) {
        return Ok(Auth::Key { email, key });
    }

    if let Some(auth) = load_config_auth()? {
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
