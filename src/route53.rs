use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use reqwest::header::{HeaderMap, HeaderValue};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::output;
use crate::publish::{
    self, DaneTlsa, ListedTlsa, PruneReport, PublishAction, PublishMode, PublishReport,
};
use crate::tlsa;
use crate::verbose;

const API_HOST: &str = "route53.amazonaws.com";
const SERVICE: &str = "route53";
const REGION: &str = "us-east-1";
const DEFAULT_TTL: u32 = 3600;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
struct Credentials {
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    creds: Credentials,
    ttl: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ZoneInfo {
    pub id: String,
    pub name: String,
    pub private: bool,
}

#[derive(Debug, Clone)]
pub struct HostedZone {
    pub id: String,
    pub name: String,
    pub private: bool,
}

impl Client {
    pub fn from_env_or_config() -> Result<Self> {
        verbose::step("loading Route 53 credentials");
        let (creds, source) = load_credentials()?;
        match source {
            Some(path) => {
                verbose::step(format_args!("Route 53 credentials from {}", path.display()))
            }
            None => verbose::step("Route 53 credentials from AWS environment"),
        }
        let http = reqwest::Client::builder()
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            creds,
            ttl: config_ttl().unwrap_or(DEFAULT_TTL),
        })
    }

    pub fn auth_label(&self) -> String {
        format!("access key {}…", prefix(&self.creds.access_key, 4))
    }

    pub async fn list_zones(&self) -> Result<Vec<HostedZone>> {
        let mut zones = Vec::new();
        let mut marker: Option<String> = None;
        loop {
            let mut path = "/2013-04-01/hostedzone?maxitems=100".to_string();
            if let Some(marker) = &marker {
                path.push_str("&marker=");
                path.push_str(&aws_encode(marker));
            }
            let xml = self.request("GET", &path, b"").await?;
            zones.extend(parse_hosted_zones(&xml));
            if xml_text(&xml, "IsTruncated").as_deref() != Some("true") {
                break;
            }
            marker = xml_text(&xml, "NextMarker");
            if marker.is_none() {
                break;
            }
        }
        Ok(zones)
    }

    pub async fn zone_by_name(&self, name: &str) -> Result<Option<HostedZone>> {
        let dns = trailing_dot(name);
        verbose::step(format_args!("looking up Route 53 zone {dns}"));
        let path = format!(
            "/2013-04-01/hostedzonesbyname?dnsname={}&maxitems=5",
            aws_encode(&dns)
        );
        let xml = self.request("GET", &path, b"").await?;
        let zone = parse_hosted_zones(&xml)
            .into_iter()
            .find(|zone| publish::names_equal(&zone.name, name));
        match &zone {
            Some(zone) => verbose::step(format_args!("found zone {} ({})", zone.name, zone.id)),
            None => verbose::step(format_args!("no Route 53 zone named {name}")),
        }
        Ok(zone)
    }

    pub async fn list_tlsa(
        &self,
        zone: &HostedZone,
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
        zone: &HostedZone,
        hostname: Option<&str>,
        port: u16,
        certificate: &str,
        mode: PublishMode,
        dryrun: bool,
    ) -> Result<PublishReport> {
        let owner = tlsa::owner_name(port, hostname);
        let fqdn = publish::fqdn_owner(&zone.name, hostname, port);
        verbose::step(format_args!(
            "Route 53 publish {owner} mode={mode:?} dryrun={dryrun}"
        ));
        let ours = self.records_for_owner(zone, &fqdn).await?;
        let dane: Vec<DaneTlsa> = ours.iter().map(ListedTlsa::to_dane).collect();
        let action = publish::publish_action(&dane, certificate, mode, dryrun);
        let report = |action: PublishAction| PublishReport {
            zone: zone.name.trim_end_matches('.').to_string(),
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
                "Route 53: TLSA already published for {} ({owner})",
                zone.name.trim_end_matches('.')
            ));
            return Ok(report(action));
        }
        if mode == PublishMode::Rollover && !ours.is_empty() {
            output::text(format!(
                "Route 53: keeping {} existing TLSA record(s) for rollover",
                ours.len()
            ));
        }

        match action {
            PublishAction::WouldAdd => {
                output::text(format!(
                    "Route 53: dry run, would add {owner} TLSA for {}",
                    zone.name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::WouldReplace => {
                output::text(format!(
                    "Route 53: dry run, would replace TLSA {owner} on {}",
                    zone.name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::Added | PublishAction::Replaced => {
                let next = publish::rrset_after_publish(&dane, certificate, action);
                self.upsert_rrset(zone, &fqdn, &next).await?;
                let verb = if action == PublishAction::Replaced {
                    "updated"
                } else {
                    "added"
                };
                output::text(format!(
                    "Route 53: TLSA record {verb} for {}",
                    zone.name.trim_end_matches('.')
                ));
                Ok(report(action))
            }
            PublishAction::AlreadyPublished => unreachable!("handled above"),
        }
    }

    pub async fn prune_tlsa(
        &self,
        zone: &HostedZone,
        hostname: Option<&str>,
        port: u16,
        live_hash: &str,
        dryrun: bool,
    ) -> Result<PruneReport> {
        let fqdn = publish::fqdn_owner(&zone.name, hostname, port);
        verbose::step(format_args!(
            "Route 53 prune stale TLSA for {fqdn} dryrun={dryrun}"
        ));
        let ours = self.records_for_owner(zone, &fqdn).await?;
        let dane: Vec<DaneTlsa> = ours.iter().map(ListedTlsa::to_dane).collect();
        let stale = publish::stale_dane(&dane, live_hash);
        let hashes: Vec<String> = stale
            .iter()
            .map(|record| record.certificate.clone())
            .collect();
        if stale.is_empty() {
            output::text(format!(
                "Route 53: no stale TLSA records for {}",
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
                output::text(format!("Route 53: dry run, would delete stale TLSA {hash}"));
            }
        } else {
            let next = publish::rrset_after_prune(&dane, live_hash);
            if next.is_empty() {
                self.delete_rrset(zone, &fqdn, &dane).await?;
            } else {
                self.upsert_rrset(zone, &fqdn, &next).await?;
            }
            for hash in &hashes {
                output::text(format!("Route 53: deleted stale TLSA {hash}"));
            }
        }
        Ok(PruneReport {
            zone: zone.name.trim_end_matches('.').to_string(),
            dryrun,
            stale: hashes,
        })
    }

    pub fn print_zone_info(&self, zone: &HostedZone) {
        output::text(">>> Route 53 Information:");
        output::text(format!("Zone name: {}", zone.name));
        output::text(format!("Hosted zone ID: {}", zone.id));
        output::text(format!(
            "Private: {}",
            if zone.private { "yes" } else { "no" }
        ));
    }

    async fn records_for_owner(&self, zone: &HostedZone, fqdn: &str) -> Result<Vec<ListedTlsa>> {
        let records = self.tlsa_records(zone).await?;
        Ok(records
            .into_iter()
            .filter(|record| publish::names_equal(&record.name, fqdn))
            .collect())
    }

    async fn tlsa_records(&self, zone: &HostedZone) -> Result<Vec<ListedTlsa>> {
        verbose::step("listing Route 53 TLSA records");
        let mut records = Vec::new();
        let mut name: Option<String> = None;
        let mut rtype: Option<String> = None;
        let mut identifier: Option<String> = None;
        loop {
            let mut path = format!("/2013-04-01/hostedzone/{}/rrset?maxitems=100", zone.id);
            if let Some(name) = &name {
                path.push_str("&name=");
                path.push_str(&aws_encode(name));
            }
            if let Some(rtype) = &rtype {
                path.push_str("&type=");
                path.push_str(&aws_encode(rtype));
            }
            if let Some(identifier) = &identifier {
                path.push_str("&identifier=");
                path.push_str(&aws_encode(identifier));
            }
            let xml = self.request("GET", &path, b"").await?;
            records.extend(
                parse_rrsets(&xml)
                    .into_iter()
                    .filter(|set| set.record_type.eq_ignore_ascii_case("TLSA"))
                    .flat_map(|set| set.into_listed()),
            );
            if xml_text(&xml, "IsTruncated").as_deref() != Some("true") {
                break;
            }
            name = xml_text(&xml, "NextRecordName");
            rtype = xml_text(&xml, "NextRecordType");
            identifier = xml_text(&xml, "NextRecordIdentifier");
            if name.is_none() {
                break;
            }
        }
        verbose::step(format_args!(
            "Route 53 returned {} TLSA value(s)",
            records.len()
        ));
        Ok(records)
    }

    async fn upsert_rrset(
        &self,
        zone: &HostedZone,
        name: &str,
        records: &[DaneTlsa],
    ) -> Result<()> {
        let body = change_batch("UPSERT", name, records, self.ttl);
        verbose::step(format_args!(
            "Route 53 UPSERT {name} ({} value(s))",
            records.len()
        ));
        self.request(
            "POST",
            &format!("/2013-04-01/hostedzone/{}/rrset", zone.id),
            body.as_bytes(),
        )
        .await?;
        Ok(())
    }

    async fn delete_rrset(
        &self,
        zone: &HostedZone,
        name: &str,
        records: &[DaneTlsa],
    ) -> Result<()> {
        let body = change_batch("DELETE", name, records, self.ttl);
        verbose::step(format_args!("Route 53 DELETE {name}"));
        self.request(
            "POST",
            &format!("/2013-04-01/hostedzone/{}/rrset", zone.id),
            body.as_bytes(),
        )
        .await?;
        Ok(())
    }

    async fn request(&self, method: &str, path_and_query: &str, body: &[u8]) -> Result<String> {
        let url = format!("https://{API_HOST}{path_and_query}");
        verbose::step(format_args!("Route 53 {method} {path_and_query}"));
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static(API_HOST));
        if method == "POST" {
            headers.insert("content-type", HeaderValue::from_static("application/xml"));
        }
        sign_v4(
            method,
            &url,
            &mut headers,
            body,
            &self.creds.access_key,
            &self.creds.secret_key,
            self.creds.session_token.as_deref(),
        )?;
        let mut builder = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url).body(body.to_vec()),
            other => bail!("unsupported HTTP method {other}"),
        };
        builder = builder.headers(headers);
        let response = builder
            .send()
            .await
            .with_context(|| format!("Route 53 {method} {path_and_query} failed"))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Route 53 returned a non-text response")?;
        if !status.is_success() {
            let message = xml_text(&text, "Message")
                .or_else(|| xml_text(&text, "Code"))
                .unwrap_or(text);
            bail!("Route 53 API error ({status}): {message}");
        }
        Ok(text)
    }
}

struct ParsedRrset {
    name: String,
    record_type: String,
    values: Vec<String>,
}

impl ParsedRrset {
    fn into_listed(self) -> Vec<ListedTlsa> {
        self.values
            .into_iter()
            .filter_map(|value| ListedTlsa::from_rdata(self.name.clone(), &value, None))
            .collect()
    }
}

fn change_batch(action: &str, name: &str, records: &[DaneTlsa], ttl: u32) -> String {
    let mut values = String::new();
    for record in records {
        values.push_str(&format!(
            "<ResourceRecord><Value>{}</Value></ResourceRecord>",
            xml_escape(&publish::format_tlsa_rdata(record))
        ));
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>
      <Change>
        <Action>{action}</Action>
        <ResourceRecordSet>
          <Name>{}</Name>
          <Type>TLSA</Type>
          <TTL>{ttl}</TTL>
          <ResourceRecords>{values}</ResourceRecords>
        </ResourceRecordSet>
      </Change>
    </Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>"#,
        xml_escape(name)
    )
}

fn parse_hosted_zones(xml: &str) -> Vec<HostedZone> {
    xml_blocks(xml, "HostedZone")
        .into_iter()
        .filter_map(|block| {
            let id = xml_text(&block, "Id")?;
            let name = xml_text(&block, "Name")?;
            Some(HostedZone {
                id: id.trim_start_matches("/hostedzone/").to_string(),
                name,
                private: xml_text(&block, "PrivateZone").as_deref() == Some("true"),
            })
        })
        .collect()
}

fn parse_rrsets(xml: &str) -> Vec<ParsedRrset> {
    xml_blocks(xml, "ResourceRecordSet")
        .into_iter()
        .filter_map(|block| {
            Some(ParsedRrset {
                name: xml_text(&block, "Name")?,
                record_type: xml_text(&block, "Type")?,
                values: xml_texts(&block, "Value"),
            })
        })
        .collect()
}

fn xml_blocks(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        blocks.push(after[..end].to_string());
        rest = &after[end + close.len()..];
    }
    blocks
}

fn xml_text(xml: &str, tag: &str) -> Option<String> {
    xml_texts(xml, tag).into_iter().next()
}

fn xml_texts(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let mut values = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let after = &rest[start + open.len()..];
        let Some(end) = after.find(&close) else {
            break;
        };
        values.push(after[..end].trim().to_string());
        rest = &after[end + close.len()..];
    }
    values
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn trailing_dot(name: &str) -> String {
    let name = name.trim();
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

fn prefix(value: &str, n: usize) -> String {
    value.chars().take(n).collect()
}

fn load_credentials() -> Result<(Credentials, Option<PathBuf>)> {
    let mut access = env_value(&["AWS_ACCESS_KEY_ID", "GENTLSA_AWS_ACCESS_KEY_ID"]);
    let mut secret = env_value(&["AWS_SECRET_ACCESS_KEY", "GENTLSA_AWS_SECRET_ACCESS_KEY"]);
    let mut token = env_value(&["AWS_SESSION_TOKEN", "GENTLSA_AWS_SESSION_TOKEN"]);
    let mut source = None;
    if (access.is_none() || secret.is_none())
        && let Some((from_file, path)) = load_config_credentials()?
    {
        access = access.or(from_file.access_key);
        secret = secret.or(from_file.secret_key);
        token = token.or(from_file.session_token);
        source = Some(path);
    }
    let access_key = access.context(
        "Please configure Route 53 credentials in /etc/gentlsa/route53.cfg \
         or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY",
    )?;
    let secret_key = secret.context(
        "Please configure Route 53 credentials in /etc/gentlsa/route53.cfg \
         or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY",
    )?;
    Ok((
        Credentials {
            access_key,
            secret_key,
            session_token: token,
        },
        source,
    ))
}

struct FileCreds {
    access_key: Option<String>,
    secret_key: Option<String>,
    session_token: Option<String>,
}

fn load_config_credentials() -> Result<Option<(FileCreds, PathBuf)>> {
    for path in config_paths() {
        if !path.exists() {
            continue;
        }
        let conf = ini::Ini::load_from_file(&path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let section = conf
            .section(Some("Route53"))
            .or_else(|| conf.section(Some("route53")))
            .or_else(|| conf.section(Some("AWS")));
        let Some(section) = section else {
            continue;
        };
        return Ok(Some((
            FileCreds {
                access_key: section_get(
                    section,
                    &["access_key", "access-key", "aws_access_key_id"],
                ),
                secret_key: section_get(
                    section,
                    &["secret_key", "secret-key", "aws_secret_access_key"],
                ),
                session_token: section_get(
                    section,
                    &["session_token", "aws_session_token", "token"],
                ),
            },
            path,
        )));
    }
    Ok(None)
}

fn section_get(section: &ini::Properties, keys: &[&str]) -> Option<String> {
    keys.iter()
        .find_map(|key| section.get(key))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn config_ttl() -> Option<u32> {
    for path in config_paths() {
        if !path.exists() {
            continue;
        }
        let Ok(conf) = ini::Ini::load_from_file(&path) else {
            continue;
        };
        let section = conf
            .section(Some("Route53"))
            .or_else(|| conf.section(Some("route53")))
            .or_else(|| conf.section(Some("AWS")))?;
        return section.get("ttl")?.trim().parse().ok();
    }
    None
}

fn config_paths() -> Vec<PathBuf> {
    let mut paths = vec![PathBuf::from("/etc/gentlsa/route53.cfg")];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".gentlsa").join("route53.cfg"));
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

fn sign_v4(
    method: &str,
    url: &str,
    headers: &mut HeaderMap,
    body: &[u8],
    access_key: &str,
    secret_key: &str,
    session_token: Option<&str>,
) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid Route 53 URL")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?;
    let (amz_date, datestamp) = amz_timestamps(now.as_secs())?;
    headers.insert(
        "x-amz-date",
        HeaderValue::from_str(&amz_date).context("invalid x-amz-date")?,
    );
    if let Some(token) = session_token {
        headers.insert(
            "x-amz-security-token",
            HeaderValue::from_str(token).context("invalid session token")?,
        );
    }

    let mut header_pairs: Vec<(String, String)> = headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                value.to_str().unwrap_or("").trim().to_string(),
            )
        })
        .collect();
    header_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let signed_headers = header_pairs
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_headers = header_pairs
        .iter()
        .map(|(name, value)| format!("{name}:{value}\n"))
        .collect::<String>();

    let canonical_query = {
        let mut pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        pairs
            .iter()
            .map(|(k, v)| format!("{}={}", aws_encode(k), aws_encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    };

    let payload_hash = hex::encode(Sha256::digest(body));
    let canonical_request = format!(
        "{method}\n{}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        parsed.path()
    );
    let scope = format!("{datestamp}/{REGION}/{SERVICE}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );
    let signing_key = signing_key(secret_key, &datestamp);
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    );
    headers.insert(
        "authorization",
        HeaderValue::from_str(&authorization).context("invalid Authorization header")?,
    );
    Ok(())
}

fn signing_key(secret: &str, datestamp: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = hmac_sha256(&k_date, REGION.as_bytes());
    let k_service = hmac_sha256(&k_region, SERVICE.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn amz_timestamps(unix_secs: u64) -> Result<(String, String)> {
    const DAYS_PER_400Y: i64 = 365 * 400 + 97;
    let days = (unix_secs / 86400) as i64;
    let tod = unix_secs % 86400;
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let sec = tod % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - DAYS_PER_400Y + 1 } / DAYS_PER_400Y;
    let doe = (z - era * DAYS_PER_400Y) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    Ok((
        format!("{year:04}{month:02}{day:02}T{hour:02}{min:02}{sec:02}Z"),
        format!("{year:04}{month:02}{day:02}"),
    ))
}

fn aws_encode(s: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_zone_and_rrset_xml() {
        let zones = parse_hosted_zones(
            r#"<ListHostedZonesByNameResponse>
                 <HostedZones>
                   <HostedZone>
                     <Id>/hostedzone/Z123</Id>
                     <Name>example.com.</Name>
                     <Config><PrivateZone>false</PrivateZone></Config>
                   </HostedZone>
                 </HostedZones>
               </ListHostedZonesByNameResponse>"#,
        );
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].id, "Z123");
        assert!(!zones[0].private);

        let sets = parse_rrsets(
            r#"<ResourceRecordSets>
                 <ResourceRecordSet>
                   <Name>_443._tcp.example.com.</Name>
                   <Type>TLSA</Type>
                   <ResourceRecords>
                     <ResourceRecord><Value>3 1 1 AABB</Value></ResourceRecord>
                     <ResourceRecord><Value>2 1 1 CCCC</Value></ResourceRecord>
                   </ResourceRecords>
                 </ResourceRecordSet>
               </ResourceRecordSets>"#,
        );
        let listed: Vec<_> = sets
            .into_iter()
            .flat_map(ParsedRrset::into_listed)
            .collect();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].certificate, "aabb");
        assert_eq!(listed[1].usage, 2);
    }

    #[test]
    fn amz_date_known_epoch() {
        // 2015-08-30 12:36:00 UTC used in the AWS SigV4 docs.
        let (amz, date) = amz_timestamps(1_440_938_160).unwrap();
        assert_eq!(amz, "20150830T123600Z");
        assert_eq!(date, "20150830");
    }

    #[test]
    fn config_paths_prefer_etc() {
        assert_eq!(config_paths()[0], PathBuf::from("/etc/gentlsa/route53.cfg"));
    }
}
