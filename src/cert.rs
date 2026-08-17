use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use sha2::{Digest, Sha256, Sha512};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::dns::TlsaRecord;
use crate::tlsa::{self, StarttlsProto, TlsaParams, owner_name};
use crate::verbose;

use serde::Serialize;

const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize)]
pub struct CertDetails {
    pub serial: String,
    pub issuer: String,
    pub subject: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub san: Option<String>,
    pub not_before: String,
    pub not_after: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertLifetime {
    /// Whole days until `notAfter`. Negative if the certificate has already expired.
    pub days_left: i64,
    pub not_yet_valid: bool,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
    /// Issuer certificates presented alongside the leaf, in chain order.
    /// Empty for certificates loaded from a file.
    chain_der: Vec<Vec<u8>>,
    not_before_ts: i64,
    not_after_ts: i64,
}

impl Certificate {
    pub fn from_der(der: Vec<u8>) -> Result<Self> {
        Self::from_der_chain(der, Vec::new())
    }

    pub fn from_der_chain(der: Vec<u8>, chain_der: Vec<Vec<u8>>) -> Result<Self> {
        let (not_before_ts, not_after_ts) = {
            let (_, cert) =
                X509Certificate::from_der(&der).context("failed to parse certificate")?;
            let validity = cert.validity();
            (
                validity.not_before.timestamp(),
                validity.not_after.timestamp(),
            )
        };
        Ok(Self {
            der,
            chain_der,
            not_before_ts,
            not_after_ts,
        })
    }

    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self> {
        if looks_like_pem(bytes) {
            verbose::step("parsing PEM certificate");
            let pem = pem::parse(bytes).context("failed to parse PEM certificate")?;
            return Self::from_der(pem.contents().to_vec());
        }
        verbose::step("parsing DER certificate");
        Self::from_der(bytes.to_vec())
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        verbose::step(format_args!("reading certificate {}", path.display()));
        let bytes = std::fs::read(path)
            .with_context(|| format!("failed to read certificate {}", path.display()))?;
        Self::from_pem_or_der(&bytes)
    }

    pub fn parsed(&self) -> Result<X509Certificate<'_>> {
        let (_, cert) =
            X509Certificate::from_der(&self.der).context("failed to parse certificate")?;
        Ok(cert)
    }

    /// TLSA selector 1: SHA-256 of the SubjectPublicKeyInfo.
    pub fn spki_sha256_hex(&self) -> Result<String> {
        let cert = self.parsed()?;
        Ok(hex::encode(Sha256::digest(cert.public_key().raw)))
    }

    /// Certificate association data for a TLSA record with the given parameters.
    /// Usage 0/2 (trust anchor) hashes the first presented issuer certificate,
    /// falling back to this certificate itself when no chain was presented
    /// (a file-loaded CA cert, or a self-signed leaf that is its own anchor).
    pub fn tlsa_record_data(&self, params: TlsaParams) -> Result<String> {
        let der = if params.is_trust_anchor() {
            self.chain_der.first().unwrap_or(&self.der)
        } else {
            &self.der
        };
        tlsa_association_data(der, params.selector, params.matching)
    }

    /// Whether a DNS TLSA record matches this certificate or its presented chain.
    /// Usage 1/3 compares against the leaf; usage 0/2 against every presented
    /// certificate (hash presence only — no PKIX or DANE-TA chain validation).
    /// `None` when the record's parameters cannot be computed.
    pub fn matches_tlsa(&self, record: &TlsaRecord) -> Option<bool> {
        let candidates: Vec<&Vec<u8>> = match record.usage {
            1 | 3 => vec![&self.der],
            0 | 2 => std::iter::once(&self.der).chain(&self.chain_der).collect(),
            _ => return None,
        };
        let mut matched = false;
        for der in candidates {
            match tlsa_association_data(der, record.selector, record.matching) {
                Ok(data) => matched |= tlsa::hashes_equal(&data, &record.certificate),
                Err(_) => return None,
            }
        }
        Some(matched)
    }

    pub fn details(&self) -> Result<CertDetails> {
        let cert = self.parsed()?;
        Ok(CertDetails {
            serial: serial_hex(&cert),
            issuer: cert.issuer().to_string(),
            subject: cert.subject().to_string(),
            san: format_san(&cert),
            not_before: format_asn1_time(&cert.validity().not_before),
            not_after: format_asn1_time(&cert.validity().not_after),
        })
    }

    pub fn lifetime(&self) -> CertLifetime {
        self.lifetime_at(ASN1Time::now().timestamp())
    }

    fn lifetime_at(&self, now: i64) -> CertLifetime {
        CertLifetime {
            days_left: (self.not_after_ts - now).div_euclid(86_400),
            not_yet_valid: now < self.not_before_ts,
        }
    }

    /// TLSA selector 0: SHA-256 of the full certificate.
    #[cfg(test)]
    pub fn cert_sha256_hex(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(&self.der)))
    }

    pub fn print_info(&self, hostname: Option<&str>, ports: &[u16], show_info: bool) -> Result<()> {
        self.print_info_params(hostname, ports, show_info, TlsaParams::default())
    }

    pub fn print_info_params(
        &self,
        hostname: Option<&str>,
        ports: &[u16],
        show_info: bool,
        params: TlsaParams,
    ) -> Result<()> {
        if show_info {
            let info = self.details()?;
            println!(">>> Certificate Information:");
            println!("Serial : {}", info.serial);
            println!("Issuer : {}", info.issuer);
            println!("Subject: {}", info.subject);
            if let Some(san) = &info.san {
                println!("Subject Alternative Name(s): {san}");
            }
            println!("Certificate Inception:  {}", info.not_before);
            println!("Certificate Expiration: {}", info.not_after);
        }

        let hash = self.tlsa_record_data(params)?;
        if params.is_default() {
            verbose::step(format_args!("SPKI SHA-256 {hash}"));
        } else {
            verbose::step(format_args!("{} {hash}", params.label()));
        }
        if ports.is_empty() {
            println!(
                "TLSA {} {} {} {hash}",
                params.usage, params.selector, params.matching
            );
        } else {
            for port in ports {
                println!(
                    "{}",
                    tlsa::record_line_with(&owner_name(*port, hostname), params, &hash)
                );
            }
        }
        Ok(())
    }
}

/// RFC 6698 §2.1: apply the selector (0 full cert, 1 SPKI) and matching type
/// (0 exact, 1 SHA2-256, 2 SHA2-512) to a DER certificate.
fn tlsa_association_data(der: &[u8], selector: u8, matching: u8) -> Result<String> {
    let data: Vec<u8> = match selector {
        0 => der.to_vec(),
        1 => {
            let (_, cert) =
                X509Certificate::from_der(der).context("failed to parse certificate")?;
            cert.public_key().raw.to_vec()
        }
        other => bail!("unsupported TLSA selector {other}"),
    };
    Ok(match matching {
        0 => hex::encode(&data),
        1 => hex::encode(Sha256::digest(&data)),
        2 => hex::encode(Sha512::digest(&data)),
        other => bail!("unsupported TLSA matching type {other}"),
    })
}

pub fn fetch_live(host: &str, port: u16, starttls: Option<StarttlsProto>) -> Result<Certificate> {
    let proto = StarttlsProto::resolve(port, starttls);
    verbose::step(format_args!(
        "connecting to {host}:{port} ({})",
        proto.label()
    ));
    let stream = match proto {
        StarttlsProto::None => tcp_connect(host, port)
            .with_context(|| format!("Exception: Connection error: connect {host}:{port}"))?,
        StarttlsProto::Smtp => smtp_starttls(host, port)
            .with_context(|| format!("Exception: Connection error: SMTP STARTTLS {host}:{port}"))?,
        StarttlsProto::Imap => imap_starttls(host, port)
            .with_context(|| format!("Exception: Connection error: IMAP STARTTLS {host}:{port}"))?,
        StarttlsProto::Pop3 => pop3_starttls(host, port)
            .with_context(|| format!("Exception: Connection error: POP3 STLS {host}:{port}"))?,
        StarttlsProto::Xmpp => xmpp_starttls(host, port)
            .with_context(|| format!("Exception: Connection error: XMPP STARTTLS {host}:{port}"))?,
    };
    tls_peer_cert(stream, host)
        .with_context(|| format!("Exception: Connection error: TLS {host}:{port}"))
}

pub fn install_crypto_provider() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("failed to install rustls crypto provider"))
}

fn tcp_connect(host: &str, port: u16) -> Result<TcpStream> {
    let stream = TcpStream::connect((host, port))
        .with_context(|| format!("failed to connect to {host}:{port}"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    stream.set_nodelay(true)?;
    verbose::step(format_args!("TCP connected to {host}:{port}"));
    Ok(stream)
}

fn smtp_starttls(host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = tcp_connect(host, port)?;
    smtp_negotiate(&mut stream)?;
    Ok(stream)
}

fn smtp_negotiate(stream: &mut impl ReadWrite) -> Result<()> {
    let (code, text) = smtp_read_response(stream)?;
    if code != 220 {
        bail!("SMTP banner rejected ({code}): {text}");
    }
    verbose::step(format_args!("SMTP banner {code}"));

    let (code, text) = smtp_command(stream, "EHLO gentlsa")?;
    if code != 250 {
        bail!("EHLO rejected ({code}): {text}");
    }
    verbose::step("SMTP EHLO accepted");

    let (code, text) = smtp_command(stream, "STARTTLS")?;
    if code != 220 {
        bail!("STARTTLS rejected ({code}): {text}");
    }
    verbose::step("SMTP STARTTLS accepted");
    Ok(())
}

fn smtp_command(stream: &mut impl ReadWrite, command: &str) -> Result<(u16, String)> {
    stream.write_all(format!("{command}\r\n").as_bytes())?;
    stream.flush()?;
    smtp_read_response(stream)
}

fn smtp_read_response(stream: &mut impl Read) -> Result<(u16, String)> {
    let mut messages = Vec::new();
    let code = loop {
        let line = read_crlf_line(stream, "SMTP")?;
        if line.len() < 3 {
            bail!("short SMTP response: {line:?}");
        }
        let code: u16 = line[..3]
            .parse()
            .with_context(|| format!("invalid SMTP status in {line:?}"))?;
        let continued = line.as_bytes().get(3) == Some(&b'-');
        if line.len() > 4 {
            messages.push(line[4..].to_string());
        }
        if !continued {
            break code;
        }
    };
    Ok((code, messages.join("\n")))
}

fn imap_starttls(host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = tcp_connect(host, port)?;
    imap_negotiate(&mut stream)?;
    Ok(stream)
}

fn imap_negotiate(stream: &mut impl ReadWrite) -> Result<()> {
    let greeting = read_crlf_line(stream, "IMAP")?;
    if !greeting.starts_with("* ") {
        bail!("IMAP greeting rejected: {greeting}");
    }
    let greeting_upper = greeting.to_ascii_uppercase();
    if greeting_upper.contains(" BYE") {
        bail!("IMAP greeting is BYE: {greeting}");
    }
    verbose::step("IMAP greeting");

    stream.write_all(b"a001 STARTTLS\r\n")?;
    stream.flush()?;
    loop {
        let line = read_crlf_line(stream, "IMAP")?;
        let upper = line.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("A001 ") {
            if rest.starts_with("OK") {
                verbose::step("IMAP STARTTLS accepted");
                return Ok(());
            }
            bail!("IMAP STARTTLS rejected: {line}");
        }
        if upper.starts_with("* BYE") {
            bail!("IMAP closed: {line}");
        }
    }
}

fn pop3_starttls(host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = tcp_connect(host, port)?;
    pop3_negotiate(&mut stream)?;
    Ok(stream)
}

fn pop3_negotiate(stream: &mut impl ReadWrite) -> Result<()> {
    let greeting = read_crlf_line(stream, "POP3")?;
    if !greeting.starts_with("+OK") {
        bail!("POP3 greeting rejected: {greeting}");
    }
    verbose::step("POP3 greeting");

    stream.write_all(b"STLS\r\n")?;
    stream.flush()?;
    let resp = read_crlf_line(stream, "POP3")?;
    if !resp.starts_with("+OK") {
        bail!("POP3 STLS rejected: {resp}");
    }
    verbose::step("POP3 STLS accepted");
    Ok(())
}

fn xmpp_starttls(host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = tcp_connect(host, port)?;
    xmpp_negotiate(&mut stream, host, port)?;
    Ok(stream)
}

fn xmpp_negotiate(stream: &mut impl ReadWrite, host: &str, port: u16) -> Result<()> {
    let xmlns = StarttlsProto::Xmpp.xmpp_stream_ns(port);
    let open = format!(
        "<?xml version='1.0'?><stream:stream xmlns='{xmlns}' \
         xmlns:stream='http://etherx.jabber.org/streams' to='{}' version='1.0'>",
        xml_attr(host)
    );
    stream.write_all(open.as_bytes())?;
    stream.flush()?;

    let features = read_until_markers(
        stream,
        &["</stream:features>", "<stream:features/>"],
        "XMPP",
    )?;
    let features_l = features.to_ascii_lowercase();
    if !features_l.contains("starttls") && !features_l.contains("urn:ietf:params:xml:ns:xmpp-tls") {
        bail!("XMPP server did not advertise STARTTLS");
    }
    verbose::step("XMPP stream features advertised STARTTLS");

    stream.write_all(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")?;
    stream.flush()?;
    let reply = xmpp_read_element(stream, &["proceed", "failure"])?;
    if reply.to_ascii_lowercase().contains("<failure") {
        bail!("XMPP STARTTLS rejected");
    }
    verbose::step("XMPP STARTTLS accepted");
    Ok(())
}

/// Read a complete XML start-or-empty element named in `names` (e.g. proceed).
/// Stops after the closing `>` so leftover bytes are not fed to the TLS handshake.
fn xmpp_read_element(stream: &mut impl Read, names: &[&str]) -> Result<String> {
    let starts: Vec<String> = names.iter().map(|name| format!("<{name}")).collect();
    let start_refs: Vec<&str> = starts.iter().map(String::as_str).collect();
    let mut buf = read_until_markers(stream, &start_refs, "XMPP")?;
    if !buf.contains('>') {
        buf.push_str(&read_until_markers(stream, &[">"], "XMPP")?);
    }
    if xml_start_is_empty(&buf) {
        return Ok(buf);
    }
    let lower = buf.to_ascii_lowercase();
    let name = names
        .iter()
        .find(|name| lower.contains(&format!("<{name}")))
        .copied()
        .unwrap_or(names[0]);
    let close = format!("</{name}>");
    if !lower.contains(&close) {
        buf.push_str(&read_until_markers(stream, &[&close], "XMPP")?);
    }
    Ok(buf)
}

fn xml_start_is_empty(buf: &str) -> bool {
    buf.trim_end()
        .strip_suffix('>')
        .is_some_and(|rest| rest.trim_end().ends_with('/'))
}

fn xml_attr(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn read_crlf_line(stream: &mut impl Read, proto: &str) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            bail!("{proto} connection closed");
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
        if line.len() > 8192 {
            bail!("{proto} line too long");
        }
    }
    String::from_utf8(line).with_context(|| format!("{proto} response was not valid UTF-8"))
}

fn read_until_markers(stream: &mut impl Read, markers: &[&str], proto: &str) -> Result<String> {
    let markers: Vec<Vec<u8>> = markers
        .iter()
        .map(|m| m.as_bytes().to_ascii_lowercase())
        .collect();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            bail!("{proto} connection closed");
        }
        buf.push(byte[0]);
        if buf.len() > 65_536 {
            bail!("{proto} response too long");
        }
        if markers.iter().any(|marker| {
            buf.len() >= marker.len()
                && buf[buf.len() - marker.len()..].eq_ignore_ascii_case(marker)
        }) {
            return Ok(String::from_utf8_lossy(&buf).into_owned());
        }
    }
}

fn tls_peer_cert(mut stream: TcpStream, server_name: &str) -> Result<Certificate> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|err| anyhow::anyhow!("invalid server name {server_name}: {err}"))?;
    let mut conn = ClientConnection::new(Arc::new(client_config()?), name)
        .context("failed to create TLS client")?;

    verbose::step(format_args!("TLS handshake with {server_name}"));
    while conn.is_handshaking() {
        conn.complete_io(&mut stream)
            .context("TLS handshake failed")?;
    }

    let mut certs = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|cert| cert.as_ref().to_vec())
        .collect::<Vec<_>>();
    if certs.is_empty() {
        bail!("no peer certificate");
    }
    let der = certs.remove(0);
    verbose::step(format_args!(
        "received leaf certificate ({} bytes) and {} chain certificate(s)",
        der.len(),
        certs.len()
    ));
    Certificate::from_der_chain(der, certs)
}

fn client_config() -> Result<ClientConfig> {
    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAllVerifier))
        .with_no_client_auth())
}

/// Accept any certificate. We are hashing whatever the server presents, like
/// the original Python tool which disabled TLS verification.
#[derive(Debug)]
struct AcceptAllVerifier;

impl ServerCertVerifier for AcceptAllVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn looks_like_pem(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes)
        .map(|text| text.contains("BEGIN CERTIFICATE"))
        .unwrap_or(false)
}

fn serial_hex(cert: &X509Certificate<'_>) -> String {
    let hex = hex::encode(cert.raw_serial());
    let trimmed = hex.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_string()
    }
}

fn format_san(cert: &X509Certificate<'_>) -> Option<String> {
    let san = cert.subject_alternative_name().ok().flatten()?;
    let names: Vec<String> = san
        .value
        .general_names
        .iter()
        .map(|name| match name {
            GeneralName::DNSName(dns) => format!("DNS:{dns}"),
            GeneralName::RFC822Name(email) => format!("email:{email}"),
            GeneralName::URI(uri) => format!("URI:{uri}"),
            GeneralName::IPAddress(ip) => format!("IP Address:{}", format_ip(ip)),
            other => other.to_string(),
        })
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join(", "))
    }
}

fn format_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        16 => {
            let octets: [u8; 16] = bytes.try_into().unwrap_or([0; 16]);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => hex::encode(bytes),
    }
}

fn format_asn1_time(time: &ASN1Time) -> String {
    let dt = time.to_datetime();
    let offset = dt.offset();
    let tz = if offset.is_utc() { " UTC" } else { "" };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}{:+03}:{:02}{tz}",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        offset.whole_hours(),
        offset.minutes_past_hour().unsigned_abs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_CERT_PEM: &str = include_str!("../tests/fixtures/test.example.pem");
    const SPKI_SHA512: &str = "d13899813b35185d9e3fe6fda257f15b4bfe8ec86ff9387155b3fcd9437692f50e018beeeef44ff767a151d31deb13719f6f7ec30e159c55cddef2b9531af1c1";
    const CERT_SHA256: &str = "d954c9dea1cc3687da0e9d7d08e94d364407234cb634d148e40c6bff44a05110";
    const CERT_SHA512: &str = "00537481b06573dcce15cbe75f6d5c63e1ae62f66396f6307ca985476e77417d5705840e6d8c67f7b3d6db48cf1e6fd630bdc571aecd469a0ef37528252a4f5a";

    #[test]
    fn tlsa_record_data_by_params() {
        let cert = Certificate::from_pem_or_der(TEST_CERT_PEM.as_bytes()).unwrap();
        let data = |usage, selector, matching| {
            cert.tlsa_record_data(TlsaParams {
                usage,
                selector,
                matching,
            })
            .unwrap()
        };

        assert_eq!(data(3, 1, 1), cert.spki_sha256_hex().unwrap());
        assert_eq!(data(3, 0, 1), CERT_SHA256);
        assert_eq!(data(3, 1, 2), SPKI_SHA512);
        assert_eq!(data(3, 0, 2), CERT_SHA512);
        // Matching type 0 is the exact DER, hex-encoded.
        assert!(data(3, 1, 0).starts_with("30820122300d06092a864886f70d010101050003"));
        // Trust-anchor usage with no presented chain falls back to the cert itself.
        assert_eq!(data(2, 1, 1), data(3, 1, 1));
    }

    #[test]
    fn matches_tlsa_by_params() {
        let cert = Certificate::from_pem_or_der(TEST_CERT_PEM.as_bytes()).unwrap();
        let record = |usage, selector, matching, hash: &str| TlsaRecord {
            usage,
            selector,
            matching,
            certificate: hash.into(),
        };
        let spki256 = cert.spki_sha256_hex().unwrap();

        assert_eq!(
            cert.matches_tlsa(&record(3, 1, 1, &spki256.to_uppercase())),
            Some(true)
        );
        assert_eq!(cert.matches_tlsa(&record(3, 0, 1, CERT_SHA256)), Some(true));
        assert_eq!(cert.matches_tlsa(&record(3, 1, 2, SPKI_SHA512)), Some(true));
        assert_eq!(cert.matches_tlsa(&record(3, 1, 1, "beef")), Some(false));
        // Trust-anchor usage matches any presented certificate (here just the leaf).
        assert_eq!(cert.matches_tlsa(&record(2, 1, 1, &spki256)), Some(true));
        assert_eq!(cert.matches_tlsa(&record(0, 0, 1, CERT_SHA256)), Some(true));
        // Unassigned parameters are not comparable.
        assert_eq!(cert.matches_tlsa(&record(9, 1, 1, &spki256)), None);
        assert_eq!(cert.matches_tlsa(&record(3, 4, 1, &spki256)), None);
        assert_eq!(cert.matches_tlsa(&record(3, 1, 7, &spki256)), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Certificate::from_pem_or_der(b"not a cert").is_err());
    }

    #[test]
    fn pem_detection() {
        assert!(looks_like_pem(TEST_CERT_PEM.as_bytes()));
        assert!(!looks_like_pem(&[0x30, 0x82, 0x01]));
    }

    #[test]
    fn hashes_match_openssl() {
        let cert = Certificate::from_pem_or_der(TEST_CERT_PEM.as_bytes()).unwrap();
        assert_eq!(
            cert.spki_sha256_hex().unwrap(),
            "ff94ad7dfafffed26e98150947dd8b1a7d981fabf90740c574685c81d487b9a8"
        );
        assert_eq!(
            cert.cert_sha256_hex().unwrap(),
            "d954c9dea1cc3687da0e9d7d08e94d364407234cb634d148e40c6bff44a05110"
        );

        let parsed = cert.parsed().unwrap();
        assert_eq!(
            parsed.subject().to_string(),
            "C=US, O=GenTLSA Test, CN=test.example"
        );
        assert_eq!(
            parsed.issuer().to_string(),
            "C=US, O=GenTLSA Test, CN=test.example"
        );
    }

    struct Scripted {
        reads: std::io::Cursor<Vec<u8>>,
        writes: Vec<u8>,
    }

    impl Scripted {
        fn new(server: &str) -> Self {
            Self {
                reads: std::io::Cursor::new(server.as_bytes().to_vec()),
                writes: Vec::new(),
            }
        }

        fn written(&self) -> String {
            String::from_utf8_lossy(&self.writes).into_owned()
        }
    }

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.read(buf)
        }
    }

    impl Write for Scripted {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn smtp_negotiate_ehlo_and_starttls() {
        let mut stream =
            Scripted::new("220 mx.example ESMTP\r\n250-hello\r\n250 STARTTLS\r\n220 Go ahead\r\n");
        smtp_negotiate(&mut stream).unwrap();
        let written = stream.written();
        assert!(written.contains("EHLO gentlsa"));
        assert!(written.contains("STARTTLS"));
    }

    #[test]
    fn smtp_negotiate_rejects_starttls() {
        let mut stream =
            Scripted::new("220 mx.example ESMTP\r\n250 ok\r\n454 TLS not available\r\n");
        let err = smtp_negotiate(&mut stream).unwrap_err();
        assert!(err.to_string().contains("STARTTLS rejected"));
    }

    #[test]
    fn imap_negotiate_starttls() {
        let mut stream = Scripted::new(
            "* OK IMAP4rev1 ready\r\n* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK Begin TLS\r\n",
        );
        imap_negotiate(&mut stream).unwrap();
        assert_eq!(stream.written(), "a001 STARTTLS\r\n");
    }

    #[test]
    fn imap_negotiate_rejects_starttls() {
        let mut stream = Scripted::new("* OK ready\r\na001 BAD no TLS\r\n");
        let err = imap_negotiate(&mut stream).unwrap_err();
        assert!(err.to_string().contains("IMAP STARTTLS rejected"));
    }

    #[test]
    fn pop3_negotiate_stls() {
        let mut stream = Scripted::new("+OK POP3 ready\r\n+OK Begin TLS\r\n");
        pop3_negotiate(&mut stream).unwrap();
        assert_eq!(stream.written(), "STLS\r\n");
    }

    #[test]
    fn pop3_negotiate_rejects_stls() {
        let mut stream = Scripted::new("+OK ready\r\n-ERR not supported\r\n");
        let err = pop3_negotiate(&mut stream).unwrap_err();
        assert!(err.to_string().contains("POP3 STLS rejected"));
    }

    #[test]
    fn xmpp_negotiate_client_stream() {
        let mut stream = Scripted::new(
            "<?xml version='1.0'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' \
             xmlns='jabber:client' version='1.0'>\
             <stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>\
             <required/></starttls></stream:features>\
             <proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        );
        xmpp_negotiate(&mut stream, "xmpp.example.com", 5222).unwrap();
        let written = stream.written();
        assert!(written.contains("xmlns='jabber:client'"));
        assert!(written.contains("to='xmpp.example.com'"));
        assert!(written.contains("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>"));
    }

    #[test]
    fn xmpp_negotiate_server_namespace_on_5269() {
        let mut stream = Scripted::new(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams' \
             xmlns='jabber:server' version='1.0'>\
             <stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\
             </stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>",
        );
        xmpp_negotiate(&mut stream, "example.com", 5269).unwrap();
        assert!(stream.written().contains("xmlns='jabber:server'"));
    }

    #[test]
    fn xmpp_negotiate_consumes_full_proceed() {
        let mut stream = Scripted::new(
            "<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>\
             <stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\
             </stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>TLSBYTES",
        );
        xmpp_negotiate(&mut stream, "example.com", 5222).unwrap();
        let mut rest = String::new();
        stream.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "TLSBYTES");
    }

    #[test]
    fn xmpp_negotiate_paired_proceed() {
        let mut stream = Scripted::new(
            "<stream:stream><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\
             </stream:features><proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'></proceed>TLSBYTES",
        );
        xmpp_negotiate(&mut stream, "example.com", 5222).unwrap();
        let mut rest = String::new();
        stream.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "TLSBYTES");
    }

    #[test]
    fn xmpp_negotiate_requires_starttls_feature() {
        let mut stream = Scripted::new(
            "<stream:stream><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>\
             </stream:features>",
        );
        let err = xmpp_negotiate(&mut stream, "example.com", 5222).unwrap_err();
        assert!(err.to_string().contains("did not advertise STARTTLS"));
    }

    #[test]
    fn xml_attr_escapes() {
        assert_eq!(xml_attr("a&b<c>'d\""), "a&amp;b&lt;c&gt;&apos;d&quot;");
    }

    #[test]
    fn lifetime_matches_not_after() {
        // The fixture is valid 2026-08-16 22:40:10 UTC to 2026-08-17 22:40:10 UTC.
        const NOT_BEFORE: i64 = 1_786_920_010;
        const NOT_AFTER: i64 = 1_787_006_410;
        let cert = Certificate::from_pem_or_der(TEST_CERT_PEM.as_bytes()).unwrap();

        let fresh = cert.lifetime_at(NOT_BEFORE);
        assert_eq!(fresh.days_left, 1);
        assert!(!fresh.not_yet_valid);

        assert!(cert.lifetime_at(NOT_BEFORE - 1).not_yet_valid);
        assert_eq!(cert.lifetime_at(NOT_AFTER - 1).days_left, 0);
        assert_eq!(cert.lifetime_at(NOT_AFTER).days_left, 0);
        assert_eq!(cert.lifetime_at(NOT_AFTER + 1).days_left, -1);
    }
}
