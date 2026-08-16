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
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::time::ASN1Time;

use crate::tlsa::{self, owner_name};

const IO_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct Certificate {
    der: Vec<u8>,
}

impl Certificate {
    pub fn from_der(der: Vec<u8>) -> Result<Self> {
        X509Certificate::from_der(&der).context("failed to parse certificate")?;
        Ok(Self { der })
    }

    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self> {
        if looks_like_pem(bytes) {
            let pem = pem::parse(bytes).context("failed to parse PEM certificate")?;
            return Self::from_der(pem.contents().to_vec());
        }
        Self::from_der(bytes.to_vec())
    }

    pub fn from_file(path: &Path) -> Result<Self> {
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

    /// TLSA selector 0: SHA-256 of the full certificate.
    #[cfg(test)]
    pub fn cert_sha256_hex(&self) -> Result<String> {
        Ok(hex::encode(Sha256::digest(&self.der)))
    }

    pub fn print_info(
        &self,
        hostname: Option<&str>,
        port: Option<u16>,
        show_info: bool,
    ) -> Result<()> {
        let cert = self.parsed()?;
        if show_info {
            println!(">>> Certificate Information:");
            println!("Serial : {}", serial_hex(&cert));
            println!("Issuer : {}", cert.issuer());
            println!("Subject: {}", cert.subject());
            if let Some(san) = format_san(&cert) {
                println!("Subject Alternative Name(s): {san}");
            }
            println!(
                "Certificate Inception:  {}",
                format_asn1_time(&cert.validity().not_before)
            );
            println!(
                "Certificate Expiration: {}",
                format_asn1_time(&cert.validity().not_after)
            );
        }

        let hash = self.spki_sha256_hex()?;
        match port {
            Some(port) => println!("{}", tlsa::record_line(&owner_name(port, hostname), &hash)),
            None => println!(
                "TLSA {} {} {} {hash}",
                tlsa::USAGE,
                tlsa::SELECTOR,
                tlsa::MATCHING
            ),
        }
        Ok(())
    }
}

pub fn fetch_live(host: &str, port: u16) -> Result<Certificate> {
    if tlsa::uses_starttls(port) {
        let stream = smtp_starttls(host, port)
            .with_context(|| format!("Exception: Connection error: STARTTLS {host}:{port}"))?;
        return tls_peer_cert(stream, host)
            .with_context(|| format!("Exception: Connection error: TLS {host}:{port}"));
    }

    let stream = tcp_connect(host, port)
        .with_context(|| format!("Exception: Connection error: connect {host}:{port}"))?;
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
    Ok(stream)
}

fn smtp_starttls(host: &str, port: u16) -> Result<TcpStream> {
    let mut stream = tcp_connect(host, port)?;
    let (code, text) = smtp_read_response(&mut stream)?;
    if code != 220 {
        bail!("SMTP banner rejected ({code}): {text}");
    }

    let (code, text) = smtp_command(&mut stream, "EHLO gentlsa")?;
    if code != 250 {
        bail!("EHLO rejected ({code}): {text}");
    }

    let (code, text) = smtp_command(&mut stream, "STARTTLS")?;
    if code != 220 {
        bail!("STARTTLS rejected ({code}): {text}");
    }
    Ok(stream)
}

fn smtp_command(stream: &mut TcpStream, command: &str) -> Result<(u16, String)> {
    stream.write_all(format!("{command}\r\n").as_bytes())?;
    stream.flush()?;
    smtp_read_response(stream)
}

fn smtp_read_response(stream: &mut TcpStream) -> Result<(u16, String)> {
    let mut messages = Vec::new();
    let code = loop {
        let line = read_crlf_line(stream)?;
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

fn read_crlf_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte)?;
        if n == 0 {
            bail!("SMTP connection closed");
        }
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
        if line.len() > 8192 {
            bail!("SMTP line too long");
        }
    }
    String::from_utf8(line).context("SMTP response was not valid UTF-8")
}

fn tls_peer_cert(mut stream: TcpStream, server_name: &str) -> Result<Certificate> {
    let name = ServerName::try_from(server_name.to_string())
        .map_err(|err| anyhow::anyhow!("invalid server name {server_name}: {err}"))?;
    let mut conn = ClientConnection::new(Arc::new(client_config()?), name)
        .context("failed to create TLS client")?;

    while conn.is_handshaking() {
        conn.complete_io(&mut stream)
            .context("TLS handshake failed")?;
    }

    let der = conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| cert.as_ref().to_vec())
        .context("no peer certificate")?;
    Certificate::from_der(der)
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
}
