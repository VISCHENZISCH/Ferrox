//! Résolveurs amont : DNS classique (UDP, TCP), DNS sur TLS (RFC 7858) et DNS sur HTTPS
//! (RFC 8484).
//!
//! Formes acceptées :
//! - `1.1.1.1`, `1.1.1.1:53`, `2606:4700::1111`, `[2606:4700::1111]:53` : UDP, puis TCP
//!   pour les clients TCP ;
//! - `tls://1.1.1.1:853#cloudflare-dns.com` : DoT, le nom après `#` est vérifié dans le
//!   certificat (l'adresse IP sinon) ;
//! - `https://1.1.1.1/dns-query` : DoH. Préférez une adresse IP dans l'URL : un nom
//!   demanderait au système de le résoudre, éventuellement via Ferrox lui-même.

use crate::http_client::{self, HttpsClient};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// Connexions DoT gardées ouvertes par résolveur.
const DOT_POOL: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamKind {
    Plain(SocketAddr),
    Tls { addr: SocketAddr, name: String },
    Https { url: String },
}

/// Résolveur amont prêt à l'emploi (avec son pool de connexions chiffrées).
pub struct Upstream {
    pub kind: UpstreamKind,
    dot_pool: Mutex<Vec<TlsStream<TcpStream>>>,
}

impl std::fmt::Debug for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.kind.fmt(f)
    }
}

impl std::fmt::Display for UpstreamKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamKind::Plain(a) => write!(f, "{a}"),
            UpstreamKind::Tls { addr, name } => write!(f, "tls://{addr}#{name}"),
            UpstreamKind::Https { url } => f.write_str(url),
        }
    }
}

fn parse_addr(s: &str, default_port: u16) -> Option<SocketAddr> {
    s.parse::<SocketAddr>()
        .ok()
        .or_else(|| {
            s.parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, default_port))
        })
        .or_else(|| {
            // `[2606:4700::1111]` sans port.
            let inner = s.strip_prefix('[')?.strip_suffix(']')?;
            inner
                .parse::<IpAddr>()
                .ok()
                .map(|ip| SocketAddr::new(ip, default_port))
        })
}

/// Analyse une ligne de configuration `upstreams`.
pub fn parse(s: &str) -> Result<UpstreamKind, String> {
    let s = s.trim();
    let err = || format!("résolveur amont invalide : « {s} »");
    if let Some(rest) = s.strip_prefix("tls://") {
        let (addr, name) = match rest.split_once('#') {
            Some((a, n)) => (a, Some(n.trim())),
            None => (rest, None),
        };
        let addr = parse_addr(addr.trim(), 853).ok_or_else(err)?;
        let name = name
            .filter(|n| !n.is_empty())
            .map_or_else(|| addr.ip().to_string(), str::to_string);
        ServerName::try_from(name.clone()).map_err(|_| err())?;
        return Ok(UpstreamKind::Tls { addr, name });
    }
    if s.starts_with("https://") {
        let uri: hyper::Uri = s.parse().map_err(|_| err())?;
        if uri.host().is_none_or(str::is_empty) {
            return Err(err());
        }
        return Ok(UpstreamKind::Https { url: s.to_string() });
    }
    parse_addr(s, 53).map(UpstreamKind::Plain).ok_or_else(err)
}

impl Upstream {
    pub fn new(kind: UpstreamKind) -> Self {
        Self {
            kind,
            dot_pool: Mutex::new(Vec::new()),
        }
    }

    pub fn is_plain(&self) -> bool {
        matches!(self.kind, UpstreamKind::Plain(_))
    }

    pub fn plain_addr(&self) -> Option<SocketAddr> {
        match self.kind {
            UpstreamKind::Plain(a) => Some(a),
            _ => None,
        }
    }

    /// Envoie une requête par DoT ou DoH et renvoie la réponse brute.
    pub async fn exchange_encrypted(
        &self,
        pkt: &[u8],
        tls: &TlsConnector,
        https: &HttpsClient,
        timeout: Duration,
    ) -> std::io::Result<Vec<u8>> {
        let fut = async {
            match &self.kind {
                UpstreamKind::Tls { addr, name } => self.dot(pkt, *addr, name, tls).await,
                UpstreamKind::Https { url } => doh(pkt, url, https).await,
                UpstreamKind::Plain(_) => Err(std::io::Error::other("résolveur non chiffré")),
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "dns timeout"))?
    }

    async fn dot(
        &self,
        pkt: &[u8],
        addr: SocketAddr,
        name: &str,
        tls: &TlsConnector,
    ) -> std::io::Result<Vec<u8>> {
        // Connexion réutilisée si possible ; une connexion fermée par le serveur entre-temps
        // échoue à la première écriture ou lecture : on réessaie alors sur une neuve.
        let pooled = self.dot_pool.lock().pop();
        if let Some(mut s) = pooled {
            if let Ok(r) = dot_round_trip(&mut s, pkt).await {
                self.give_back(s);
                return Ok(r);
            }
        }
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        let server = ServerName::try_from(name.to_string())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut s = tls.connect(server, tcp).await?;
        let r = dot_round_trip(&mut s, pkt).await?;
        self.give_back(s);
        Ok(r)
    }

    fn give_back(&self, s: TlsStream<TcpStream>) {
        let mut pool = self.dot_pool.lock();
        if pool.len() < DOT_POOL {
            pool.push(s);
        }
    }
}

async fn dot_round_trip(s: &mut TlsStream<TcpStream>, pkt: &[u8]) -> std::io::Result<Vec<u8>> {
    let len = u16::try_from(pkt.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "message trop long"))?;
    let mut out = Vec::with_capacity(pkt.len() + 2);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(pkt);
    s.write_all(&out).await?;
    s.flush().await?;
    // Les réponses arrivent dans l'ordre sur une connexion utilisée par une seule requête
    // à la fois ; l'identifiant est tout de même vérifié.
    loop {
        let n = s.read_u16().await? as usize;
        let mut buf = vec![0u8; n];
        s.read_exact(&mut buf).await?;
        if buf.len() >= 2 && buf[..2] == pkt[..2] {
            return Ok(buf);
        }
    }
}

async fn doh(pkt: &[u8], url: &str, client: &HttpsClient) -> std::io::Result<Vec<u8>> {
    let body = Full::new(Bytes::copy_from_slice(pkt))
        .map_err(|never| match never {})
        .boxed();
    let req = hyper::Request::post(url)
        .header(hyper::header::CONTENT_TYPE, "application/dns-message")
        .header(hyper::header::ACCEPT, "application/dns-message")
        .header(
            hyper::header::USER_AGENT,
            concat!("Ferrox/", env!("CARGO_PKG_VERSION")),
        )
        .body(body)
        .map_err(std::io::Error::other)?;
    let resp = client.request(req).await.map_err(std::io::Error::other)?;
    if !resp.status().is_success() {
        return Err(std::io::Error::other(format!(
            "DoH : HTTP {}",
            resp.status()
        )));
    }
    let bytes = Limited::new(resp.into_body(), 65_535)
        .collect()
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))?
        .to_bytes();
    Ok(bytes.to_vec())
}

/// Connecteur TLS pour DoT (racines webpki).
pub fn dot_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions TLS")
    .with_root_certificates(roots)
    .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

/// Client HTTPS pour DoH.
pub fn doh_client() -> HttpsClient {
    http_client::build_with_timeout(Duration::from_secs(5))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_forms() {
        assert_eq!(
            parse("1.1.1.1").unwrap(),
            UpstreamKind::Plain("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            parse("2606:4700::1111").unwrap(),
            UpstreamKind::Plain("[2606:4700::1111]:53".parse().unwrap())
        );
        assert_eq!(
            parse("[2606:4700::1111]").unwrap(),
            UpstreamKind::Plain("[2606:4700::1111]:53".parse().unwrap())
        );
        assert_eq!(
            parse("tls://1.1.1.1#cloudflare-dns.com").unwrap(),
            UpstreamKind::Tls {
                addr: "1.1.1.1:853".parse().unwrap(),
                name: "cloudflare-dns.com".into()
            }
        );
        assert_eq!(
            parse("tls://9.9.9.9:853").unwrap(),
            UpstreamKind::Tls {
                addr: "9.9.9.9:853".parse().unwrap(),
                name: "9.9.9.9".into()
            }
        );
        assert!(matches!(
            parse("https://1.1.1.1/dns-query").unwrap(),
            UpstreamKind::Https { .. }
        ));
        assert!(parse("tls://nope").is_err());
        assert!(parse("https://").is_err());
        assert!(parse("exemple").is_err());
    }
}
