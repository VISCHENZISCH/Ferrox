//! Contrôle d'accès : réseaux autorisés, ports CONNECT, authentification Basic
//! et exclusion d'interception temporaire.

use base64::Engine as _;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Réseau autorisé, par exemple `192.168.1.0/24` ou `::1/128`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Accepte `10.0.0.0/8`, `::1/128` ou une adresse seule (`192.168.1.10`).
    pub fn parse(s: &str) -> Option<Self> {
        let (ip, len) = s.trim().split_once('/').unwrap_or((s.trim(), ""));
        let net: IpAddr = ip.trim().parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = if len.is_empty() {
            max
        } else {
            len.trim().parse().ok()?
        };
        (prefix <= max).then_some(Self { net, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // Une adresse IPv4 vue par une socket IPv6 (::ffff:a.b.c.d) est traitée comme IPv4.
        let ip = ip.to_canonical();
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(n) & mask == u32::from(a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(n) & mask == u128::from(a) & mask
            }
            _ => false,
        }
    }

    /// Vrai pour `0.0.0.0/0` ou `::/0` : tout le monde est autorisé.
    pub fn is_any(&self) -> bool {
        self.prefix == 0
    }
}

impl std::fmt::Display for Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.net, self.prefix)
    }
}

/// Réseaux autorisés par défaut : la boucle locale seulement.
pub fn loopback() -> Vec<Cidr> {
    vec![
        Cidr {
            net: IpAddr::from([127, 0, 0, 0]),
            prefix: 8,
        },
        Cidr {
            net: IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 1]),
            prefix: 128,
        },
    ]
}

/// Analyse une liste de réseaux ; une liste vide revient à la boucle locale.
pub fn parse_allow(list: &[String], what: &str) -> anyhow::Result<Vec<Cidr>> {
    let mut out = Vec::with_capacity(list.len());
    for s in list.iter().filter(|s| !s.trim().is_empty()) {
        out.push(
            Cidr::parse(s)
                .ok_or_else(|| anyhow::anyhow!("{what} : réseau autorisé invalide « {s} »"))?,
        );
    }
    if out.is_empty() {
        out = loopback();
    }
    Ok(out)
}

/// À appeler juste après `accept()` ou `recv_from()` : refus hors des réseaux listés.
pub fn client_allowed(ip: IpAddr, allow: &[Cidr]) -> bool {
    allow.iter().any(|c| c.contains(ip))
}

/// CONNECT limité aux ports listés (443 et 8443 par défaut, comme Squid).
pub fn connect_port_allowed(port: u16, allowed: &[u16]) -> bool {
    allowed.contains(&port)
}

/// Identifiants attendus pour l'authentification Basic du proxy explicite.
#[derive(Clone, Debug)]
pub struct BasicAuth {
    expected: Vec<u8>,
}

impl BasicAuth {
    pub fn new(user: &str, password: &str) -> Self {
        Self {
            expected: format!("{user}:{password}").into_bytes(),
        }
    }

    /// Vérifie la valeur d'un en-tête `Proxy-Authorization`.
    pub fn check(&self, header: Option<&[u8]>) -> bool {
        let Some(h) = header.and_then(|h| std::str::from_utf8(h).ok()) else {
            return false;
        };
        let Some((scheme, token)) = h.trim().split_once(' ') else {
            return false;
        };
        if !scheme.eq_ignore_ascii_case("basic") {
            return false;
        }
        let Ok(got) = base64::engine::general_purpose::STANDARD.decode(token.trim()) else {
            return false;
        };
        constant_time_eq(&got, &self.expected)
    }
}

/// Comparaison en temps constant (pour une longueur donnée).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Contournement d'interception temporaire : il faut plusieurs échecs, et il expire.
pub struct BypassCache {
    inner: Mutex<HashMap<String, (u32, Instant)>>,
    threshold: u32,
    ttl: Duration,
    max: usize,
}

impl BypassCache {
    pub fn new(threshold: u32, ttl: Duration, max: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            threshold: threshold.max(1),
            ttl,
            max: max.max(1),
        }
    }

    /// Enregistre un échec de poignée de main interceptée.
    pub fn record_failure(&self, host: &str) {
        let mut m = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let now = Instant::now();
        if m.len() >= self.max && !m.contains_key(host) {
            m.retain(|_, (_, t)| now.duration_since(*t) < self.ttl);
            if m.len() >= self.max {
                // Toujours plein : on retire l'entrée la plus ancienne.
                if let Some(oldest) = m
                    .iter()
                    .min_by_key(|(_, (_, t))| *t)
                    .map(|(k, _)| k.clone())
                {
                    m.remove(&oldest);
                }
            }
        }
        let e = m.entry(host.to_owned()).or_insert((0, now));
        if now.duration_since(e.1) >= self.ttl {
            e.0 = 0;
        }
        e.0 += 1;
        e.1 = now;
    }

    /// Vrai si l'hôte doit passer en tunnel direct.
    pub fn is_bypassed(&self, host: &str) -> bool {
        let m = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        m.get(host)
            .is_some_and(|(n, t)| *n >= self.threshold && t.elapsed() < self.ttl)
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4_v6() {
        let lan = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(lan.contains(ip("192.168.1.42")));
        assert!(!lan.contains(ip("192.168.2.1")));
        assert!(lan.contains(ip("::ffff:192.168.1.7")));
        let one = Cidr::parse("10.0.0.5").unwrap();
        assert!(one.contains(ip("10.0.0.5")) && !one.contains(ip("10.0.0.6")));
        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains(ip("fd12::1")) && !v6.contains(ip("fe80::1")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("pas-une-ip").is_none());
    }

    #[test]
    fn default_is_loopback() {
        let a = parse_allow(&[], "proxy").unwrap();
        assert!(client_allowed(ip("127.0.0.1"), &a));
        assert!(client_allowed(ip("::1"), &a));
        assert!(!client_allowed(ip("192.168.1.10"), &a));
        assert!(parse_allow(&["300.1.1.1/8".into()], "proxy").is_err());
    }

    #[test]
    fn connect_ports() {
        assert!(connect_port_allowed(443, &[443, 8443]));
        assert!(!connect_port_allowed(25, &[443, 8443]));
    }

    #[test]
    fn basic_auth() {
        let a = BasicAuth::new("alice", "s3cret");
        // base64("alice:s3cret")
        assert!(a.check(Some(b"Basic YWxpY2U6czNjcmV0")));
        assert!(a.check(Some(b"basic  YWxpY2U6czNjcmV0 ")));
        assert!(!a.check(Some(b"Basic YWxpY2U6bm9wZQ==")));
        assert!(!a.check(Some(b"Bearer YWxpY2U6czNjcmV0")));
        assert!(!a.check(None));
    }

    #[test]
    fn bypass_needs_threshold_and_is_bounded() {
        let c = BypassCache::new(3, Duration::from_secs(3600), 2);
        c.record_failure("a.com");
        c.record_failure("a.com");
        assert!(!c.is_bypassed("a.com"));
        c.record_failure("a.com");
        assert!(c.is_bypassed("a.com"));
        c.record_failure("b.com");
        c.record_failure("c.com");
        assert!(c.len() <= 2);
        let short = BypassCache::new(1, Duration::from_millis(1), 10);
        short.record_failure("x.com");
        std::thread::sleep(Duration::from_millis(5));
        assert!(!short.is_bypassed("x.com"));
    }
}
