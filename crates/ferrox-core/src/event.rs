//! Événements produits par le proxy et le DNS, et alertes produites par la détection.

use serde::Serialize;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::Arc;

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    /// HTTPS déchiffré (MITM).
    Https,
    /// Tunnel CONNECT ou SNI non déchiffré.
    Tunnel,
}

impl Scheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
            Scheme::Tunnel => "tunnel",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct HttpEvent {
    pub ts: i64,
    pub client: IpAddr,
    pub method: String,
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: Option<String>,
    pub status: u16,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub duration_ms: u32,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub action: Action,
    pub reason: Option<String>,
    pub category: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct DnsEvent {
    pub ts: i64,
    pub client: IpAddr,
    pub qname: String,
    pub qtype: String,
    pub rcode: String,
    pub answers: u16,
    pub latency_ms: u32,
    pub cached: bool,
    pub action: Action,
    pub reason: Option<String>,
    pub category: Option<String>,
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "Faible",
            Severity::Medium => "Moyenne",
            Severity::High => "Haute",
            Severity::Critical => "Critique",
        }
    }
}

#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AlertKind {
    Beacon,
    Exfiltration,
    SuspiciousUserAgent,
    DnsDga,
    DnsTunnel,
    DnsNxStorm,
    ThreatBlocked,
}

impl AlertKind {
    pub fn label(&self) -> &'static str {
        match self {
            AlertKind::Beacon => "Balise C2",
            AlertKind::Exfiltration => "Exfiltration",
            AlertKind::SuspiciousUserAgent => "User-Agent suspect",
            AlertKind::DnsDga => "DNS aléatoire (DGA)",
            AlertKind::DnsTunnel => "Tunnel DNS",
            AlertKind::DnsNxStorm => "Rafale NXDOMAIN",
            AlertKind::ThreatBlocked => "Menace bloquée",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Alert {
    pub id: u64,
    pub ts: i64,
    pub severity: Severity,
    pub kind: AlertKind,
    pub client: IpAddr,
    pub target: String,
    pub detail: String,
    pub score: f32,
}

#[derive(Clone, Debug)]
pub enum Event {
    Http(HttpEvent),
    Dns(DnsEvent),
}

/// Point d'émission utilisé par le chemin critique : jamais bloquant.
/// Si le pipeline est saturé, l'événement est compté puis abandonné.
#[derive(Clone)]
pub struct EventSink {
    tx: SyncSender<Event>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    pub fn new(tx: SyncSender<Event>, dropped: Arc<AtomicU64>) -> Self {
        Self { tx, dropped }
    }

    #[inline]
    pub fn emit(&self, ev: Event) {
        match self.tx.try_send(ev) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
