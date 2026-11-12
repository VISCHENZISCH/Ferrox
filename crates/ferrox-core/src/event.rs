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

#[derive(
    Serialize, serde::Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
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
    /// Règle décrite dans le fichier de règles TOML.
    Rule,
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
            AlertKind::Rule => "Règle personnalisée",
        }
    }

    /// Identifiant stable (journaux ECS, API).
    pub fn as_str(&self) -> &'static str {
        match self {
            AlertKind::Beacon => "beacon",
            AlertKind::Exfiltration => "exfiltration",
            AlertKind::SuspiciousUserAgent => "suspicious_user_agent",
            AlertKind::DnsDga => "dns_dga",
            AlertKind::DnsTunnel => "dns_tunnel",
            AlertKind::DnsNxStorm => "dns_nx_storm",
            AlertKind::ThreatBlocked => "threat_blocked",
            AlertKind::Rule => "rule",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }

    pub const ALL: [AlertKind; 8] = [
        AlertKind::Beacon,
        AlertKind::Exfiltration,
        AlertKind::SuspiciousUserAgent,
        AlertKind::DnsDga,
        AlertKind::DnsTunnel,
        AlertKind::DnsNxStorm,
        AlertKind::ThreatBlocked,
        AlertKind::Rule,
    ];
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" | "faible" => Some(Severity::Low),
            "medium" | "moyenne" => Some(Severity::Medium),
            "high" | "haute" => Some(Severity::High),
            "critical" | "critique" => Some(Severity::Critical),
            _ => None,
        }
    }

    pub fn index(&self) -> usize {
        *self as usize
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
    /// User-Agent en cause pour les alertes de type User-Agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub detail: String,
    pub score: f32,
    /// Identifiant de la règle TOML à l'origine de l'alerte.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Nom lisible de cette règle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
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
