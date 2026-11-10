//! Journalisation JSON Lines au format ECS (Elastic Common Schema), rotation quotidienne,
//! et envoi syslog UDP optionnel vers un SIEM.

use crate::config::LogConfig;
use crate::event::{Alert, Event};
use serde_json::{json, Value};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

struct DailyFile {
    prefix: &'static str,
    day: String,
    w: Option<BufWriter<File>>,
}

impl DailyFile {
    fn new(prefix: &'static str) -> Self {
        Self {
            prefix,
            day: String::new(),
            w: None,
        }
    }

    fn write(&mut self, dir: &Path, day: &str, line: &str) {
        if self.day != day || self.w.is_none() {
            if let Some(mut w) = self.w.take() {
                let _ = w.flush();
            }
            let path = dir.join(format!("{}-{day}.jsonl", self.prefix));
            match OpenOptions::new().create(true).append(true).open(&path) {
                Ok(f) => self.w = Some(BufWriter::with_capacity(256 * 1024, f)),
                Err(e) => {
                    tracing::warn!("journal {} : {e}", path.display());
                    return;
                }
            }
            self.day = day.to_string();
        }
        if let Some(w) = &mut self.w {
            let _ = w.write_all(line.as_bytes());
            let _ = w.write_all(b"\n");
        }
    }

    fn flush(&mut self) {
        if let Some(w) = &mut self.w {
            let _ = w.flush();
        }
    }
}

pub struct Logger {
    dir: PathBuf,
    jsonl: bool,
    traffic: DailyFile,
    alerts: DailyFile,
    syslog: Option<(UdpSocket, SocketAddr)>,
    hostname: String,
}

fn ts_parts(ms: i64) -> (String, String) {
    let t = OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let iso = t.format(&Rfc3339).unwrap_or_default();
    let day = iso.get(..10).unwrap_or("1970-01-01").to_string();
    (iso, day)
}

impl Logger {
    pub fn new(cfg: &LogConfig, dir: PathBuf) -> Self {
        if cfg.jsonl {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                tracing::warn!("dossier de journaux {} : {e}", dir.display());
            }
        }
        let syslog = cfg.syslog.as_deref().and_then(|target| {
            let addr = target.to_socket_addrs().ok()?.next()?;
            let bind = if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            Some((UdpSocket::bind(bind).ok()?, addr))
        });
        let hostname = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .unwrap_or_else(|| "ferrox".into());
        Self {
            dir,
            jsonl: cfg.jsonl,
            traffic: DailyFile::new("traffic"),
            alerts: DailyFile::new("alerts"),
            syslog,
            hostname,
        }
    }

    pub fn write_event(&mut self, ev: &Event) {
        if !self.jsonl && self.syslog.is_none() {
            return;
        }
        let (doc, ms) = ecs_event(ev);
        self.emit(doc, ms, false);
    }

    pub fn write_alert(&mut self, a: &Alert) {
        if !self.jsonl && self.syslog.is_none() {
            return;
        }
        self.emit(ecs_alert(a), a.ts, true);
    }

    fn emit(&mut self, mut doc: Value, ms: i64, alert: bool) {
        let (iso, day) = ts_parts(ms);
        doc["@timestamp"] = Value::String(iso.clone());
        let line = doc.to_string();
        if self.jsonl {
            let f = if alert {
                &mut self.alerts
            } else {
                &mut self.traffic
            };
            f.write(&self.dir, &day, &line);
        }
        if let Some((sock, addr)) = &self.syslog {
            // RFC 5424 : facilité local0 ; sévérité 4 (warning) pour les alertes, 6 (info) sinon.
            let pri = if alert { 16 * 8 + 4 } else { 16 * 8 + 6 };
            let msg = format!("<{pri}>1 {iso} {} ferrox - - - {line}", self.hostname);
            let _ = sock.send_to(msg.as_bytes(), addr);
        }
    }

    pub fn flush(&mut self) {
        self.traffic.flush();
        self.alerts.flush();
    }
}

fn ecs_event(ev: &Event) -> (Value, i64) {
    match ev {
        Event::Http(e) => (
            json!({
                "event": {
                    "kind": "event",
                    "category": ["network", "web"],
                    "type": [if e.action == crate::event::Action::Block { "denied" } else { "allowed" }, "connection"],
                    "action": e.action,
                    "reason": e.reason,
                    "duration": e.duration_ms as u64 * 1_000_000,
                    "dataset": "ferrox.proxy",
                },
                "source": { "ip": e.client, "bytes": e.bytes_up },
                "destination": { "domain": e.host, "port": e.port, "bytes": e.bytes_down },
                "network": { "protocol": e.scheme.as_str(), "bytes": e.bytes_up + e.bytes_down },
                "url": { "domain": e.host, "path": e.path, "scheme": e.scheme.as_str() },
                "http": {
                    "request": { "method": e.method },
                    "response": { "status_code": e.status, "mime_type": e.content_type },
                },
                "user_agent": { "original": e.user_agent },
                "ferrox": { "category": e.category },
            }),
            e.ts,
        ),
        Event::Dns(e) => (
            json!({
                "event": {
                    "kind": "event",
                    "category": ["network"],
                    "type": [if e.action == crate::event::Action::Block { "denied" } else { "allowed" }, "protocol"],
                    "action": e.action,
                    "reason": e.reason,
                    "duration": e.latency_ms as u64 * 1_000_000,
                    "dataset": "ferrox.dns",
                },
                "source": { "ip": e.client },
                "network": { "protocol": "dns" },
                "dns": {
                    "type": "query",
                    "question": { "name": e.qname, "type": e.qtype },
                    "response_code": e.rcode,
                    "answers_count": e.answers,
                },
                "ferrox": { "category": e.category, "cached": e.cached },
            }),
            e.ts,
        ),
    }
}

/// Score arrondi à deux décimales : 0.3 au lieu de 0.30000001192092896.
fn round2(x: f32) -> f64 {
    (f64::from(x) * 100.0).round() / 100.0
}

fn ecs_alert(a: &Alert) -> Value {
    let mut doc = json!({
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection", "network"],
            "type": ["indicator"],
            "severity": match a.severity {
                crate::event::Severity::Low => 25,
                crate::event::Severity::Medium => 50,
                crate::event::Severity::High => 75,
                crate::event::Severity::Critical => 99,
            },
            "id": a.id.to_string(),
            "dataset": "ferrox.alert",
        },
        "rule": { "name": a.kind, "description": a.kind.label() },
        "source": { "ip": a.client },
        "message": a.detail,
        "ferrox": { "score": round2(a.score), "severity": a.severity },
    });
    // « * » désigne plusieurs destinations : pas de domaine à écrire.
    if a.target != "*" {
        doc["destination"] = json!({ "domain": a.target });
    }
    if let Some(ua) = &a.user_agent {
        doc["user_agent"] = json!({ "original": ua });
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{AlertKind, Severity};

    #[test]
    fn alert_ecs_fields() {
        let a = Alert {
            id: 1,
            ts: 1_700_000_000_000,
            severity: Severity::Medium,
            kind: AlertKind::SuspiciousUserAgent,
            client: "10.0.0.2".parse().unwrap(),
            target: "example.com".into(),
            user_agent: Some("curl/8.0".into()),
            detail: "outil".into(),
            score: 0.3,
        };
        let d = ecs_alert(&a);
        assert_eq!(d["destination"]["domain"], "example.com");
        assert_eq!(d["user_agent"]["original"], "curl/8.0");
        assert_eq!(d["ferrox"]["score"].to_string(), "0.3");
    }
}
