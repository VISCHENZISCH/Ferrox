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

/// Version du schéma ECS suivie par les journaux. Gelée à partir de Ferrox 1.0 :
/// un changement incompatible de format impose une version majeure.
pub const ECS_VERSION: &str = "8.11.0";

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

/// Règles de conservation et de confidentialité, modifiables à chaud.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogPolicy {
    pub retention_days: u32,
    pub max_total_mb: u64,
    pub mask_query: bool,
}

impl LogPolicy {
    pub fn from_config(cfg: &LogConfig) -> Self {
        Self {
            retention_days: cfg.retention_days,
            max_total_mb: cfg.max_total_mb,
            mask_query: cfg.mask_query,
        }
    }
}

/// Remplace la valeur de chaque paramètre d'URL par `*` : `/a?q=secret&x` → `/a?q=*&x`.
/// Le fragment éventuel est retiré.
pub fn mask_query(path: &str) -> std::borrow::Cow<'_, str> {
    let Some((base, query)) = path.split_once('?') else {
        return std::borrow::Cow::Borrowed(path);
    };
    let query = query.split('#').next().unwrap_or("");
    let mut out = String::with_capacity(path.len());
    out.push_str(base);
    out.push('?');
    for (i, kv) in query.split('&').enumerate() {
        if i > 0 {
            out.push('&');
        }
        match kv.split_once('=') {
            Some((k, _)) => {
                out.push_str(k);
                out.push_str("=*");
            }
            None => out.push_str(kv),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Date `AAAA-MM-JJ` d'un fichier `traffic-AAAA-MM-JJ.jsonl` ou `alerts-…`.
fn file_day(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".jsonl")?;
    let day = stem
        .strip_prefix("traffic-")
        .or_else(|| stem.strip_prefix("alerts-"))?;
    (day.len() == 10 && day.as_bytes()[4] == b'-' && day.as_bytes()[7] == b'-').then_some(day)
}

/// Résultat d'une purge des journaux.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    pub removed_files: usize,
    pub removed_bytes: u64,
}

/// Supprime les journaux plus anciens que la rétention, puis les plus anciens tant que la
/// taille totale dépasse le plafond. Les fichiers du jour `today` ne sont jamais supprimés.
pub fn purge_logs(dir: &Path, policy: LogPolicy, today: &str) -> PurgeReport {
    let mut report = PurgeReport::default();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return report;
    };
    let mut files: Vec<(String, PathBuf, u64)> = rd
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let day = file_day(&name)?.to_string();
            let len = e.metadata().ok()?.len();
            Some((day, e.path(), len))
        })
        .collect();
    files.sort();
    let cutoff = (policy.retention_days > 0).then(|| {
        let t = OffsetDateTime::now_utc() - time::Duration::days(i64::from(policy.retention_days));
        t.format(&Rfc3339).unwrap_or_default()[..10].to_string()
    });
    let mut total: u64 = files.iter().map(|f| f.2).sum();
    let max = policy.max_total_mb.saturating_mul(1024 * 1024);
    for (day, path, len) in &files {
        if day.as_str() >= today {
            break;
        }
        let too_old = cutoff.as_deref().is_some_and(|c| day.as_str() < c);
        let too_big = max > 0 && total > max;
        if !(too_old || too_big) {
            continue;
        }
        if std::fs::remove_file(path).is_ok() {
            total -= len;
            report.removed_files += 1;
            report.removed_bytes += len;
        }
    }
    report
}

pub struct Logger {
    dir: PathBuf,
    jsonl: bool,
    policy: LogPolicy,
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
            policy: LogPolicy::from_config(cfg),
            traffic: DailyFile::new("traffic"),
            alerts: DailyFile::new("alerts"),
            syslog,
            hostname,
        }
    }

    pub fn set_policy(&mut self, policy: LogPolicy) {
        self.policy = policy;
    }

    /// Applique la rétention (appelée au démarrage puis toutes les heures).
    pub fn purge(&mut self) -> PurgeReport {
        if !self.jsonl {
            return PurgeReport::default();
        }
        self.flush();
        let (_, today) = ts_parts(crate::event::now_ms());
        let r = purge_logs(&self.dir, self.policy, &today);
        if r.removed_files > 0 {
            tracing::info!(
                "journaux : {} fichier(s) supprimé(s), {} octets libérés",
                r.removed_files,
                r.removed_bytes
            );
        }
        r
    }

    pub fn write_event(&mut self, ev: &Event) {
        if !self.jsonl && self.syslog.is_none() {
            return;
        }
        let (mut doc, ms) = ecs_event(ev);
        if self.policy.mask_query {
            if let Some(path) = doc["url"]["path"].as_str() {
                let masked = mask_query(path).into_owned();
                doc["url"]["path"] = Value::String(masked);
            }
        }
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
        doc["ecs"] = json!({ "version": ECS_VERSION });
        doc["observer"] = json!({
            "vendor": "Ferrox",
            "product": "Ferrox",
            "type": "proxy",
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": self.hostname,
        });
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
        "rule": {
            "id": a.rule.clone().unwrap_or_else(|| a.kind.as_str().to_string()),
            "name": a.rule_name.clone().unwrap_or_else(|| a.kind.label().to_string()),
            "category": a.kind.as_str(),
        },
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
    fn masks_query_values() {
        assert_eq!(mask_query("/a?q=secret&x&id=4#f"), "/a?q=*&x&id=*");
        assert_eq!(mask_query("/plain"), "/plain");
        assert_eq!(mask_query("/?"), "/?");
    }

    #[test]
    fn purge_respects_size_and_today() {
        let dir = std::env::temp_dir().join(format!("ferrox-purge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for d in ["2020-01-01", "2020-01-02", "2099-12-31"] {
            std::fs::write(
                dir.join(format!("traffic-{d}.jsonl")),
                vec![b'x'; 600 * 1024],
            )
            .unwrap();
        }
        std::fs::write(dir.join("notes.txt"), b"keep").unwrap();
        // Rétention : les fichiers de 2020 sont trop vieux ; le jour courant est gardé.
        let r = purge_logs(
            &dir,
            LogPolicy {
                retention_days: 30,
                max_total_mb: 0,
                mask_query: false,
            },
            "2099-12-31",
        );
        assert_eq!(r.removed_files, 2);
        assert!(dir.join("traffic-2099-12-31.jsonl").exists());
        assert!(dir.join("notes.txt").exists());
        // Plafond de taille : les plus anciens partent d'abord.
        for d in ["2098-01-01", "2098-01-02"] {
            std::fs::write(
                dir.join(format!("alerts-{d}.jsonl")),
                vec![b'x'; 600 * 1024],
            )
            .unwrap();
        }
        let r = purge_logs(
            &dir,
            LogPolicy {
                retention_days: 0,
                max_total_mb: 1,
                mask_query: false,
            },
            "2099-12-31",
        );
        assert_eq!(r.removed_files, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

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
            rule: None,
            rule_name: None,
        };
        let d = ecs_alert(&a);
        assert_eq!(d["destination"]["domain"], "example.com");
        assert_eq!(d["user_agent"]["original"], "curl/8.0");
        assert_eq!(d["ferrox"]["score"].to_string(), "0.3");
    }
}
