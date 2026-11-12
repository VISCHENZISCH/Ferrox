//! Historique persistant (SQLite) : agrégats par minute et alertes.
//!
//! Le pipeline écrit (une seule connexion, transactions groupées) ; l'interface et l'API
//! lisent par une connexion séparée en lecture seule. La base est en mode WAL : les
//! lectures ne bloquent pas les écritures.

use crate::event::{Action, Alert, AlertKind, Event, Severity};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS minutes (
    t           INTEGER PRIMARY KEY,
    requests    INTEGER NOT NULL DEFAULT 0,
    blocked     INTEGER NOT NULL DEFAULT 0,
    dns         INTEGER NOT NULL DEFAULT 0,
    dns_blocked INTEGER NOT NULL DEFAULT 0,
    bytes_up    INTEGER NOT NULL DEFAULT 0,
    bytes_down  INTEGER NOT NULL DEFAULT 0,
    alerts      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    kind       TEXT NOT NULL,
    severity   TEXT NOT NULL,
    client     TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    score      REAL NOT NULL,
    rule       TEXT,
    rule_name  TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
PRAGMA user_version = 1;
";

/// Agrégat d'une minute (`t` = minute Unix, en secondes divisées par 60).
#[derive(Serialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MinutePoint {
    pub t: i64,
    pub requests: u64,
    pub blocked: u64,
    pub dns: u64,
    pub dns_blocked: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub alerts: u64,
}

impl MinutePoint {
    fn add(&mut self, o: &MinutePoint) {
        self.requests += o.requests;
        self.blocked += o.blocked;
        self.dns += o.dns;
        self.dns_blocked += o.dns_blocked;
        self.bytes_up += o.bytes_up;
        self.bytes_down += o.bytes_down;
        self.alerts += o.alerts;
    }
}

/// Alerte relue depuis l'historique.
#[derive(Serialize, Clone, Debug)]
pub struct StoredAlert {
    pub id: i64,
    pub ts: i64,
    pub kind: AlertKind,
    pub severity: Severity,
    pub client: String,
    pub target: String,
    pub detail: String,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

fn u(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

fn i(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

/// Écriture : agrégats en mémoire jusqu'au prochain `flush`, puis une transaction.
pub struct HistoryWriter {
    conn: Connection,
    pending: BTreeMap<i64, MinutePoint>,
    alerts: Vec<Alert>,
    retention_days: u32,
}

fn open_rw(path: &Path) -> rusqlite::Result<Connection> {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

impl HistoryWriter {
    pub fn open(path: &Path, retention_days: u32) -> anyhow::Result<Self> {
        let conn =
            open_rw(path).map_err(|e| anyhow::anyhow!("historique {} : {e}", path.display()))?;
        Ok(Self {
            conn,
            pending: BTreeMap::new(),
            alerts: Vec::new(),
            retention_days,
        })
    }

    pub fn set_retention(&mut self, days: u32) {
        self.retention_days = days;
    }

    fn minute(&mut self, ts_ms: i64) -> &mut MinutePoint {
        let t = ts_ms.div_euclid(60_000);
        self.pending.entry(t).or_insert(MinutePoint {
            t,
            ..MinutePoint::default()
        })
    }

    pub fn record_event(&mut self, ev: &Event) {
        match ev {
            Event::Http(e) => {
                let m = self.minute(e.ts);
                m.requests += 1;
                m.blocked += u64::from(e.action == Action::Block);
                m.bytes_up += e.bytes_up;
                m.bytes_down += e.bytes_down;
            }
            Event::Dns(e) => {
                let m = self.minute(e.ts);
                m.dns += 1;
                m.dns_blocked += u64::from(e.action == Action::Block);
            }
        }
    }

    pub fn record_alert(&mut self, a: &Alert) {
        self.minute(a.ts).alerts += 1;
        self.alerts.push(a.clone());
    }

    /// Écrit tout ce qui est en attente, en une transaction.
    pub fn flush(&mut self) -> rusqlite::Result<()> {
        if self.pending.is_empty() && self.alerts.is_empty() {
            return Ok(());
        }
        let tx = self.conn.transaction()?;
        {
            let mut up = tx.prepare_cached(
                "INSERT INTO minutes (t, requests, blocked, dns, dns_blocked, bytes_up, bytes_down, alerts)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT(t) DO UPDATE SET
                   requests = requests + excluded.requests,
                   blocked = blocked + excluded.blocked,
                   dns = dns + excluded.dns,
                   dns_blocked = dns_blocked + excluded.dns_blocked,
                   bytes_up = bytes_up + excluded.bytes_up,
                   bytes_down = bytes_down + excluded.bytes_down,
                   alerts = alerts + excluded.alerts",
            )?;
            for m in self.pending.values() {
                up.execute(params![
                    m.t,
                    i(m.requests),
                    i(m.blocked),
                    i(m.dns),
                    i(m.dns_blocked),
                    i(m.bytes_up),
                    i(m.bytes_down),
                    i(m.alerts)
                ])?;
            }
            let mut ins = tx.prepare_cached(
                "INSERT INTO alerts (ts, kind, severity, client, target, detail, score, rule, rule_name, user_agent)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            )?;
            for a in &self.alerts {
                ins.execute(params![
                    a.ts,
                    a.kind.as_str(),
                    a.severity.as_str(),
                    a.client.to_string(),
                    a.target,
                    a.detail,
                    (f64::from(a.score) * 100.0).round() / 100.0,
                    a.rule,
                    a.rule_name,
                    a.user_agent
                ])?;
            }
        }
        tx.commit()?;
        self.pending.clear();
        self.alerts.clear();
        Ok(())
    }

    /// Supprime ce qui dépasse la durée de conservation ; renvoie le nombre de lignes retirées.
    pub fn purge(&mut self, now_ms: i64) -> rusqlite::Result<usize> {
        if self.retention_days == 0 {
            return Ok(0);
        }
        let cutoff_ms = now_ms - i64::from(self.retention_days) * 86_400_000;
        let a = self
            .conn
            .execute("DELETE FROM alerts WHERE ts < ?1", params![cutoff_ms])?;
        let m = self.conn.execute(
            "DELETE FROM minutes WHERE t < ?1",
            params![cutoff_ms.div_euclid(60_000)],
        )?;
        Ok(a + m)
    }
}

/// Lecture seule de l'historique (interface, API).
pub struct HistoryReader {
    conn: Connection,
}

/// Bilan d'une période.
#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct PeriodTotals {
    pub totals: MinutePoint,
    pub alerts_by_severity: [u64; 4],
}

impl HistoryReader {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            // Crée la base vide pour que les lectures aboutissent.
            drop(open_rw(path)?);
        }
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(2))?;
        Ok(Self { conn })
    }

    /// Points de `from_ms` à `to_ms`, regroupés par pas de `step_min` minutes ; les pas sans
    /// donnée sont remplis de zéros (série continue).
    pub fn series(
        &self,
        from_ms: i64,
        to_ms: i64,
        step_min: i64,
    ) -> anyhow::Result<Vec<MinutePoint>> {
        let step = step_min.max(1);
        let from = from_ms.div_euclid(60_000).div_euclid(step) * step;
        let to = to_ms.div_euclid(60_000);
        let mut st = self.conn.prepare_cached(
            "SELECT t, requests, blocked, dns, dns_blocked, bytes_up, bytes_down, alerts
             FROM minutes WHERE t >= ?1 AND t <= ?2 ORDER BY t",
        )?;
        let rows = st.query_map(params![from, to], |r| {
            Ok(MinutePoint {
                t: r.get(0)?,
                requests: u(r.get(1)?),
                blocked: u(r.get(2)?),
                dns: u(r.get(3)?),
                dns_blocked: u(r.get(4)?),
                bytes_up: u(r.get(5)?),
                bytes_down: u(r.get(6)?),
                alerts: u(r.get(7)?),
            })
        })?;
        let n = usize::try_from((to - from) / step + 1)
            .unwrap_or(0)
            .min(100_000);
        let mut out: Vec<MinutePoint> = (0..n)
            .map(|k| MinutePoint {
                t: from + i64::try_from(k).unwrap_or(0) * step,
                ..MinutePoint::default()
            })
            .collect();
        for row in rows {
            let m = row?;
            let k = usize::try_from((m.t - from) / step).unwrap_or(usize::MAX);
            if let Some(slot) = out.get_mut(k) {
                slot.add(&m);
            }
        }
        Ok(out)
    }

    /// Totaux et alertes par gravité sur une période.
    pub fn totals(&self, from_ms: i64, to_ms: i64) -> anyhow::Result<PeriodTotals> {
        let mut t = PeriodTotals::default();
        let (from, to) = (from_ms.div_euclid(60_000), to_ms.div_euclid(60_000));
        let row = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(requests),0), COALESCE(SUM(blocked),0), COALESCE(SUM(dns),0),
                        COALESCE(SUM(dns_blocked),0), COALESCE(SUM(bytes_up),0),
                        COALESCE(SUM(bytes_down),0), COALESCE(SUM(alerts),0)
                 FROM minutes WHERE t >= ?1 AND t <= ?2",
                params![from, to],
                |r| {
                    Ok(MinutePoint {
                        t: from,
                        requests: u(r.get(0)?),
                        blocked: u(r.get(1)?),
                        dns: u(r.get(2)?),
                        dns_blocked: u(r.get(3)?),
                        bytes_up: u(r.get(4)?),
                        bytes_down: u(r.get(5)?),
                        alerts: u(r.get(6)?),
                    })
                },
            )
            .optional()?;
        t.totals = row.unwrap_or_default();
        let mut st = self.conn.prepare_cached(
            "SELECT severity, COUNT(*) FROM alerts WHERE ts >= ?1 AND ts <= ?2 GROUP BY severity",
        )?;
        let rows = st.query_map(params![from_ms, to_ms], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (sev, n) = row?;
            if let Some(s) = Severity::parse(&sev) {
                t.alerts_by_severity[s.index()] += u(n);
            }
        }
        Ok(t)
    }

    /// Alertes les plus récentes (au plus `limit`), éventuellement depuis `since_ms`.
    pub fn alerts(&self, limit: usize, since_ms: Option<i64>) -> anyhow::Result<Vec<StoredAlert>> {
        let mut st = self.conn.prepare_cached(
            "SELECT id, ts, kind, severity, client, target, detail, score, rule, rule_name, user_agent
             FROM alerts WHERE ts >= ?1 ORDER BY ts DESC, id DESC LIMIT ?2",
        )?;
        let rows = st.query_map(
            params![
                since_ms.unwrap_or(0),
                i64::try_from(limit).unwrap_or(i64::MAX)
            ],
            |r| {
                let kind: String = r.get(2)?;
                let sev: String = r.get(3)?;
                Ok(StoredAlert {
                    id: r.get(0)?,
                    ts: r.get(1)?,
                    kind: AlertKind::parse(&kind).unwrap_or(AlertKind::Rule),
                    severity: Severity::parse(&sev).unwrap_or(Severity::Low),
                    client: r.get(4)?,
                    target: r.get(5)?,
                    detail: r.get(6)?,
                    score: r.get(7)?,
                    rule: r.get(8)?,
                    rule_name: r.get(9)?,
                    user_agent: r.get(10)?,
                })
            },
        )?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

/// Chemin de la base pour une configuration donnée.
pub fn path_for(cfg: &crate::config::HistoryConfig, paths: &crate::config::Paths) -> PathBuf {
    paths.history_file(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{now_ms, DnsEvent, HttpEvent, Scheme};

    fn http(ts: i64, blocked: bool) -> Event {
        Event::Http(HttpEvent {
            ts,
            client: "10.0.0.2".parse().unwrap(),
            method: "GET".into(),
            scheme: Scheme::Http,
            host: "example.com".into(),
            port: 80,
            path: None,
            status: 200,
            bytes_up: 100,
            bytes_down: 1000,
            duration_ms: 3,
            user_agent: None,
            content_type: None,
            action: if blocked {
                Action::Block
            } else {
                Action::Allow
            },
            reason: None,
            category: None,
        })
    }

    #[test]
    fn writes_aggregates_reads_and_purges() {
        let dir = std::env::temp_dir().join(format!("ferrox-hist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("h.sqlite3");
        let mut w = HistoryWriter::open(&path, 7).unwrap();
        let now = now_ms() / 60_000 * 60_000;
        w.record_event(&http(now, false));
        w.record_event(&http(now + 1000, true));
        w.record_event(&Event::Dns(DnsEvent {
            ts: now - 120_000,
            client: "10.0.0.2".parse().unwrap(),
            qname: "a.test".into(),
            qtype: "A".into(),
            rcode: "NOERROR".into(),
            answers: 1,
            latency_ms: 1,
            cached: false,
            action: Action::Allow,
            reason: None,
            category: None,
        }));
        w.record_alert(&Alert {
            id: 1,
            ts: now,
            severity: Severity::High,
            kind: AlertKind::Beacon,
            client: "10.0.0.2".parse().unwrap(),
            target: "example.com".into(),
            user_agent: None,
            detail: "balise".into(),
            score: 0.9,
            rule: None,
            rule_name: None,
        });
        w.flush().unwrap();
        // Deuxième écriture sur la même minute : les compteurs s'additionnent.
        w.record_event(&http(now + 2000, false));
        w.flush().unwrap();

        let r = HistoryReader::open(&path).unwrap();
        let s = r.series(now - 5 * 60_000, now, 1).unwrap();
        assert_eq!(s.len(), 6);
        let last = s.last().unwrap();
        assert_eq!((last.requests, last.blocked, last.alerts), (3, 1, 1));
        assert_eq!(s[3].dns, 1);
        let hourly = r.series(now - 3_600_000, now, 60).unwrap();
        assert_eq!(hourly.iter().map(|p| p.requests).sum::<u64>(), 3);
        let t = r.totals(now - 3_600_000, now + 60_000).unwrap();
        assert_eq!(t.totals.bytes_down, 3000);
        assert_eq!(t.alerts_by_severity, [0, 0, 1, 0]);
        let a = r.alerts(10, None).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].kind, AlertKind::Beacon);

        // Purge : tout est plus récent que 7 jours, rien ne part ; à +8 jours tout part.
        assert_eq!(w.purge(now).unwrap(), 0);
        assert!(w.purge(now + 8 * 86_400_000).unwrap() >= 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
