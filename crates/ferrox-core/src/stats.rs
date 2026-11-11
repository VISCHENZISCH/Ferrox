//! Agrégats temps réel pour l'interface : compteurs, série par seconde, classements,
//! derniers événements et alertes.

use crate::event::{now_ms, Action, Alert, AlertKind, DnsEvent, Event, HttpEvent, Severity};
use parking_lot::Mutex;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const SERIES_LEN: usize = 300;
const RECENT_LEN: usize = 1500;
const ALERTS_LEN: usize = 2000;
const MAP_MAX: usize = 50_000;

/// Horodatage le plus récent parmi le dixième le plus ancien des valeurs données :
/// les entrées dont `last_ts` est inférieur ou égal sont à retirer.
fn oldest_tenth_cutoff(mut ts: Vec<i64>) -> i64 {
    if ts.is_empty() {
        return i64::MIN;
    }
    let cut = (ts.len() / 10).min(ts.len() - 1);
    *ts.select_nth_unstable(cut).1
}

#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct Totals {
    pub requests: u64,
    pub blocked: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_cached: u64,
    pub alerts: u64,
    pub dropped_events: u64,
    pub active_connections: u64,
    /// Octets relayés depuis le démarrage, comptés au fil de l'eau (tunnels ouverts compris) :
    /// la différence entre deux instantanés donne le débit en temps réel.
    pub live_bytes_up: u64,
    pub live_bytes_down: u64,
}

#[derive(Serialize, Clone, Copy, Debug, Default)]
pub struct SeriesPoint {
    pub t: i64,
    pub requests: u32,
    pub blocked: u32,
    pub dns: u32,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub alerts: u32,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct DomainStat {
    pub domain: String,
    pub requests: u64,
    pub blocked: u64,
    pub bytes: u64,
    pub clients: u32,
    pub last_ts: i64,
}

#[derive(Serialize, Clone, Debug)]
pub struct ClientStat {
    pub client: IpAddr,
    pub requests: u64,
    pub dns: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub blocked: u64,
    pub alerts: u64,
    pub last_ts: i64,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Snapshot {
    pub seq: u64,
    pub uptime_s: u64,
    pub totals: Totals,
    pub series: Vec<SeriesPoint>,
    pub top_domains: Vec<DomainStat>,
    pub top_clients: Vec<ClientStat>,
    pub blocked_by_category: Vec<(String, u64)>,
    pub alerts_by_kind: Vec<(AlertKind, u64)>,
    pub alerts_by_severity: [u64; 4],
    pub recent_http: Vec<HttpEvent>,
    pub recent_dns: Vec<DnsEvent>,
    pub alerts: Vec<Alert>,
}

struct DomainAcc {
    requests: u64,
    blocked: u64,
    bytes: u64,
    clients: Vec<IpAddr>,
    last_ts: i64,
}

#[derive(Default)]
struct Inner {
    seq: u64,
    totals: Totals,
    series: VecDeque<SeriesPoint>,
    domains: HashMap<String, DomainAcc>,
    clients: HashMap<IpAddr, ClientStat>,
    categories: HashMap<String, u64>,
    alert_kinds: HashMap<AlertKind, u64>,
    severities: [u64; 4],
    recent_http: VecDeque<HttpEvent>,
    recent_dns: VecDeque<DnsEvent>,
    alerts: VecDeque<Alert>,
}

pub struct Stats {
    inner: Mutex<Inner>,
    pub active: Arc<AtomicU64>,
    pub dropped: Arc<AtomicU64>,
    /// Compteurs d'octets incrémentés par le proxy à chaque bloc relayé.
    pub live_up: Arc<AtomicU64>,
    pub live_down: Arc<AtomicU64>,
    started: std::time::Instant,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

/// Options de l'instantané : combien d'éléments récents copier.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotOpts {
    pub recent: usize,
    pub alerts: usize,
    pub series: usize,
    pub top: usize,
}

impl Default for SnapshotOpts {
    fn default() -> Self {
        Self {
            recent: 400,
            alerts: 500,
            series: 120,
            top: 12,
        }
    }
}

impl Stats {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            active: Arc::new(AtomicU64::new(0)),
            dropped: Arc::new(AtomicU64::new(0)),
            live_up: Arc::new(AtomicU64::new(0)),
            live_down: Arc::new(AtomicU64::new(0)),
            started: std::time::Instant::now(),
        }
    }

    fn bucket(inner: &mut Inner) -> &mut SeriesPoint {
        let t = now_ms() / 1000;
        if inner.series.back().map(|p| p.t) != Some(t) {
            inner.series.push_back(SeriesPoint {
                t,
                ..Default::default()
            });
            while inner.series.len() > SERIES_LEN {
                inner.series.pop_front();
            }
        }
        inner.series.back_mut().unwrap()
    }

    pub fn ingest(&self, ev: &Event) {
        let mut g = self.inner.lock();
        let inner = &mut *g;
        inner.seq += 1;
        match ev {
            Event::Http(e) => {
                let blocked = e.action == Action::Block;
                inner.totals.requests += 1;
                inner.totals.bytes_up += e.bytes_up;
                inner.totals.bytes_down += e.bytes_down;
                if blocked {
                    inner.totals.blocked += 1;
                    *inner
                        .categories
                        .entry(e.category.clone().unwrap_or_else(|| "autre".into()))
                        .or_default() += 1;
                }
                let b = Self::bucket(inner);
                b.requests += 1;
                b.bytes_up += e.bytes_up;
                b.bytes_down += e.bytes_down;
                if blocked {
                    b.blocked += 1;
                }
                Self::domain(
                    inner,
                    &e.host,
                    e.client,
                    e.ts,
                    blocked,
                    e.bytes_up + e.bytes_down,
                );
                let c = Self::client(inner, e.client);
                c.requests += 1;
                c.bytes_up += e.bytes_up;
                c.bytes_down += e.bytes_down;
                c.blocked += blocked as u64;
                c.last_ts = e.ts;
                inner.recent_http.push_back(e.clone());
                if inner.recent_http.len() > RECENT_LEN {
                    inner.recent_http.pop_front();
                }
            }
            Event::Dns(e) => {
                let blocked = e.action == Action::Block;
                inner.totals.dns_queries += 1;
                inner.totals.dns_cached += e.cached as u64;
                if blocked {
                    inner.totals.dns_blocked += 1;
                    *inner
                        .categories
                        .entry(e.category.clone().unwrap_or_else(|| "autre".into()))
                        .or_default() += 1;
                }
                let b = Self::bucket(inner);
                b.dns += 1;
                if blocked {
                    b.blocked += 1;
                }
                if blocked {
                    Self::domain(inner, &e.qname, e.client, e.ts, true, 0);
                }
                let c = Self::client(inner, e.client);
                c.dns += 1;
                c.blocked += blocked as u64;
                c.last_ts = e.ts;
                inner.recent_dns.push_back(e.clone());
                if inner.recent_dns.len() > RECENT_LEN {
                    inner.recent_dns.pop_front();
                }
            }
        }
    }

    fn domain(inner: &mut Inner, host: &str, client: IpAddr, ts: i64, blocked: bool, bytes: u64) {
        if inner.domains.len() >= MAP_MAX && !inner.domains.contains_key(host) {
            // Élimine les domaines vus une seule fois pour borner la mémoire,
            // puis, si cela ne suffit pas, le dixième le plus ancien.
            inner.domains.retain(|_, d| d.requests > 1);
            if inner.domains.len() >= MAP_MAX {
                let limit =
                    oldest_tenth_cutoff(inner.domains.values().map(|d| d.last_ts).collect());
                inner.domains.retain(|_, d| d.last_ts > limit);
            }
        }
        let d = inner.domains.entry(host.to_string()).or_insert(DomainAcc {
            requests: 0,
            blocked: 0,
            bytes: 0,
            clients: Vec::new(),
            last_ts: ts,
        });
        d.requests += 1;
        d.blocked += blocked as u64;
        d.bytes += bytes;
        d.last_ts = ts;
        if d.clients.len() < 64 && !d.clients.contains(&client) {
            d.clients.push(client);
        }
    }

    fn client(inner: &mut Inner, ip: IpAddr) -> &mut ClientStat {
        if inner.clients.len() >= MAP_MAX && !inner.clients.contains_key(&ip) {
            // Table bornée : le dixième le plus ancien est retiré, en temps linéaire.
            let limit = oldest_tenth_cutoff(inner.clients.values().map(|c| c.last_ts).collect());
            inner.clients.retain(|_, c| c.last_ts > limit);
        }
        inner.clients.entry(ip).or_insert(ClientStat {
            client: ip,
            requests: 0,
            dns: 0,
            bytes_up: 0,
            bytes_down: 0,
            blocked: 0,
            alerts: 0,
            last_ts: 0,
        })
    }

    pub fn add_alert(&self, a: &Alert) {
        let mut g = self.inner.lock();
        let inner = &mut *g;
        inner.seq += 1;
        inner.totals.alerts += 1;
        *inner.alert_kinds.entry(a.kind).or_default() += 1;
        inner.severities[match a.severity {
            Severity::Low => 0,
            Severity::Medium => 1,
            Severity::High => 2,
            Severity::Critical => 3,
        }] += 1;
        Self::bucket(inner).alerts += 1;
        Self::client(inner, a.client).alerts += 1;
        inner.alerts.push_back(a.clone());
        if inner.alerts.len() > ALERTS_LEN {
            inner.alerts.pop_front();
        }
    }

    /// Alertes d'identifiant strictement supérieur à `after` (dans l'ordre), sans plafond
    /// autre que l'historique conservé : aucune alerte n'est sautée en rafale.
    pub fn alerts_since(&self, after: u64) -> Vec<Alert> {
        let g = self.inner.lock();
        let start = g.alerts.partition_point(|a| a.id <= after);
        g.alerts.range(start..).cloned().collect()
    }

    pub fn seq(&self) -> u64 {
        self.inner.lock().seq
    }

    pub fn snapshot(&self, opts: SnapshotOpts) -> Snapshot {
        let g = self.inner.lock();
        let mut totals = g.totals;
        totals.active_connections = self.active.load(Ordering::Relaxed);
        totals.dropped_events = self.dropped.load(Ordering::Relaxed);
        totals.live_bytes_up = self.live_up.load(Ordering::Relaxed);
        totals.live_bytes_down = self.live_down.load(Ordering::Relaxed);

        // Série continue : secondes manquantes remplies de zéros.
        let now = now_ms() / 1000;
        let from = now - opts.series as i64 + 1;
        let mut series = Vec::with_capacity(opts.series);
        let mut it = g.series.iter().filter(|p| p.t >= from).peekable();
        for t in from..=now {
            match it.peek() {
                Some(p) if p.t == t => {
                    series.push(**p);
                    it.next();
                }
                _ => series.push(SeriesPoint {
                    t,
                    ..Default::default()
                }),
            }
        }

        let mut top_domains: Vec<DomainStat> = g
            .domains
            .iter()
            .map(|(k, d)| DomainStat {
                domain: k.clone(),
                requests: d.requests,
                blocked: d.blocked,
                bytes: d.bytes,
                clients: d.clients.len() as u32,
                last_ts: d.last_ts,
            })
            .collect();
        top_domains.sort_unstable_by_key(|d| std::cmp::Reverse(d.requests));
        top_domains.truncate(opts.top);

        let mut top_clients: Vec<ClientStat> = g.clients.values().cloned().collect();
        top_clients.sort_unstable_by(|a, b| {
            (b.bytes_up + b.bytes_down + b.dns).cmp(&(a.bytes_up + a.bytes_down + a.dns))
        });
        top_clients.truncate(opts.top);

        let mut cats: Vec<(String, u64)> =
            g.categories.iter().map(|(k, v)| (k.clone(), *v)).collect();
        cats.sort_unstable_by_key(|c| std::cmp::Reverse(c.1));
        let mut kinds: Vec<(AlertKind, u64)> =
            g.alert_kinds.iter().map(|(k, v)| (*k, *v)).collect();
        kinds.sort_unstable_by_key(|k| std::cmp::Reverse(k.1));

        let tail = |len: usize, n: usize| len.saturating_sub(n);
        Snapshot {
            seq: g.seq,
            uptime_s: self.started.elapsed().as_secs(),
            totals,
            series,
            top_domains,
            top_clients,
            blocked_by_category: cats,
            alerts_by_kind: kinds,
            alerts_by_severity: g.severities,
            recent_http: g
                .recent_http
                .iter()
                .skip(tail(g.recent_http.len(), opts.recent))
                .cloned()
                .collect(),
            recent_dns: g
                .recent_dns
                .iter()
                .skip(tail(g.recent_dns.len(), opts.recent))
                .cloned()
                .collect(),
            alerts: g
                .alerts
                .iter()
                .skip(tail(g.alerts.len(), opts.alerts))
                .cloned()
                .collect(),
        }
    }
}

#[cfg(test)]
mod bound_tests {
    use super::oldest_tenth_cutoff;

    #[test]
    fn cutoff_removes_about_a_tenth() {
        let ts: Vec<i64> = (0..100).collect();
        let limit = oldest_tenth_cutoff(ts.clone());
        let kept = ts.iter().filter(|&&t| t > limit).count();
        assert!((85..=90).contains(&kept), "{kept}");
        // Toutes égales : tout est retiré, la table repart de zéro plutôt que de grossir.
        assert_eq!(oldest_tenth_cutoff(vec![5; 10]), 5);
        assert_eq!(oldest_tenth_cutoff(vec![]), i64::MIN);
    }
}
