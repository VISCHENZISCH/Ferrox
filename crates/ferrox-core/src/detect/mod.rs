//! Détection comportementale : balises C2, exfiltration, User-Agent, DNS (DGA, tunnel, NXDOMAIN),
//! et accès à des domaines malveillants connus.
//!
//! Le détecteur tourne sur le fil du pipeline : pas de verrou, état en mémoire borné
//! et purgé périodiquement.

use crate::config::DetectConfig;
use crate::event::{Action, Alert, AlertKind, DnsEvent, Event, HttpEvent, Scheme, Severity};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

const MB: f64 = 1024.0 * 1024.0;
const BEACON_HISTORY: usize = 24;

#[derive(Default)]
struct Beacon {
    ts: VecDeque<i64>,
    sizes: VecDeque<u64>,
}

#[derive(Default)]
struct PairBytes {
    up: u64,
    down: u64,
    first_ts: i64,
}

#[derive(Default)]
struct DnsWindow {
    start: i64,
    txt: u32,
    subs: HashSet<Box<str>>,
}

#[derive(Default)]
struct NxWindow {
    start: i64,
    total: u32,
    nx: u32,
}

#[derive(Default)]
pub struct Detector {
    next_id: u64,
    beacons: HashMap<(IpAddr, Box<str>), Beacon>,
    exfil_window: HashMap<IpAddr, (VecDeque<(i64, u64)>, u64)>,
    pairs: HashMap<(IpAddr, Box<str>), PairBytes>,
    ua_seen: HashMap<IpAddr, HashMap<Box<str>, i64>>,
    dns_win: HashMap<(IpAddr, Box<str>), DnsWindow>,
    nx_win: HashMap<IpAddr, NxWindow>,
    cooldown: HashMap<(AlertKind, IpAddr, Box<str>), i64>,
    last_prune: i64,
}

/// Domaine « enregistrable » approximatif (sans liste des suffixes publics).
pub fn registrable(host: &str) -> &str {
    let labels: Vec<&str> = host.split('.').collect();
    let n = labels.len();
    if n <= 2 {
        return host;
    }
    let tld = labels[n - 1];
    let sld = labels[n - 2];
    let take = if tld.len() == 2
        && matches!(
            sld,
            "co" | "com" | "net" | "org" | "gov" | "ac" | "edu" | "gouv" | "ne" | "or"
        ) {
        3
    } else {
        2
    };
    let skip: usize = labels[..n - take].iter().map(|l| l.len() + 1).sum();
    &host[skip..]
}

/// Entropie de Shannon en bits par caractère.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn mean_std(v: &[f64]) -> (f64, f64) {
    let n = v.len() as f64;
    let mean = v.iter().sum::<f64>() / n;
    let var = v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    (mean, var.sqrt())
}

fn human_bytes(b: f64) -> String {
    if b >= MB * 1024.0 {
        format!("{:.2} Go", b / MB / 1024.0)
    } else if b >= MB {
        format!("{:.1} Mo", b / MB)
    } else if b >= 1024.0 {
        format!("{:.0} Ko", b / 1024.0)
    } else {
        format!("{b:.0} o")
    }
}

/// Paramètres d'une alerte (remplace les dix arguments positionnels).
struct AlertSpec<'a> {
    ts: i64,
    cooldown_ms: i64,
    kind: AlertKind,
    severity: Severity,
    client: IpAddr,
    target: &'a str,
    /// User-Agent en cause, écrit dans `user_agent.original` (jamais dans le domaine).
    user_agent: Option<&'a str>,
    detail: String,
    score: f32,
}

impl Detector {
    pub fn new() -> Self {
        Self::default()
    }

    fn alert(&mut self, out: &mut Vec<Alert>, a: AlertSpec<'_>) {
        let AlertSpec {
            ts,
            cooldown_ms,
            kind,
            severity,
            client,
            target,
            user_agent,
            detail,
            score,
        } = a;
        // Le User-Agent fait partie de la clé : deux outils différents vers un même hôte
        // donnent deux alertes.
        let key_target = match user_agent {
            Some(ua) => format!("{target}\u{0}{ua}"),
            None => target.to_string(),
        };
        let key = (kind, client, Box::<str>::from(key_target));
        if let Some(&last) = self.cooldown.get(&key) {
            if ts - last < cooldown_ms {
                return;
            }
        }
        self.cooldown.insert(key, ts);
        self.next_id += 1;
        out.push(Alert {
            id: self.next_id,
            ts,
            severity,
            kind,
            client,
            target: target.to_string(),
            user_agent: user_agent.map(str::to_string),
            detail,
            score,
        });
    }

    pub fn ingest(&mut self, cfg: &DetectConfig, ev: &Event) -> Vec<Alert> {
        let mut out = Vec::new();
        match ev {
            Event::Http(e) => self.http(cfg, e, &mut out),
            Event::Dns(e) => self.dns(cfg, e, &mut out),
        }
        out
    }

    fn threat(
        &mut self,
        out: &mut Vec<Alert>,
        ts: i64,
        client: IpAddr,
        target: &str,
        category: &Option<String>,
        reason: &Option<String>,
    ) {
        let Some(cat) = category.as_deref() else {
            return;
        };
        let sev = match cat {
            "malware" | "c2" | "botnet" | "ransomware" => Severity::High,
            "phishing" | "cryptojacking" => Severity::Medium,
            _ => return,
        };
        self.alert(
            out,
            AlertSpec {
                ts,
                cooldown_ms: 10 * 60_000,
                kind: AlertKind::ThreatBlocked,
                severity: sev,
                client,
                target,
                user_agent: None,
                detail: format!(
                    "Accès à un domaine classé « {cat} » bloqué ({})",
                    reason.as_deref().unwrap_or("liste")
                ),
                score: 0.9,
            },
        );
    }

    fn http(&mut self, cfg: &DetectConfig, e: &HttpEvent, out: &mut Vec<Alert>) {
        if e.action == Action::Block {
            self.threat(out, e.ts, e.client, &e.host, &e.category, &e.reason);
            return;
        }
        if cfg.beacon.enabled {
            self.beacon(cfg, e, out);
        }
        if cfg.exfil.enabled {
            self.exfil(cfg, e, out);
        }
        if cfg.user_agent.enabled {
            self.user_agent(cfg, e, out);
        }
    }

    fn beacon(&mut self, cfg: &DetectConfig, e: &HttpEvent, out: &mut Vec<Alert>) {
        let bc = &cfg.beacon;
        let reg = registrable(&e.host);
        if bc
            .ignore
            .iter()
            .any(|d| e.host == *d || e.host.ends_with(&format!(".{d}")) || reg == d)
        {
            return;
        }
        let key = (e.client, Box::<str>::from(e.host.as_str()));
        let b = self.beacons.entry(key).or_default();
        // Les requêtes groupées d'un même contact (< 1 s) comptent pour un seul battement.
        if let Some(&last) = b.ts.back() {
            if e.ts - last < 1000 {
                if let Some(s) = b.sizes.back_mut() {
                    *s += e.bytes_up;
                }
                return;
            }
        }
        b.ts.push_back(e.ts);
        b.sizes.push_back(e.bytes_up);
        if b.ts.len() > BEACON_HISTORY {
            b.ts.pop_front();
            b.sizes.pop_front();
        }
        if b.ts.len() < bc.min_events.max(4) {
            return;
        }
        let mut iv: Vec<f64> =
            b.ts.iter()
                .zip(b.ts.iter().skip(1))
                .map(|(a, c)| (c - a) as f64 / 1000.0)
                .collect();
        // Tolère une absence ponctuelle (veille, coupure) : on retire le plus long intervalle.
        iv.sort_by(|a, c| a.partial_cmp(c).unwrap());
        iv.pop();
        let (mean, std) = mean_std(&iv);
        if mean < bc.min_interval_s || mean > bc.max_interval_s || mean <= 0.0 {
            return;
        }
        let cv = std / mean;
        if cv > bc.max_cv {
            return;
        }
        let sizes: Vec<f64> = b.sizes.iter().map(|&s| s as f64).collect();
        let (sm, ss) = mean_std(&sizes);
        let size_cv = if sm > 0.0 { ss / sm } else { 0.0 };
        let n = b.ts.len();
        let severity = if cv < 0.05 || size_cv < 0.1 {
            Severity::High
        } else {
            Severity::Medium
        };
        let score = (1.0 - cv / bc.max_cv.max(1e-6)).clamp(0.0, 1.0) as f32 * 0.7
            + (1.0 - size_cv.min(1.0)) as f32 * 0.3;
        self.alert(
            out,
            AlertSpec {
                ts: e.ts,
                cooldown_ms: 30 * 60_000,
                kind: AlertKind::Beacon,
                severity,
                client: e.client,
                target: &e.host,
                user_agent: None,
                detail: format!(
                "{n} contacts réguliers, intervalle moyen {mean:.1} s, gigue {:.1} %, taille moyenne {}",
                cv * 100.0,
                human_bytes(sm)
            ),
                score,
            },
        );
    }

    fn exfil(&mut self, cfg: &DetectConfig, e: &HttpEvent, out: &mut Vec<Alert>) {
        let xc = &cfg.exfil;
        let up = e.bytes_up as f64;
        if up >= xc.single_upload_mb * MB {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: 5 * 60_000,
                    kind: AlertKind::Exfiltration,
                    severity: Severity::High,
                    client: e.client,
                    target: &e.host,
                    user_agent: None,
                    detail: format!("Envoi unique de {} vers {}", human_bytes(up), e.host),
                    score: (up / (xc.single_upload_mb * MB) / 4.0).min(1.0) as f32,
                },
            );
        }

        // Fenêtre glissante par client.
        let window_ms = xc.window_s as i64 * 1000;
        let (win, sum) = self.exfil_window.entry(e.client).or_default();
        win.push_back((e.ts, e.bytes_up));
        *sum += e.bytes_up;
        while let Some(&(t, b)) = win.front() {
            if e.ts - t > window_ms {
                win.pop_front();
                *sum -= b;
            } else {
                break;
            }
        }
        let total = *sum as f64;
        if total >= xc.window_upload_mb * MB {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: window_ms,
                    kind: AlertKind::Exfiltration,
                    severity: Severity::High,
                    client: e.client,
                    target: "*",
                    user_agent: None,
                    detail: format!(
                        "{} envoyés en {} s par ce client",
                        human_bytes(total),
                        xc.window_s
                    ),
                    score: 0.8,
                },
            );
        }

        // Asymétrie envoi/réception vers un même domaine (10 minutes).
        let reg = registrable(&e.host).to_string();
        let p = self
            .pairs
            .entry((e.client, reg.clone().into_boxed_str()))
            .or_default();
        if e.ts - p.first_ts > 600_000 {
            *p = PairBytes {
                first_ts: e.ts,
                ..Default::default()
            };
        }
        p.up += e.bytes_up;
        p.down += e.bytes_down;
        let (pu, pd) = (p.up as f64, p.down as f64);
        if pu >= xc.ratio_min_mb * MB && pu > xc.ratio * pd.max(1.0) {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: 30 * 60_000,
                    kind: AlertKind::Exfiltration,
                    severity: Severity::Medium,
                    client: e.client,
                    target: &reg,
                    user_agent: None,
                    detail: format!(
                        "Trafic asymétrique : {} envoyés pour {} reçus (×{:.0})",
                        human_bytes(pu),
                        human_bytes(pd),
                        pu / pd.max(1.0)
                    ),
                    score: 0.6,
                },
            );
        }
    }

    fn user_agent(&mut self, cfg: &DetectConfig, e: &HttpEvent, out: &mut Vec<Alert>) {
        let uc = &cfg.user_agent;
        match e
            .user_agent
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
        {
            None => {
                if uc.alert_empty && e.scheme != Scheme::Tunnel {
                    self.alert(
                        out,
                        AlertSpec {
                            ts: e.ts,
                            cooldown_ms: 60 * 60_000,
                            kind: AlertKind::SuspiciousUserAgent,
                            severity: Severity::Low,
                            client: e.client,
                            target: &e.host,
                            user_agent: None,
                            detail: "Requête sans User-Agent".into(),
                            score: 0.3,
                        },
                    );
                }
            }
            Some(ua) => {
                let low = ua.to_ascii_lowercase();
                if let Some(m) = uc
                    .suspicious
                    .iter()
                    .find(|s| low.contains(&s.to_ascii_lowercase()))
                {
                    let sev = if ["nikto", "sqlmap", "nmap", "masscan", "zgrab"]
                        .iter()
                        .any(|t| low.contains(t))
                    {
                        Severity::High
                    } else {
                        Severity::Medium
                    };
                    self.alert(
                        out,
                        AlertSpec {
                            ts: e.ts,
                            cooldown_ms: 60 * 60_000,
                            kind: AlertKind::SuspiciousUserAgent,
                            severity: sev,
                            client: e.client,
                            target: &e.host,
                            user_agent: Some(ua),
                            detail: format!(
                                "User-Agent d'outil ou de script (« {m} ») vers {}",
                                e.host
                            ),
                            score: 0.5,
                        },
                    );
                }
                let seen = self.ua_seen.entry(e.client).or_default();
                seen.insert(ua.into(), e.ts);
                seen.retain(|_, t| e.ts - *t < 600_000);
                if seen.len() > uc.max_distinct {
                    let n = seen.len();
                    self.alert(
                        out,
                        AlertSpec {
                            ts: e.ts,
                            cooldown_ms: 30 * 60_000,
                            kind: AlertKind::SuspiciousUserAgent,
                            severity: Severity::Medium,
                            client: e.client,
                            target: "*",
                            user_agent: None,
                            detail: format!(
                                "{n} User-Agents différents en 10 minutes (rotation ou usurpation)"
                            ),
                            score: 0.5,
                        },
                    );
                }
            }
        }
    }

    fn dns(&mut self, cfg: &DetectConfig, e: &DnsEvent, out: &mut Vec<Alert>) {
        if e.action == Action::Block {
            self.threat(out, e.ts, e.client, &e.qname, &e.category, &e.reason);
        }
        let dc = &cfg.dns;
        if !dc.enabled || e.qname.is_empty() {
            return;
        }
        let reg = registrable(&e.qname).to_string();
        let sub = e
            .qname
            .strip_suffix(reg.as_str())
            .unwrap_or("")
            .trim_end_matches('.');

        // Noms très longs : encodage de données dans les sous-domaines.
        let longest = e.qname.split('.').map(str::len).max().unwrap_or(0);
        if e.qname.len() > dc.max_qname_len || longest > dc.max_label_len {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: 10 * 60_000,
                    kind: AlertKind::DnsTunnel,
                    severity: Severity::High,
                    client: e.client,
                    target: &reg,
                    user_agent: None,
                    detail: format!(
                        "Requête anormalement longue ({} caractères, label de {longest}) : {}",
                        e.qname.len(),
                        truncate(&e.qname, 80)
                    ),
                    score: 0.8,
                },
            );
        }

        // Domaine d'apparence aléatoire (algorithme de génération de domaines).
        let sld = reg.split('.').next().unwrap_or("");
        if sld.len() >= dc.min_label_len {
            let h = entropy(sld);
            let digits = sld.bytes().filter(u8::is_ascii_digit).count() as f64 / sld.len() as f64;
            let vowels =
                sld.bytes().filter(|b| b"aeiouy".contains(b)).count() as f64 / sld.len() as f64;
            if h >= dc.entropy_threshold && (digits > 0.15 || vowels < 0.25) {
                self.alert(
                    out,
                    AlertSpec {
                        ts: e.ts,
                        cooldown_ms: 30 * 60_000,
                        kind: AlertKind::DnsDga,
                        severity: Severity::Medium,
                        client: e.client,
                        target: &reg,
                        user_agent: None,
                        detail: format!("Nom d'apparence aléatoire (entropie {h:.2} bits/car.)"),
                        score: (h / 4.5).min(1.0) as f32,
                    },
                );
            }
        }

        // Fenêtre d'une minute par (client, domaine) : TXT et sous-domaines uniques.
        let w = self
            .dns_win
            .entry((e.client, reg.clone().into_boxed_str()))
            .or_default();
        if e.ts - w.start > 60_000 {
            *w = DnsWindow {
                start: e.ts,
                ..Default::default()
            };
        }
        if matches!(e.qtype.as_str(), "TXT" | "NULL" | "CNAME" | "MX") && !sub.is_empty() {
            w.txt += 1;
        }
        if !sub.is_empty() && w.subs.len() < 10_000 {
            w.subs.insert(sub.into());
        }
        let (txt, subs) = (w.txt, w.subs.len() as u32);
        if txt > dc.txt_per_min {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: 10 * 60_000,
                    kind: AlertKind::DnsTunnel,
                    severity: Severity::High,
                    client: e.client,
                    target: &reg,
                    user_agent: None,
                    detail: format!("{txt} requêtes TXT/CNAME/MX en une minute"),
                    score: 0.8,
                },
            );
        }
        if subs > dc.unique_sub_per_min {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: 10 * 60_000,
                    kind: AlertKind::DnsTunnel,
                    severity: Severity::High,
                    client: e.client,
                    target: &reg,
                    user_agent: None,
                    detail: format!("{subs} sous-domaines uniques en une minute"),
                    score: 0.85,
                },
            );
        }

        // Proportion de NXDOMAIN par client.
        let nx = self.nx_win.entry(e.client).or_default();
        if e.ts - nx.start > 60_000 {
            *nx = NxWindow {
                start: e.ts,
                ..Default::default()
            };
        }
        nx.total += 1;
        if e.rcode == "NXDOMAIN" && e.action == Action::Allow {
            nx.nx += 1;
        }
        let (t, n) = (nx.total, nx.nx);
        if n >= dc.nx_min && n as f64 / t as f64 >= dc.nx_ratio {
            self.alert(
                out,
                AlertSpec {
                    ts: e.ts,
                    cooldown_ms: 10 * 60_000,
                    kind: AlertKind::DnsNxStorm,
                    severity: Severity::High,
                    client: e.client,
                    target: "*",
                    user_agent: None,
                    detail: format!("{n} réponses NXDOMAIN sur {t} requêtes en une minute"),
                    score: 0.8,
                },
            );
        }
    }

    /// Purge l'état ancien pour borner la mémoire.
    pub fn prune(&mut self, cfg: &DetectConfig, now: i64) {
        if now - self.last_prune < 60_000 {
            return;
        }
        self.last_prune = now;
        let beacon_ttl = (cfg.beacon.max_interval_s * 2000.0) as i64;
        self.beacons
            .retain(|_, b| b.ts.back().is_some_and(|&t| now - t < beacon_ttl));
        let wms = cfg.exfil.window_s as i64 * 1000;
        self.exfil_window
            .retain(|_, (w, _)| w.back().is_some_and(|&(t, _)| now - t < wms));
        self.pairs.retain(|_, p| now - p.first_ts < 600_000);
        self.ua_seen.retain(|_, m| {
            m.retain(|_, t| now - *t < 600_000);
            !m.is_empty()
        });
        self.dns_win.retain(|_, w| now - w.start < 120_000);
        self.nx_win.retain(|_, w| now - w.start < 120_000);
        self.cooldown.retain(|_, t| now - *t < 3_600_000);
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..s.floor_char_boundary(n)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{now_ms, Scheme};

    fn http(ts: i64, host: &str, up: u64) -> Event {
        Event::Http(HttpEvent {
            ts,
            client: "10.0.0.5".parse().unwrap(),
            method: "GET".into(),
            scheme: Scheme::Https,
            host: host.into(),
            port: 443,
            path: Some("/".into()),
            status: 200,
            bytes_up: up,
            bytes_down: 500,
            duration_ms: 10,
            user_agent: Some("Mozilla/5.0".into()),
            content_type: None,
            action: Action::Allow,
            reason: None,
            category: None,
        })
    }

    fn dns(ts: i64, q: &str, qtype: &str, rcode: &str) -> Event {
        Event::Dns(DnsEvent {
            ts,
            client: "10.0.0.7".parse().unwrap(),
            qname: q.into(),
            qtype: qtype.into(),
            rcode: rcode.into(),
            answers: 0,
            latency_ms: 1,
            cached: false,
            action: Action::Allow,
            reason: None,
            category: None,
        })
    }

    #[test]
    fn registrable_domains() {
        assert_eq!(registrable("a.b.example.com"), "example.com");
        assert_eq!(registrable("x.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(registrable("example.com"), "example.com");
    }

    #[test]
    fn detects_regular_beacon() {
        let cfg = DetectConfig::default();
        let mut d = Detector::new();
        let t0 = now_ms();
        let mut alerts = vec![];
        for i in 0..12 {
            let jitter = if i % 2 == 0 { 300 } else { -300 };
            alerts.extend(d.ingest(&cfg, &http(t0 + i * 60_000 + jitter, "c2.evil.net", 420)));
        }
        assert!(
            alerts.iter().any(|a| a.kind == AlertKind::Beacon),
            "{alerts:?}"
        );
    }

    #[test]
    fn ignores_irregular_traffic() {
        let cfg = DetectConfig::default();
        let mut d = Detector::new();
        let t0 = now_ms();
        let gaps = [5, 90, 12, 300, 7, 45, 600, 20, 3, 150, 60, 9];
        let mut t = t0;
        let mut alerts = vec![];
        for g in gaps {
            t += g * 1000;
            alerts.extend(d.ingest(&cfg, &http(t, "news.example.com", 800)));
        }
        assert!(!alerts.iter().any(|a| a.kind == AlertKind::Beacon));
    }

    #[test]
    fn detects_big_upload() {
        let cfg = DetectConfig::default();
        let mut d = Detector::new();
        let a = d.ingest(&cfg, &http(now_ms(), "drop.example.org", 50 * 1024 * 1024));
        assert!(a.iter().any(|a| a.kind == AlertKind::Exfiltration));
    }

    #[test]
    fn detects_dns_tunnel_and_dga() {
        let cfg = DetectConfig::default();
        let mut d = Detector::new();
        let t0 = now_ms();
        let mut alerts = vec![];
        for i in 0..80 {
            let q = format!("{:x}{:x}.t.tunnel.example", i * 7919, i * 104729);
            alerts.extend(d.ingest(&cfg, &dns(t0 + i * 100, &q, "TXT", "NOERROR")));
        }
        assert!(alerts.iter().any(|a| a.kind == AlertKind::DnsTunnel));
        let a = d.ingest(&cfg, &dns(t0, "xk7q2vbz9pw4mj.com", "A", "NXDOMAIN"));
        assert!(a.iter().any(|a| a.kind == AlertKind::DnsDga), "{a:?}");
    }

    #[test]
    fn entropy_values() {
        assert!(entropy("aaaa") < 0.01);
        assert!(entropy("google") < 2.5);
        assert!(entropy("xk7q2vbz9pw4mj") > 3.5);
    }
}
