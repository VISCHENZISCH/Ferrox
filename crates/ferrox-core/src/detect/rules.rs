//! Règles de détection décrites en TOML, rechargées à chaud.
//!
//! ```toml
//! [[rule]]
//! id = "powershell-download"
//! name = "Script téléchargé par PowerShell"
//! severity = "high"            # low, medium, high, critical
//! source = "http"              # http, dns ou any
//! cooldown_s = 600             # silence après une alerte, par client et règle
//! [rule.match]
//! user_agent = ["*powershell*"]
//! path = ["*.ps1", "*.psm1"]
//! [rule.threshold]             # facultatif : N événements dans une fenêtre
//! count = 3
//! window_s = 60
//! group_by = "client"          # client (défaut), client_host ou host
//! distinct = "host"            # facultatif : compte des valeurs distinctes
//! ```
//!
//! Toutes les conditions présentes doivent être vraies ; dans une liste, une seule valeur
//! suffit. Les motifs acceptent `*` et `?` et ignorent la casse ; un motif de domaine sans
//! joker couvre aussi les sous-domaines (`example.com` couvre `a.example.com`).

use crate::access::Cidr;
use crate::event::{Action, Event, Severity};
use serde::Deserialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::Path;

#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    Http,
    Dns,
    #[default]
    Any,
}

#[derive(Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    #[default]
    Client,
    ClientHost,
    Host,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Distinct {
    Host,
    Path,
    Qname,
    UserAgent,
}

#[derive(Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MatchAction {
    Allow,
    Block,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Match {
    #[serde(default)]
    pub host: Vec<String>,
    #[serde(default)]
    pub path: Vec<String>,
    #[serde(default)]
    pub user_agent: Vec<String>,
    #[serde(default)]
    pub method: Vec<String>,
    #[serde(default)]
    pub port: Vec<u16>,
    #[serde(default)]
    pub status: Vec<u16>,
    #[serde(default)]
    pub qtype: Vec<String>,
    #[serde(default)]
    pub rcode: Vec<String>,
    #[serde(default)]
    pub category: Vec<String>,
    #[serde(default)]
    pub client: Vec<String>,
    pub action: Option<MatchAction>,
    pub min_bytes_up: Option<u64>,
    pub min_bytes_down: Option<u64>,
    pub min_qname_len: Option<usize>,
}

#[derive(Deserialize, Clone, Copy, Debug)]
#[serde(deny_unknown_fields)]
pub struct Threshold {
    pub count: u32,
    pub window_s: u64,
    #[serde(default)]
    pub group_by: GroupBy,
    pub distinct: Option<Distinct>,
}

#[derive(Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RuleDef {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub severity: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub source: Source,
    #[serde(default = "default_cooldown")]
    pub cooldown_s: u64,
    #[serde(rename = "match", default)]
    pub matches: Match,
    pub threshold: Option<Threshold>,
}

fn yes() -> bool {
    true
}
fn default_cooldown() -> u64 {
    600
}

#[derive(Deserialize, Debug, Default)]
#[serde(deny_unknown_fields)]
struct RulesFile {
    #[serde(default)]
    rule: Vec<RuleDef>,
}

/// Règle validée, motifs prêts à l'emploi.
#[derive(Debug, Clone)]
pub struct Rule {
    pub def: RuleDef,
    pub severity: Severity,
    clients: Vec<Cidr>,
    lower: LowerMatch,
}

#[derive(Debug, Clone, Default)]
struct LowerMatch {
    host: Vec<String>,
    path: Vec<String>,
    user_agent: Vec<String>,
    method: Vec<String>,
    qtype: Vec<String>,
    rcode: Vec<String>,
    category: Vec<String>,
}

fn lower(v: &[String]) -> Vec<String> {
    v.iter().map(|s| s.trim().to_ascii_lowercase()).collect()
}

/// Ensemble de règles chargé d'un fichier.
#[derive(Debug, Default, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: RulesFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut ids = HashSet::new();
        let mut rules = Vec::with_capacity(file.rule.len());
        for def in file.rule {
            let at = |m: String| format!("règle « {} » : {m}", def.id);
            if def.id.trim().is_empty() {
                return Err("règle sans identifiant (id)".into());
            }
            if !ids.insert(def.id.clone()) {
                return Err(at("identifiant en double".into()));
            }
            let severity = Severity::parse(&def.severity)
                .ok_or_else(|| at(format!("gravité inconnue « {} »", def.severity)))?;
            let m = &def.matches;
            let any_condition = !(m.host.is_empty()
                && m.path.is_empty()
                && m.user_agent.is_empty()
                && m.method.is_empty()
                && m.port.is_empty()
                && m.status.is_empty()
                && m.qtype.is_empty()
                && m.rcode.is_empty()
                && m.category.is_empty()
                && m.client.is_empty()
                && m.action.is_none()
                && m.min_bytes_up.is_none()
                && m.min_bytes_down.is_none()
                && m.min_qname_len.is_none());
            if !any_condition && def.threshold.is_none() {
                return Err(at(
                    "aucune condition : la règle se déclencherait sur tout".into()
                ));
            }
            if let Some(t) = def.threshold {
                if t.count == 0 || t.window_s == 0 {
                    return Err(at("threshold : count et window_s doivent être > 0".into()));
                }
            }
            let mut clients = Vec::new();
            for c in &m.client {
                clients.push(Cidr::parse(c).ok_or_else(|| at(format!("réseau invalide « {c} »")))?);
            }
            let lower = LowerMatch {
                host: lower(&m.host),
                path: lower(&m.path),
                user_agent: lower(&m.user_agent),
                method: lower(&m.method),
                qtype: lower(&m.qtype),
                rcode: lower(&m.rcode),
                category: lower(&m.category),
            };
            rules.push(Rule {
                def,
                severity,
                clients,
                lower,
            });
        }
        Ok(Self { rules })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text)
    }

    pub fn enabled(&self) -> usize {
        self.rules.iter().filter(|r| r.def.enabled).count()
    }
}

/// Motif à jokers `*` et `?`, sans distinction de casse (le texte est déjà en minuscules).
pub fn glob(pat: &str, text: &str) -> bool {
    let (p, t) = (pat.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

fn host_match(pat: &str, host: &str) -> bool {
    if pat.contains(['*', '?']) {
        glob(pat, host)
    } else {
        host == pat
            || (host.len() > pat.len()
                && host.ends_with(pat)
                && host.as_bytes()[host.len() - pat.len() - 1] == b'.')
    }
}

fn any_glob(pats: &[String], v: Option<&str>) -> bool {
    pats.is_empty()
        || v.is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            pats.iter().any(|p| glob(p, &v))
        })
}

fn any_eq(pats: &[String], v: &str) -> bool {
    pats.is_empty() || pats.iter().any(|p| p.eq_ignore_ascii_case(v))
}

/// Vue commune d'un événement web ou DNS pour l'évaluation des règles.
struct View<'a> {
    client: IpAddr,
    host: &'a str,
    path: Option<&'a str>,
    user_agent: Option<&'a str>,
    method: Option<&'a str>,
    port: Option<u16>,
    status: Option<u16>,
    qtype: Option<&'a str>,
    rcode: Option<&'a str>,
    category: Option<&'a str>,
    action: Action,
    bytes_up: u64,
    bytes_down: u64,
    ts: i64,
}

impl<'a> View<'a> {
    fn of(ev: &'a Event) -> Self {
        match ev {
            Event::Http(e) => View {
                client: e.client,
                host: &e.host,
                path: e.path.as_deref(),
                user_agent: e.user_agent.as_deref(),
                method: Some(&e.method),
                port: Some(e.port),
                status: Some(e.status),
                qtype: None,
                rcode: None,
                category: e.category.as_deref(),
                action: e.action,
                bytes_up: e.bytes_up,
                bytes_down: e.bytes_down,
                ts: e.ts,
            },
            Event::Dns(e) => View {
                client: e.client,
                host: &e.qname,
                path: None,
                user_agent: None,
                method: None,
                port: None,
                status: None,
                qtype: Some(&e.qtype),
                rcode: Some(&e.rcode),
                category: e.category.as_deref(),
                action: e.action,
                bytes_up: 0,
                bytes_down: 0,
                ts: e.ts,
            },
        }
    }
}

impl Rule {
    fn matches(&self, ev: &Event, v: &View<'_>) -> bool {
        let d = &self.def;
        let m = &d.matches;
        let l = &self.lower;
        let src_ok = match d.source {
            Source::Any => true,
            Source::Http => matches!(ev, Event::Http(_)),
            Source::Dns => matches!(ev, Event::Dns(_)),
        };
        src_ok
            && (l.host.is_empty() || l.host.iter().any(|p| host_match(p, v.host)))
            && any_glob(&l.path, v.path)
            && any_glob(&l.user_agent, v.user_agent)
            && (l.method.is_empty() || v.method.is_some_and(|x| any_eq(&l.method, x)))
            && (m.port.is_empty() || v.port.is_some_and(|p| m.port.contains(&p)))
            && (m.status.is_empty() || v.status.is_some_and(|s| m.status.contains(&s)))
            && (l.qtype.is_empty() || v.qtype.is_some_and(|x| any_eq(&l.qtype, x)))
            && (l.rcode.is_empty() || v.rcode.is_some_and(|x| any_eq(&l.rcode, x)))
            && (l.category.is_empty() || v.category.is_some_and(|x| any_eq(&l.category, x)))
            && (self.clients.is_empty() || self.clients.iter().any(|c| c.contains(v.client)))
            && m.action
                .is_none_or(|a| (a == MatchAction::Block) == (v.action == Action::Block))
            && m.min_bytes_up.is_none_or(|b| v.bytes_up >= b)
            && m.min_bytes_down.is_none_or(|b| v.bytes_down >= b)
            && m.min_qname_len
                .is_none_or(|n| v.qtype.is_some() && v.host.len() >= n)
    }
}

/// Déclenchement d'une règle, à transformer en alerte par le détecteur.
#[derive(Debug, Clone)]
pub struct Hit {
    pub rule_idx: usize,
    pub client: IpAddr,
    pub target: String,
    pub user_agent: Option<String>,
    pub detail: String,
    pub ts: i64,
}

/// Événements récents d'une fenêtre : (horodatage, empreinte de la valeur comptée).
type Window = VecDeque<(i64, u64)>;

/// État des fenêtres de seuil.
#[derive(Default)]
pub struct RuleState {
    windows: HashMap<(usize, Box<str>), Window>,
}

fn fx(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl RuleState {
    /// Évalue toutes les règles actives sur un événement.
    pub fn eval(&mut self, set: &RuleSet, ev: &Event) -> Vec<Hit> {
        let v = View::of(ev);
        let mut hits = Vec::new();
        for (idx, r) in set.rules.iter().enumerate() {
            if !r.def.enabled || !r.matches(ev, &v) {
                continue;
            }
            let target = v.host.to_string();
            let Some(t) = r.def.threshold else {
                hits.push(Hit {
                    rule_idx: idx,
                    client: v.client,
                    target,
                    user_agent: v.user_agent.map(str::to_string),
                    detail: if r.def.description.is_empty() {
                        r.def.name.clone()
                    } else {
                        r.def.description.clone()
                    },
                    ts: v.ts,
                });
                continue;
            };
            let key: Box<str> = match t.group_by {
                GroupBy::Client => v.client.to_string().into(),
                GroupBy::ClientHost => format!("{}|{}", v.client, v.host).into(),
                GroupBy::Host => v.host.into(),
            };
            let tag = match t.distinct {
                None => 0,
                Some(Distinct::Host | Distinct::Qname) => fx(v.host),
                Some(Distinct::Path) => fx(v.path.unwrap_or("")),
                Some(Distinct::UserAgent) => fx(v.user_agent.unwrap_or("")),
            };
            let win = self.windows.entry((idx, key)).or_default();
            let from = v.ts - i64::try_from(t.window_s.saturating_mul(1000)).unwrap_or(i64::MAX);
            while win.front().is_some_and(|x| x.0 < from) {
                win.pop_front();
            }
            win.push_back((v.ts, tag));
            // Borne mémoire : une fenêtre ne garde jamais plus que nécessaire.
            let cap = (t.count as usize).saturating_mul(4).max(64);
            while win.len() > cap {
                win.pop_front();
            }
            let n = if t.distinct.is_some() {
                win.iter().map(|x| x.1).collect::<HashSet<_>>().len()
            } else {
                win.len()
            };
            if n >= t.count as usize {
                let what = if t.distinct.is_some() {
                    "valeurs distinctes"
                } else {
                    "événements"
                };
                let base = if r.def.description.is_empty() {
                    r.def.name.clone()
                } else {
                    r.def.description.clone()
                };
                hits.push(Hit {
                    rule_idx: idx,
                    client: v.client,
                    target: if t.group_by == GroupBy::Client {
                        "*".into()
                    } else {
                        target
                    },
                    user_agent: None,
                    detail: format!("{base} : {n} {what} en {} s", t.window_s),
                    ts: v.ts,
                });
                win.clear();
            }
        }
        hits
    }

    /// Retire les fenêtres inactives.
    pub fn prune(&mut self, now: i64, max_window_ms: i64) {
        self.windows
            .retain(|_, w| w.back().is_some_and(|x| now - x.0 <= max_window_ms));
    }

    pub fn reset(&mut self) {
        self.windows.clear();
    }
}

/// Exemple de fichier de règles, écrit à la création si aucun n'existe.
pub const EXAMPLE: &str = include_str!("../../../../config/rules.example.toml");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{HttpEvent, Scheme};

    fn http(ts: i64, host: &str, path: &str, ua: &str) -> Event {
        Event::Http(HttpEvent {
            ts,
            client: "10.0.0.5".parse().unwrap(),
            method: "GET".into(),
            scheme: Scheme::Http,
            host: host.into(),
            port: 80,
            path: Some(path.into()),
            status: 200,
            bytes_up: 10,
            bytes_down: 10,
            duration_ms: 1,
            user_agent: Some(ua.into()),
            content_type: None,
            action: Action::Allow,
            reason: None,
            category: None,
        })
    }

    #[test]
    fn globbing() {
        assert!(glob("*.ps1", "/a/b/run.ps1"));
        assert!(glob("*powershell*", "mozilla/5.0 windowspowershell/5.1"));
        assert!(glob("a?c", "abc"));
        assert!(!glob("a?c", "abbc"));
        assert!(glob("*", ""));
        assert!(host_match("example.com", "a.example.com"));
        assert!(!host_match("example.com", "badexample.com"));
        assert!(host_match("*.ru", "x.y.ru"));
    }

    #[test]
    fn simple_and_threshold_rules() {
        let set = RuleSet::parse(
            r#"
            [[rule]]
            id = "ps"
            name = "PowerShell"
            severity = "high"
            source = "http"
            [rule.match]
            user_agent = ["*PowerShell*"]
            path = ["*.ps1"]

            [[rule]]
            id = "scan"
            name = "Balayage"
            severity = "medium"
            [rule.match]
            client = ["10.0.0.0/8"]
            [rule.threshold]
            count = 3
            window_s = 60
            distinct = "host"
            "#,
        )
        .unwrap();
        assert_eq!(set.enabled(), 2);
        let mut st = RuleState::default();
        let hits = st.eval(
            &set,
            &http(1000, "a.test", "/x.ps1", "WindowsPowerShell/5.1"),
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_idx, 0);
        // Même hôte répété : pas de valeurs distinctes suffisantes.
        assert!(st.eval(&set, &http(1100, "a.test", "/", "x")).is_empty());
        assert!(st.eval(&set, &http(1200, "b.test", "/", "x")).is_empty());
        let hits = st.eval(&set, &http(1300, "c.test", "/", "x"));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule_idx, 1);
        assert!(hits[0].detail.contains("3 valeurs distinctes"));
    }

    #[test]
    fn rejects_bad_files() {
        assert!(RuleSet::parse(
            "[[rule]]\nid=\"a\"\nname=\"a\"\nseverity=\"énorme\"\n[rule.match]\nport=[1]"
        )
        .is_err());
        assert!(RuleSet::parse("[[rule]]\nid=\"a\"\nname=\"a\"\nseverity=\"low\"").is_err());
        assert!(RuleSet::parse(
            "[[rule]]\nid=\"a\"\nname=\"a\"\nseverity=\"low\"\n[rule.match]\nhots=[\"x\"]"
        )
        .is_err());
        assert!(
            RuleSet::parse(EXAMPLE).is_ok(),
            "{:?}",
            RuleSet::parse(EXAMPLE).err()
        );
    }
}
