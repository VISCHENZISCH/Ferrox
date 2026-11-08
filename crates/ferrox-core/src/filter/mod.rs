//! Filtrage : domaines (listes, catégories, manuel), extensions, types MIME, signatures.
//!
//! La recherche d'un domaine parcourt ses suffixes (`a.b.c.com`, `b.c.com`, `c.com`)
//! dans une table de hachage : coût proportionnel au nombre de labels, sans verrou
//! grâce à `ArcSwap` (rechargement à chaud atomique).

pub mod lists;
pub mod magic;

use crate::config::{FilterConfig, Paths};
use arc_swap::ArcSwap;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SourceInfo {
    pub name: String,
    pub category: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockReason {
    pub reason: String,
    pub category: String,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct LoadReport {
    pub total_domains: usize,
    pub sources: Vec<SourceCount>,
    pub errors: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SourceCount {
    pub name: String,
    pub category: String,
    pub domains: usize,
}

#[derive(Default)]
pub struct FilterSet {
    domains: HashMap<Box<str>, u16>,
    sources: Vec<SourceInfo>,
    allow: HashSet<Box<str>>,
    extensions: HashSet<String>,
    mimes: Vec<String>,
    magic_kinds: HashSet<magic::Kind>,
}

/// Normalise un nom d'hôte : minuscules, sans point final ni port.
pub fn normalize_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('.');
    let h = if h.starts_with('[') {
        h.trim_start_matches('[').split(']').next().unwrap_or(h)
    } else if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
    } else {
        h
    };
    h.to_ascii_lowercase()
}

/// Itère sur le domaine puis ses suffixes parents.
fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    let mut rest = Some(host);
    std::iter::from_fn(move || {
        let cur = rest?;
        rest = cur
            .find('.')
            .map(|i| &cur[i + 1..])
            .filter(|s| !s.is_empty());
        Some(cur)
    })
}

impl FilterSet {
    pub fn build(cfg: &FilterConfig, paths: &Paths) -> (Self, LoadReport) {
        let mut set = FilterSet::default();
        let mut report = LoadReport::default();

        // Listes téléchargées (mises en cache sur disque).
        let lists_dir = paths.lists_dir();
        for src in cfg.lists.iter().filter(|s| s.enabled) {
            let file = lists_dir.join(format!("{}.txt", lists::safe_name(&src.name)));
            match std::fs::read_to_string(&file) {
                Ok(text) => {
                    let n = set.add_source(&src.name, &src.category, lists::parse_list(&text));
                    report.sources.push(SourceCount {
                        name: src.name.clone(),
                        category: src.category.clone(),
                        domains: n,
                    });
                }
                Err(_) => report.errors.push(format!(
                    "liste « {} » absente : lancez une mise à jour des listes",
                    src.name
                )),
            }
        }

        // Catégories UT1 : <dossier>/<catégorie>/domains
        let cat_dir = paths.categories_dir(cfg);
        for cat in &cfg.blocked_categories {
            let file = cat_dir.join(cat).join("domains");
            match std::fs::read_to_string(&file) {
                Ok(text) => {
                    let n = set.add_source(&format!("cat:{cat}"), cat, lists::parse_list(&text));
                    report.sources.push(SourceCount {
                        name: format!("cat:{cat}"),
                        category: cat.clone(),
                        domains: n,
                    });
                }
                Err(e) => report.errors.push(format!(
                    "catégorie « {cat} » illisible ({}) : {e}",
                    file.display()
                )),
            }
        }

        // Blocage manuel.
        let n = set.add_source(
            "manuel",
            "custom",
            cfg.custom_block.iter().map(|d| normalize_host(d)).collect(),
        );
        report.sources.push(SourceCount {
            name: "manuel".into(),
            category: "custom".into(),
            domains: n,
        });

        set.allow = cfg
            .allow
            .iter()
            .map(|d| normalize_host(d).into_boxed_str())
            .collect();
        set.extensions = cfg
            .blocked_extensions
            .iter()
            .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .collect();
        set.mimes = cfg
            .blocked_mime
            .iter()
            .map(|m| m.trim().to_ascii_lowercase())
            .filter(|m| !m.is_empty())
            .collect();
        if cfg.sniff_magic {
            set.magic_kinds = set
                .extensions
                .iter()
                .filter_map(|e| magic::kind_for_extension(e))
                .collect();
        }
        report.total_domains = set.domains.len();
        (set, report)
    }

    fn add_source(&mut self, name: &str, category: &str, domains: Vec<String>) -> usize {
        let idx = self.sources.len() as u16;
        self.sources.push(SourceInfo {
            name: name.to_string(),
            category: category.to_string(),
        });
        let mut n = 0;
        for d in domains {
            if d.is_empty() {
                continue;
            }
            // La première source qui déclare un domaine le garde.
            self.domains.entry(d.into_boxed_str()).or_insert_with(|| {
                n += 1;
                idx
            });
        }
        n
    }

    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Vérifie un nom d'hôte déjà normalisé.
    pub fn check_domain(&self, host: &str) -> Option<BlockReason> {
        if host.is_empty() {
            return None;
        }
        if suffixes(host).any(|s| self.allow.contains(s)) {
            return None;
        }
        for s in suffixes(host) {
            if let Some(&idx) = self.domains.get(s) {
                let src = &self.sources[idx as usize];
                return Some(BlockReason {
                    reason: format!("liste:{} ({s})", src.name),
                    category: src.category.clone(),
                });
            }
        }
        None
    }

    /// Vérifie l'extension du chemin d'URL (sans la query string).
    pub fn check_path(&self, path: &str) -> Option<BlockReason> {
        if self.extensions.is_empty() {
            return None;
        }
        let p = path.split(['?', '#']).next().unwrap_or(path);
        let file = p.rsplit('/').next().unwrap_or(p);
        let ext = file.rsplit_once('.')?.1.to_ascii_lowercase();
        self.extensions.contains(&ext).then(|| BlockReason {
            reason: format!("extension:.{ext}"),
            category: "filetype".into(),
        })
    }

    pub fn check_mime(&self, content_type: &str) -> Option<BlockReason> {
        let ct = content_type.to_ascii_lowercase();
        self.mimes
            .iter()
            .find(|m| ct.starts_with(m.as_str()))
            .map(|m| BlockReason {
                reason: format!("mime:{m}"),
                category: "filetype".into(),
            })
    }

    pub fn wants_sniff(&self) -> bool {
        !self.magic_kinds.is_empty()
    }

    pub fn check_magic(&self, head: &[u8]) -> Option<BlockReason> {
        let kind = magic::detect(head)?;
        self.magic_kinds.contains(&kind).then(|| BlockReason {
            reason: format!("signature:{}", kind.name()),
            category: "filetype".into(),
        })
    }
}

/// Filtre partagé, rechargeable à chaud.
pub struct Filter {
    set: ArcSwap<FilterSet>,
}

impl Filter {
    pub fn new(set: FilterSet) -> Self {
        Self {
            set: ArcSwap::from_pointee(set),
        }
    }

    #[inline]
    pub fn load(&self) -> arc_swap::Guard<Arc<FilterSet>> {
        self.set.load()
    }

    /// Instantané possédé (peut traverser des `await`).
    #[inline]
    pub fn current(&self) -> Arc<FilterSet> {
        self.set.load_full()
    }

    pub fn replace(&self, set: FilterSet) {
        self.set.store(Arc::new(set));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_with(domains: &[&str], allow: &[&str]) -> FilterSet {
        let mut s = FilterSet::default();
        s.add_source(
            "t",
            "malware",
            domains.iter().map(|d| d.to_string()).collect(),
        );
        s.allow = allow.iter().map(|d| (*d).into()).collect();
        s
    }

    #[test]
    fn suffix_match_blocks_subdomains() {
        let s = set_with(&["evil.com"], &[]);
        assert!(s.check_domain("evil.com").is_some());
        assert!(s.check_domain("a.b.evil.com").is_some());
        assert!(s.check_domain("notevil.com").is_none());
        assert!(s.check_domain("com").is_none());
    }

    #[test]
    fn allow_wins() {
        let s = set_with(&["evil.com"], &["ok.evil.com"]);
        assert!(s.check_domain("ok.evil.com").is_none());
        assert!(s.check_domain("x.ok.evil.com").is_none());
        assert!(s.check_domain("bad.evil.com").is_some());
    }

    #[test]
    fn extension_check() {
        let mut s = FilterSet::default();
        s.extensions.insert("exe".into());
        assert!(s.check_path("/dl/setup.EXE?x=1").is_some());
        assert!(s.check_path("/dl/setup.exe.html").is_none());
        assert!(s.check_path("/").is_none());
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_host("Example.COM."), "example.com");
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
    }
}
