//! Lecture et téléchargement des listes de blocage
//! (formats hosts, domaine seul, Adblock `||domaine^`).

use super::normalize_host;
use crate::config::{FilterConfig, Paths};
use crate::http_client::{self, HttpsClient};
use serde::Serialize;

pub fn safe_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn valid_domain(d: &str) -> bool {
    d.len() >= 3
        && d.len() <= 253
        && d.contains('.')
        && !d.starts_with('.')
        && d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
        && d.parse::<std::net::IpAddr>().is_err()
}

pub fn parse_list(text: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(text.len() / 24);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }
        let line = line.split('#').next().unwrap_or("").trim();
        let candidate = if let Some(rest) = line.strip_prefix("||") {
            // Adblock : on ne garde que les règles de domaine complètes.
            match rest.find(['^', '/', '$']) {
                Some(i) if rest.as_bytes()[i] == b'^' => &rest[..i],
                None => rest,
                _ => continue,
            }
        } else {
            let mut parts = line.split_whitespace();
            let first = parts.next().unwrap_or("");
            match parts.next() {
                // Format hosts : "0.0.0.0 domaine"
                Some(second) if first.parse::<std::net::IpAddr>().is_ok() => second,
                _ => first,
            }
        };
        // Lignes de type URL (http://hôte/chemin) : on garde l'hôte.
        let candidate = match candidate.split_once("://") {
            Some((_, rest)) => rest.split(['/', '?', '#']).next().unwrap_or(""),
            None => candidate,
        };
        let d = normalize_host(candidate.trim_start_matches("*."));
        if valid_domain(&d) && d != "localhost.localdomain" {
            out.push(d);
        }
    }
    out
}

#[derive(Serialize, Clone, Debug)]
pub struct UpdateResult {
    pub name: String,
    pub ok: bool,
    pub domains: usize,
    pub message: String,
}

const MAX_LIST_BYTES: usize = 64 * 1024 * 1024;

/// Télécharge les listes activées et les écrit dans le dossier de données.
pub async fn update_lists(cfg: &FilterConfig, paths: &Paths) -> Vec<UpdateResult> {
    crate::install_crypto_provider();
    let client: HttpsClient = http_client::build();
    let dir = paths.lists_dir();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return vec![UpdateResult {
            name: "*".into(),
            ok: false,
            domains: 0,
            message: format!("dossier {} : {e}", dir.display()),
        }];
    }
    let mut results = Vec::new();
    for src in cfg.lists.iter().filter(|s| s.enabled) {
        let r = match http_client::fetch(&client, &src.url, MAX_LIST_BYTES).await {
            Ok(body) => {
                let text = String::from_utf8_lossy(&body);
                let n = parse_list(&text).len();
                let path = dir.join(format!("{}.txt", safe_name(&src.name)));
                match tokio::fs::write(&path, &body).await {
                    Ok(()) => UpdateResult {
                        name: src.name.clone(),
                        ok: true,
                        domains: n,
                        message: format!("{n} domaines"),
                    },
                    Err(e) => UpdateResult {
                        name: src.name.clone(),
                        ok: false,
                        domains: 0,
                        message: format!("écriture : {e}"),
                    },
                }
            }
            Err(e) => UpdateResult {
                name: src.name.clone(),
                ok: false,
                domains: 0,
                message: e.to_string(),
            },
        };
        results.push(r);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formats() {
        let t = "# c\n0.0.0.0 bad.com\n127.0.0.1 localhost\nplain.org\n||ads.net^\n||x.com/path\n! adblock\n*.wild.io\n1.2.3.4\nhttp://Evil.example:8080/a/b.exe\n";
        let v = parse_list(t);
        assert_eq!(
            v,
            vec!["bad.com", "plain.org", "ads.net", "wild.io", "evil.example"]
        );
    }
}
