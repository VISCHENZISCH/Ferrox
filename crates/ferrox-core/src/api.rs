//! API locale en lecture seule (FP-18) et point `/metrics` Prometheus (FP-15).
//!
//! | Chemin                         | Contenu                                              |
//! |--------------------------------|------------------------------------------------------|
//! | `/api/v1/health`               | état, version, durée de fonctionnement               |
//! | `/api/v1/status`               | écouteurs, filtrage, règles                          |
//! | `/api/v1/snapshot`             | instantané (`recent`, `alerts`, `series`, `top`)     |
//! | `/api/v1/alerts?since=ID`      | alertes en mémoire d'identifiant supérieur à `ID`    |
//! | `/api/v1/history/series`       | agrégats (`hours`, `step` en minutes)                |
//! | `/api/v1/history/alerts`       | alertes conservées (`limit`, `since_ms`)             |
//! | `/metrics`                     | compteurs au format texte Prometheus                 |
//!
//! Accès limité aux réseaux autorisés, jeton `Authorization: Bearer …` facultatif.

use crate::access::{client_allowed, Cidr};
use crate::event::now_ms;
use crate::history::HistoryReader;
use crate::stats::{SnapshotOpts, Stats};
use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{self, HeaderValue};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;

/// Informations de fonctionnement mises à jour par le moteur.
#[derive(Serialize, Clone, Debug, Default)]
pub struct EngineInfo {
    pub version: String,
    pub listeners: Vec<(String, String)>,
    pub filter_domains: usize,
    pub filter_errors: Vec<String>,
    pub rules_loaded: usize,
    pub rules_error: Option<String>,
    pub rules_file: String,
    pub lists_updated_ms: Option<i64>,
    pub mitm: bool,
    pub ca_days_left: Option<i64>,
}

pub struct ApiCtx {
    pub stats: Arc<Stats>,
    pub history: Option<PathBuf>,
    pub info: Arc<ArcSwap<EngineInfo>>,
    pub allow: Vec<Cidr>,
    pub token: Option<String>,
}

type Body = Full<Bytes>;

fn reply(status: StatusCode, ctype: &'static str, body: impl Into<Bytes>) -> Response<Body> {
    let mut r = Response::new(Full::new(body.into()));
    *r.status_mut() = status;
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ctype));
    r.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    r.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    r
}

fn json<T: Serialize>(v: &T) -> Response<Body> {
    match serde_json::to_vec(v) {
        Ok(b) => reply(StatusCode::OK, "application/json", b),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    }
}

fn error(status: StatusCode, msg: &str) -> Response<Body> {
    let b = serde_json::json!({ "error": msg }).to_string();
    reply(status, "application/json", b)
}

fn query(req: &Request<Incoming>) -> HashMap<String, String> {
    req.uri()
        .query()
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            (!k.is_empty()).then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn num<T: std::str::FromStr>(q: &HashMap<String, String>, k: &str, default: T) -> T {
    q.get(k).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Comparaison en temps constant (longueurs comprises, à une fuite de longueur près).
fn token_ok(expected: &str, header: Option<&HeaderValue>) -> bool {
    let Some(given) = header
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    else {
        return false;
    };
    let (a, b) = (expected.as_bytes(), given.trim().as_bytes());
    let mut diff = u8::from(a.len() != b.len());
    for (i, x) in a.iter().enumerate() {
        diff |= x ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Texte Prometheus à partir des compteurs du moteur.
pub fn metrics_text(stats: &Stats, info: &EngineInfo) -> String {
    let s = stats.snapshot(SnapshotOpts {
        recent: 0,
        alerts: 0,
        series: 0,
        top: 0,
    });
    let t = s.totals;
    let mut o = String::with_capacity(4096);
    let mut metric = |name: &str, kind: &str, help: &str, rows: &[(&str, u64)]| {
        let _ = writeln!(o, "# HELP {name} {help}");
        let _ = writeln!(o, "# TYPE {name} {kind}");
        for (labels, v) in rows {
            if labels.is_empty() {
                let _ = writeln!(o, "{name} {v}");
            } else {
                let _ = writeln!(o, "{name}{{{labels}}} {v}");
            }
        }
    };
    metric(
        "ferrox_http_requests_total",
        "counter",
        "Requêtes web vues par le proxy.",
        &[("", t.requests)],
    );
    metric(
        "ferrox_http_blocked_total",
        "counter",
        "Requêtes web bloquées.",
        &[("", t.blocked)],
    );
    metric(
        "ferrox_dns_queries_total",
        "counter",
        "Requêtes DNS reçues.",
        &[("", t.dns_queries)],
    );
    metric(
        "ferrox_dns_blocked_total",
        "counter",
        "Requêtes DNS bloquées.",
        &[("", t.dns_blocked)],
    );
    metric(
        "ferrox_dns_cache_hits_total",
        "counter",
        "Réponses DNS servies par le cache.",
        &[("", t.dns_cached)],
    );
    metric(
        "ferrox_bytes_total",
        "counter",
        "Octets relayés par le proxy.",
        &[
            ("direction=\"up\"", t.live_bytes_up),
            ("direction=\"down\"", t.live_bytes_down),
        ],
    );
    metric(
        "ferrox_alerts_total",
        "counter",
        "Alertes produites.",
        &[("", t.alerts)],
    );
    let sev = s.alerts_by_severity;
    metric(
        "ferrox_alerts_by_severity_total",
        "counter",
        "Alertes par gravité.",
        &[
            ("severity=\"low\"", sev[0]),
            ("severity=\"medium\"", sev[1]),
            ("severity=\"high\"", sev[2]),
            ("severity=\"critical\"", sev[3]),
        ],
    );
    let kinds: Vec<(String, u64)> = s
        .alerts_by_kind
        .iter()
        .map(|(k, n)| (format!("kind=\"{}\"", k.as_str()), *n))
        .collect();
    let kinds: Vec<(&str, u64)> = kinds.iter().map(|(l, n)| (l.as_str(), *n)).collect();
    metric(
        "ferrox_alerts_by_kind_total",
        "counter",
        "Alertes par type.",
        &kinds,
    );
    metric(
        "ferrox_dropped_events_total",
        "counter",
        "Événements perdus (file pleine).",
        &[("", t.dropped_events)],
    );
    metric(
        "ferrox_active_connections",
        "gauge",
        "Connexions clientes ouvertes.",
        &[("", t.active_connections)],
    );
    metric(
        "ferrox_uptime_seconds",
        "gauge",
        "Durée de fonctionnement du moteur.",
        &[("", s.uptime_s)],
    );
    metric(
        "ferrox_filter_domains",
        "gauge",
        "Domaines chargés dans le filtrage.",
        &[("", info.filter_domains as u64)],
    );
    metric(
        "ferrox_rules_loaded",
        "gauge",
        "Règles de détection TOML actives.",
        &[("", info.rules_loaded as u64)],
    );
    let build = format!("version=\"{}\"", env!("CARGO_PKG_VERSION"));
    metric(
        "ferrox_build_info",
        "gauge",
        "Version de Ferrox.",
        &[(build.as_str(), 1)],
    );
    o
}

async fn route(req: Request<Incoming>, ctx: Arc<ApiCtx>) -> Response<Body> {
    if let Some(tok) = ctx.token.as_deref().filter(|t| !t.is_empty()) {
        if !token_ok(tok, req.headers().get(header::AUTHORIZATION)) {
            let mut r = error(StatusCode::UNAUTHORIZED, "jeton manquant ou invalide");
            r.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            return r;
        }
    }
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return error(
            StatusCode::METHOD_NOT_ALLOWED,
            "lecture seule : GET uniquement",
        );
    }
    let q = query(&req);
    match req.uri().path() {
        "/metrics" => reply(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            metrics_text(&ctx.stats, &ctx.info.load()),
        ),
        "/api/v1/health" | "/healthz" => json(&serde_json::json!({
            "status": "ok",
            "version": env!("CARGO_PKG_VERSION"),
            "uptime_s": ctx.stats.snapshot(SnapshotOpts { recent: 0, alerts: 0, series: 0, top: 0 }).uptime_s,
        })),
        "/api/v1/status" => json(&**ctx.info.load()),
        "/api/v1/snapshot" => json(&ctx.stats.snapshot(SnapshotOpts {
            recent: num(&q, "recent", 100usize).min(1500),
            alerts: num(&q, "alerts", 100usize).min(2000),
            series: num(&q, "series", 60usize).min(300),
            top: num(&q, "top", 10usize).min(100),
        })),
        "/api/v1/alerts" => json(&ctx.stats.alerts_since(num(&q, "since", 0u64))),
        p @ ("/api/v1/history/series" | "/api/v1/history/alerts") => {
            let Some(path) = ctx.history.clone() else {
                return error(StatusCode::NOT_FOUND, "historique désactivé");
            };
            let series = p.ends_with("series");
            let res = tokio::task::spawn_blocking(move || -> anyhow::Result<serde_json::Value> {
                let r = HistoryReader::open(&path)?;
                let now = now_ms();
                if series {
                    let hours: i64 = num(&q, "hours", 24i64).clamp(1, 24 * 400);
                    let step: i64 = num(&q, "step", 60i64).clamp(1, 1440);
                    Ok(serde_json::to_value(r.series(
                        now - hours * 3_600_000,
                        now,
                        step,
                    )?)?)
                } else {
                    let limit = num(&q, "limit", 100usize).min(10_000);
                    let since = q.get("since_ms").and_then(|v| v.parse().ok());
                    Ok(serde_json::to_value(r.alerts(limit, since)?)?)
                }
            })
            .await;
            match res {
                Ok(Ok(v)) => json(&v),
                Ok(Err(e)) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
                Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
            }
        }
        _ => error(StatusCode::NOT_FOUND, "chemin inconnu"),
    }
}

pub async fn run(listener: TcpListener, ctx: Arc<ApiCtx>) {
    loop {
        let Ok((stream, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        };
        if !client_allowed(peer.ip(), &ctx.allow) {
            continue;
        }
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let ctx = ctx.clone();
                async move { Ok::<_, Infallible>(route(req, ctx).await) }
            });
            let _ = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .serve_connection(TokioIo::new(stream), svc)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_check() {
        let h = HeaderValue::from_static("Bearer s3cret");
        assert!(token_ok("s3cret", Some(&h)));
        assert!(!token_ok("s3cret!", Some(&h)));
        assert!(!token_ok("s3cret", None));
        assert!(!token_ok(
            "s3cret",
            Some(&HeaderValue::from_static("Basic s3cret"))
        ));
    }

    #[test]
    fn metrics_are_well_formed() {
        let stats = Stats::new();
        let txt = metrics_text(&stats, &EngineInfo::default());
        assert!(txt.contains("# TYPE ferrox_http_requests_total counter"));
        assert!(txt.contains("ferrox_bytes_total{direction=\"up\"} 0"));
        for line in txt.lines().filter(|l| !l.starts_with('#')) {
            let (_, v) = line.rsplit_once(' ').unwrap();
            v.parse::<f64>().unwrap();
        }
    }
}
