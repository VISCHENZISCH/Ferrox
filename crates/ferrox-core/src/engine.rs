//! Orchestration : démarre les écouteurs (proxy, DNS), le pipeline
//! (statistiques, détection, journaux) et expose un instantané pour l'interface.

use crate::access::{parse_allow, BasicAuth, BypassCache, Cidr};
use crate::api::{ApiCtx, EngineInfo};
use crate::config::{Config, DetectConfig, FilterConfig, Paths};
use crate::detect::rules::RuleSet;
use crate::detect::Detector;
use crate::dns::{self, DnsCtx};
use crate::event::{now_ms, Event, EventSink};
use crate::filter::{Filter, FilterSet, LoadReport};
use crate::history::HistoryWriter;
use crate::logger::LogPolicy;
use crate::logger::Logger;
use crate::proxy::{self, ProxyCtx};
use crate::stats::{Snapshot, SnapshotOpts, Stats};
use crate::tls::CertAuthority;
use arc_swap::ArcSwap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, RecvTimeoutError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, UdpSocket};

const QUEUE: usize = 131_072;

pub struct Engine {
    rt: Option<tokio::runtime::Runtime>,
    stop: Arc<AtomicBool>,
    pipeline: Option<JoinHandle<()>>,
    stats: Arc<Stats>,
    filter: Arc<Filter>,
    /// Configuration relue à chaud (détection, rétention, mise à jour des listes).
    live: Arc<ArcSwap<Config>>,
    info: Arc<ArcSwap<EngineInfo>>,
    rules_reload: Arc<AtomicBool>,
    history_path: Option<PathBuf>,
    ca: Option<Arc<CertAuthority>>,
    paths: Paths,
    pub filter_report: LoadReport,
    /// Points d'écoute effectivement ouverts, pour affichage.
    pub listeners: Vec<(String, String)>,
}

fn resolve_addr(s: &str) -> anyhow::Result<SocketAddr> {
    s.to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("adresse invalide « {s} » : {e}"))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("adresse invalide : {s}"))
}

/// Accepte `1.1.1.1`, `1.1.1.1:53`, `2606:4700::1111`, `[2606:4700::1111]:53`,
/// `tls://1.1.1.1:853#cloudflare-dns.com` (DoT) et `https://1.1.1.1/dns-query` (DoH).
pub fn parse_upstream(s: &str) -> Result<crate::dns::upstream::UpstreamKind, String> {
    crate::dns::upstream::parse(s)
}

/// Vérifie la configuration sans rien ouvrir : adresses, réseaux autorisés, résolveurs.
pub fn check_config(cfg: &Config) -> anyhow::Result<()> {
    parse_allow(&cfg.proxy.allow, "proxy")?;
    parse_allow(&cfg.dns.allow, "DNS")?;
    if cfg.proxy.enabled {
        resolve_addr(&cfg.proxy.listen)?;
        for a in [&cfg.proxy.transparent_http, &cfg.proxy.transparent_https]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
        {
            resolve_addr(a)?;
        }
        if cfg.proxy.connect_ports.is_empty() {
            tracing::warn!("proxy : aucun port CONNECT autorisé, le HTTPS explicite sera refusé");
        }
    }
    if cfg.api.enabled {
        resolve_addr(&cfg.api.listen)?;
        parse_allow(&cfg.api.allow, "API")?;
    }
    if let Some(f) = &cfg.detect.rules_file {
        if f.exists() {
            RuleSet::load(f).map_err(|e| anyhow::anyhow!("règles : {e}"))?;
        }
    }
    if cfg.dns.enabled {
        resolve_addr(&cfg.dns.listen)?;
        let n = cfg
            .dns
            .upstreams
            .iter()
            .filter(|u| !u.trim().is_empty())
            .map(|u| parse_upstream(u).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<Vec<_>>>()?
            .len();
        if n == 0 {
            anyhow::bail!("DNS : aucun résolveur amont configuré");
        }
    }
    Ok(())
}

/// Prévient quand un écouteur ouvert sur toutes les interfaces accepte tout le monde.
fn warn_exposure(what: &str, addr: SocketAddr, allow: &[Cidr]) {
    if addr.ip().is_unspecified() && allow.iter().any(Cidr::is_any) {
        tracing::warn!(
            "{what} : écoute sur {addr} ouverte à tous les clients ; restreignez « allow » \
             à vos réseaux"
        );
    }
}

impl Engine {
    pub fn start(cfg: &Config, paths: &Paths) -> anyhow::Result<Engine> {
        crate::install_crypto_provider();

        let (set, filter_report) = FilterSet::build(&cfg.filter, paths);
        let filter = Arc::new(Filter::new(set));
        let stats = Arc::new(Stats::new());
        let (tx, rx) = sync_channel::<Event>(QUEUE);
        let sink = EventSink::new(tx, stats.dropped.clone());
        let live = Arc::new(ArcSwap::from_pointee(cfg.clone()));

        let ca = if cfg.tls.mitm {
            Some(Arc::new(CertAuthority::load_or_create_with(
                &paths.ca_dir(&cfg.tls),
                cfg.tls.ca_validity_days,
            )?))
        } else {
            None
        };

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("ferrox-io")
            .build()?;

        let proxy_allow = parse_allow(&cfg.proxy.allow, "proxy")?;
        let dns_allow = parse_allow(&cfg.dns.allow, "DNS")?;
        let upstreams = cfg
            .dns
            .upstreams
            .iter()
            .filter(|u| !u.trim().is_empty())
            .map(|u| parse_upstream(u))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("DNS : {e}"))?;
        if cfg.dns.enabled && upstreams.is_empty() {
            anyhow::bail!("DNS : aucun résolveur amont configuré");
        }
        let auth = match &cfg.proxy.auth {
            Some(a) if !a.user.is_empty() => Some(BasicAuth::new(&a.user, &a.password)),
            _ => None,
        };

        // Règles TOML : fichier d'exemple créé au premier lancement (emplacement par défaut).
        let rules_path = paths.rules_file(&cfg.detect);
        if cfg.detect.rules_file.is_none() && !rules_path.exists() {
            if let Some(d) = rules_path.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            let _ = std::fs::write(&rules_path, crate::detect::rules::EXAMPLE);
        }
        let (rules, rules_error) = match RuleSet::load(&rules_path) {
            Ok(r) => (r, None),
            Err(_) if !rules_path.exists() => (RuleSet::default(), None),
            Err(e) => {
                tracing::warn!("règles de détection : {e}");
                (RuleSet::default(), Some(e))
            }
        };

        let history_path = cfg
            .history
            .enabled
            .then(|| paths.history_file(&cfg.history));
        let history = match &history_path {
            Some(p) => match HistoryWriter::open(p, cfg.history.retention_days) {
                Ok(w) => Some(w),
                Err(e) => {
                    tracing::warn!("{e}");
                    None
                }
            },
            None => None,
        };

        let info = Arc::new(ArcSwap::from_pointee(EngineInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            filter_domains: filter_report.total_domains,
            filter_errors: filter_report.errors.clone(),
            rules_loaded: rules.enabled(),
            rules_error: rules_error.clone(),
            rules_file: rules_path.display().to_string(),
            lists_updated_ms: newest_list(&cfg.filter, paths),
            mitm: ca.is_some(),
            ca_days_left: ca.as_ref().map(|c| c.days_left()),
            ..EngineInfo::default()
        }));
        let api_allow = parse_allow(&cfg.api.allow, "API")?;

        let mut listeners = Vec::new();
        rt.block_on(async {
            if cfg.proxy.enabled {
                let ctx = Arc::new(ProxyCtx {
                    filter: filter.clone(),
                    sink: sink.clone(),
                    client: crate::http_client::build_with_timeout(Duration::from_millis(
                        cfg.proxy.connect_timeout_ms,
                    )),
                    ca: ca.clone(),
                    bypass: cfg
                        .tls
                        .bypass
                        .iter()
                        .map(|d| crate::filter::normalize_host(d))
                        .collect(),
                    auto_bypass: BypassCache::new(
                        cfg.tls.auto_bypass_failures,
                        Duration::from_secs(cfg.tls.auto_bypass_ttl_s.max(1)),
                        10_000,
                    ),
                    allow: proxy_allow.clone(),
                    connect_ports: cfg.proxy.connect_ports.clone(),
                    auth,
                    slots: Arc::new(tokio::sync::Semaphore::new(
                        cfg.proxy.max_connections.max(1),
                    )),
                    connect_timeout: Duration::from_millis(cfg.proxy.connect_timeout_ms),
                    response_timeout: Duration::from_secs(cfg.proxy.response_timeout_s.max(1)),
                    idle_timeout: Duration::from_secs(cfg.proxy.idle_timeout_s.max(5)),
                    active: stats.active.clone(),
                    live_up: stats.live_up.clone(),
                    live_down: stats.live_down.clone(),
                    pac_fallback: cfg.proxy.listen.clone(),
                });
                let l = TcpListener::bind(resolve_addr(&cfg.proxy.listen)?)
                    .await
                    .map_err(|e| anyhow::anyhow!("proxy {} : {e}", cfg.proxy.listen))?;
                let a = l.local_addr()?;
                warn_exposure("proxy", a, &proxy_allow);
                listeners.push(("Proxy explicite".into(), a.to_string()));
                tokio::spawn(proxy::run_explicit(l, ctx.clone()));

                if let Some(addr) = cfg
                    .proxy
                    .transparent_http
                    .as_deref()
                    .filter(|s| !s.is_empty())
                {
                    let l = TcpListener::bind(resolve_addr(addr)?)
                        .await
                        .map_err(|e| anyhow::anyhow!("transparent HTTP {addr} : {e}"))?;
                    let a = l.local_addr()?;
                    warn_exposure("transparent HTTP", a, &proxy_allow);
                    listeners.push(("Transparent HTTP".into(), a.to_string()));
                    tokio::spawn(proxy::run_transparent_http(l, ctx.clone()));
                }
                if let Some(addr) = cfg
                    .proxy
                    .transparent_https
                    .as_deref()
                    .filter(|s| !s.is_empty())
                {
                    let l = TcpListener::bind(resolve_addr(addr)?)
                        .await
                        .map_err(|e| anyhow::anyhow!("transparent HTTPS {addr} : {e}"))?;
                    let a = l.local_addr()?;
                    warn_exposure("transparent HTTPS", a, &proxy_allow);
                    listeners.push(("Transparent HTTPS".into(), a.to_string()));
                    tokio::spawn(proxy::run_transparent_https(l, ctx.clone()));
                }
            }
            if cfg.dns.enabled {
                let ctx = Arc::new(
                    DnsCtx::new(
                        filter.clone(),
                        sink.clone(),
                        upstreams,
                        cfg.dns.block_mode,
                        cfg.dns.cache_entries.max(100),
                        Duration::from_millis(cfg.dns.timeout_ms.max(200)),
                    )
                    .with_access(dns_allow.clone(), cfg.dns.max_tcp_clients),
                );
                let addr = resolve_addr(&cfg.dns.listen)?;
                let udp = UdpSocket::bind(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("DNS UDP {} : {e}", cfg.dns.listen))?;
                // Port 0 : TCP prend le même port que celui attribué à UDP.
                let tcp_addr = udp.local_addr()?;
                let tcp = TcpListener::bind(tcp_addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("DNS TCP {} : {e}", cfg.dns.listen))?;
                warn_exposure("DNS", tcp_addr, &dns_allow);
                listeners.push(("DNS UDP/TCP".into(), tcp_addr.to_string()));
                tokio::spawn(dns::run_udp(Arc::new(udp), ctx.clone()));
                tokio::spawn(dns::run_tcp(tcp, ctx));
            }
            if cfg.api.enabled {
                let l = TcpListener::bind(resolve_addr(&cfg.api.listen)?)
                    .await
                    .map_err(|e| anyhow::anyhow!("API {} : {e}", cfg.api.listen))?;
                let a = l.local_addr()?;
                warn_exposure("API", a, &api_allow);
                listeners.push(("API et métriques".into(), a.to_string()));
                tokio::spawn(crate::api::run(
                    l,
                    Arc::new(ApiCtx {
                        stats: stats.clone(),
                        history: history_path.clone(),
                        info: info.clone(),
                        allow: api_allow.clone(),
                        token: cfg.api.token.clone(),
                    }),
                ));
            }
            // Mise à jour planifiée des listes (FP-08) : vérifiée toutes les 10 minutes.
            tokio::spawn(list_updater(
                live.clone(),
                paths.clone(),
                filter.clone(),
                info.clone(),
            ));
            Ok::<(), anyhow::Error>(())
        })?;
        info.rcu(|old| {
            let mut n = (**old).clone();
            n.listeners.clone_from(&listeners);
            n
        });
        drop(sink);

        // Pipeline : un fil dédié, sans contention avec le réseau.
        let stop = Arc::new(AtomicBool::new(false));
        let rules_reload = Arc::new(AtomicBool::new(false));
        let mut logger = Logger::new(&cfg.log, paths.logs_dir(&cfg.log));
        let pipeline = {
            let stats = stats.clone();
            let stop = stop.clone();
            let live = live.clone();
            let info = info.clone();
            let reload = rules_reload.clone();
            let paths = paths.clone();
            let mut history = history;
            std::thread::Builder::new()
                .name("ferrox-pipeline".into())
                .spawn(move || {
                    let mut detector = Detector::new();
                    detector.set_rules(Arc::new(rules));
                    let mut rules_mtime = mtime(&rules_path);
                    let mut rules_path = rules_path;
                    let mut last_flush = Instant::now();
                    let mut last_rules_check = Instant::now();
                    let mut last_purge: Option<Instant> = None;
                    let mut policy = LogPolicy::from_config(&live.load().log);
                    loop {
                        match rx.recv_timeout(Duration::from_millis(200)) {
                            Ok(ev) => {
                                let cfg = live.load();
                                stats.ingest(&ev);
                                logger.write_event(&ev);
                                if let Some(h) = history.as_mut() {
                                    h.record_event(&ev);
                                }
                                for a in detector.ingest(&cfg.detect, &ev) {
                                    stats.add_alert(&a);
                                    logger.write_alert(&a);
                                    if let Some(h) = history.as_mut() {
                                        h.record_alert(&a);
                                    }
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => {}
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                        if last_flush.elapsed() >= Duration::from_secs(1) {
                            let cfg = live.load();
                            logger.flush();
                            if let Some(h) = history.as_mut() {
                                if let Err(e) = h.flush() {
                                    tracing::warn!("historique : {e}");
                                }
                            }
                            detector.prune(&cfg.detect, now_ms());
                            let p = LogPolicy::from_config(&cfg.log);
                            if p != policy {
                                policy = p;
                                logger.set_policy(p);
                                last_purge = None;
                            }
                            // Rétention : au démarrage puis toutes les heures.
                            if last_purge.is_none_or(|t| t.elapsed() >= Duration::from_secs(3600)) {
                                logger.purge();
                                if let Some(h) = history.as_mut() {
                                    h.set_retention(cfg.history.retention_days);
                                    if let Err(e) = h.purge(now_ms()) {
                                        tracing::warn!("historique : {e}");
                                    }
                                }
                                last_purge = Some(Instant::now());
                            }
                            // Règles TOML : rechargées si le fichier change (ou sur demande).
                            let forced = reload.swap(false, Ordering::Relaxed);
                            if forced || last_rules_check.elapsed() >= Duration::from_secs(2) {
                                last_rules_check = Instant::now();
                                let path = paths.rules_file(&cfg.detect);
                                let m = mtime(&path);
                                if forced || m != rules_mtime || path != rules_path {
                                    rules_mtime = m;
                                    rules_path.clone_from(&path);
                                    let (set, err) = match RuleSet::load(&path) {
                                        Ok(r) => (Some(r), None),
                                        Err(_) if !path.exists() => {
                                            (Some(RuleSet::default()), None)
                                        }
                                        Err(e) => (None, Some(e)),
                                    };
                                    if let Some(e) = &err {
                                        tracing::warn!("règles non rechargées : {e}");
                                    }
                                    let loaded = set.as_ref().map(RuleSet::enabled);
                                    if let Some(r) = set {
                                        tracing::info!(
                                            "règles rechargées : {} actives",
                                            r.enabled()
                                        );
                                        detector.set_rules(Arc::new(r));
                                    }
                                    info.rcu(|old| {
                                        let mut n = (**old).clone();
                                        if let Some(l) = loaded {
                                            n.rules_loaded = l;
                                        }
                                        n.rules_error.clone_from(&err);
                                        n.rules_file = path.display().to_string();
                                        n
                                    });
                                }
                            }
                            last_flush = Instant::now();
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                    logger.flush();
                    if let Some(h) = history.as_mut() {
                        let _ = h.flush();
                    }
                })?
        };

        Ok(Engine {
            rt: Some(rt),
            stop,
            pipeline: Some(pipeline),
            stats,
            filter,
            live,
            info,
            rules_reload,
            history_path,
            ca,
            paths: paths.clone(),
            filter_report,
            listeners,
        })
    }

    pub fn snapshot(&self, opts: SnapshotOpts) -> Snapshot {
        self.stats.snapshot(opts)
    }

    pub fn stats(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    /// Recharge le filtrage (listes sur disque, catégories, règles manuelles) à chaud.
    pub fn reload_filter(&self, cfg: &FilterConfig) -> LoadReport {
        let (set, report) = FilterSet::build(cfg, &self.paths);
        self.filter.replace(set);
        self.live.rcu(|old| {
            let mut n = (**old).clone();
            n.filter = cfg.clone();
            n
        });
        let lists = newest_list(cfg, &self.paths);
        self.info.rcu(|old| {
            let mut n = (**old).clone();
            n.filter_domains = report.total_domains;
            n.filter_errors.clone_from(&report.errors);
            n.lists_updated_ms = lists;
            n
        });
        report
    }

    pub fn set_detect_config(&self, cfg: DetectConfig) {
        self.live.rcu(|old| {
            let mut n = (**old).clone();
            n.detect = cfg.clone();
            n
        });
    }

    /// Applique les réglages modifiables sans redémarrage : détection, rétention et masquage
    /// des journaux, historique, intervalle de mise à jour des listes.
    pub fn apply_live(&self, cfg: &Config) {
        self.live.store(Arc::new(cfg.clone()));
    }

    /// Demande le rechargement immédiat des règles TOML.
    pub fn reload_rules(&self) {
        self.rules_reload.store(true, Ordering::Relaxed);
    }

    /// État courant (écouteurs, filtrage, règles), partagé avec l'API.
    pub fn info(&self) -> Arc<EngineInfo> {
        self.info.load_full()
    }

    /// Base d'historique, si l'historique est actif.
    pub fn history_path(&self) -> Option<&std::path::Path> {
        self.history_path.as_deref()
    }

    pub fn ca_cert_path(&self) -> Option<PathBuf> {
        self.ca.as_ref().map(|c| c.cert_path.clone())
    }

    pub fn shutdown(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_timeout(Duration::from_millis(500));
        }
        self.stop.store(true, Ordering::Relaxed);
        if let Some(p) = self.pipeline.take() {
            let _ = p.join();
        }
    }
}

fn mtime(p: &std::path::Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(p).and_then(|m| m.modified()).ok()
}

/// Date de la liste activée la plus récemment mise à jour.
fn newest_list(cfg: &FilterConfig, paths: &Paths) -> Option<i64> {
    cfg.lists
        .iter()
        .filter(|l| l.enabled)
        .filter_map(|l| crate::filter::lists::list_updated_at(paths, &l.name))
        .max()
}

/// Tâche de fond : télécharge les listes trop anciennes puis recharge le filtrage à chaud.
async fn list_updater(
    live: Arc<ArcSwap<Config>>,
    paths: Paths,
    filter: Arc<Filter>,
    info: Arc<ArcSwap<EngineInfo>>,
) {
    tokio::time::sleep(Duration::from_secs(30)).await;
    loop {
        let cfg = live.load_full();
        let h = cfg.filter.update_interval_h;
        if h > 0 && crate::filter::lists::lists_stale(&cfg.filter, &paths, h, now_ms()) {
            let res = crate::filter::lists::update_lists(&cfg.filter, &paths).await;
            for r in res.iter().filter(|r| !r.ok) {
                tracing::warn!("liste {} : {}", r.name, r.message);
            }
            if res.iter().any(|r| r.ok) {
                let (fc, p) = (cfg.filter.clone(), paths.clone());
                if let Ok((set, report)) =
                    tokio::task::spawn_blocking(move || FilterSet::build(&fc, &p)).await
                {
                    filter.replace(set);
                    let lists = newest_list(&cfg.filter, &paths);
                    info.rcu(|old| {
                        let mut n = (**old).clone();
                        n.filter_domains = report.total_domains;
                        n.filter_errors.clone_from(&report.errors);
                        n.lists_updated_ms = lists;
                        n
                    });
                    tracing::info!(
                        "listes mises à jour : {} domaines filtrés",
                        report.total_domains
                    );
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(600)).await;
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}
