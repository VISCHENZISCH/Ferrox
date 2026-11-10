//! Orchestration : démarre les écouteurs (proxy, DNS), le pipeline
//! (statistiques, détection, journaux) et expose un instantané pour l'interface.

use crate::access::{parse_allow, BasicAuth, BypassCache, Cidr};
use crate::config::{Config, DetectConfig, FilterConfig, Paths};
use crate::detect::Detector;
use crate::dns::{self, DnsCtx};
use crate::event::{now_ms, Event, EventSink};
use crate::filter::{Filter, FilterSet, LoadReport};
use crate::logger::Logger;
use crate::proxy::{self, ProxyCtx};
use crate::stats::{Snapshot, SnapshotOpts, Stats};
use crate::tls::CertAuthority;
use arc_swap::ArcSwap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
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
    detect_cfg: Arc<ArcSwap<DetectConfig>>,
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

/// Accepte `1.1.1.1`, `1.1.1.1:53`, `2606:4700::1111` et `[2606:4700::1111]:53`.
pub fn parse_upstream(s: &str) -> Result<SocketAddr, String> {
    let s = s.trim();
    s.parse::<SocketAddr>()
        .or_else(|_| s.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| format!("résolveur amont invalide : « {s} »"))
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
        let detect_cfg = Arc::new(ArcSwap::from_pointee(cfg.detect.clone()));

        let ca = if cfg.tls.mitm {
            Some(Arc::new(CertAuthority::load_or_create(
                &paths.ca_dir(&cfg.tls),
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
            Ok::<(), anyhow::Error>(())
        })?;
        drop(sink);

        // Pipeline : un fil dédié, sans contention avec le réseau.
        let stop = Arc::new(AtomicBool::new(false));
        let mut logger = Logger::new(&cfg.log, paths.logs_dir(&cfg.log));
        let pipeline = {
            let stats = stats.clone();
            let stop = stop.clone();
            let detect_cfg = detect_cfg.clone();
            std::thread::Builder::new()
                .name("ferrox-pipeline".into())
                .spawn(move || {
                    let mut detector = Detector::new();
                    let mut last_flush = Instant::now();
                    loop {
                        match rx.recv_timeout(Duration::from_millis(200)) {
                            Ok(ev) => {
                                let dc = detect_cfg.load();
                                stats.ingest(&ev);
                                logger.write_event(&ev);
                                for a in detector.ingest(&dc, &ev) {
                                    stats.add_alert(&a);
                                    logger.write_alert(&a);
                                }
                            }
                            Err(RecvTimeoutError::Timeout) => {}
                            Err(RecvTimeoutError::Disconnected) => break,
                        }
                        if last_flush.elapsed() >= Duration::from_secs(1) {
                            logger.flush();
                            detector.prune(&detect_cfg.load(), now_ms());
                            last_flush = Instant::now();
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                    logger.flush();
                })?
        };

        Ok(Engine {
            rt: Some(rt),
            stop,
            pipeline: Some(pipeline),
            stats,
            filter,
            detect_cfg,
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
        report
    }

    pub fn set_detect_config(&self, cfg: DetectConfig) {
        self.detect_cfg.store(Arc::new(cfg));
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

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}
