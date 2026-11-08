//! Orchestration : démarre les écouteurs (proxy, DNS), le pipeline
//! (statistiques, détection, journaux) et expose un instantané pour l'interface.

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
    detect_cfg: Arc<ArcSwap<DetectConfig>>,
    ca: Option<Arc<CertAuthority>>,
    paths: Paths,
    pub filter_report: LoadReport,
    /// Points d'écoute effectivement ouverts, pour affichage.
    pub listeners: Vec<(String, String)>,
}

fn resolve_addr(s: &str) -> anyhow::Result<SocketAddr> {
    s.to_socket_addrs()?
        .next()
        .ok_or_else(|| anyhow::anyhow!("adresse invalide : {s}"))
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
                    auto_bypass: Default::default(),
                    connect_timeout: Duration::from_millis(cfg.proxy.connect_timeout_ms),
                    idle_timeout: Duration::from_secs(cfg.proxy.idle_timeout_s.max(5)),
                    active: stats.active.clone(),
                });
                let l = TcpListener::bind(resolve_addr(&cfg.proxy.listen)?)
                    .await
                    .map_err(|e| anyhow::anyhow!("proxy {} : {e}", cfg.proxy.listen))?;
                listeners.push(("Proxy explicite".into(), cfg.proxy.listen.clone()));
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
                    listeners.push(("Transparent HTTP".into(), addr.to_string()));
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
                    listeners.push(("Transparent HTTPS".into(), addr.to_string()));
                    tokio::spawn(proxy::run_transparent_https(l, ctx.clone()));
                }
            }
            if cfg.dns.enabled {
                let upstreams: Vec<SocketAddr> = cfg
                    .dns
                    .upstreams
                    .iter()
                    .filter_map(|u| {
                        u.parse::<SocketAddr>()
                            .ok()
                            .or_else(|| format!("{u}:53").parse().ok())
                    })
                    .collect();
                if upstreams.is_empty() {
                    anyhow::bail!("DNS : aucun résolveur amont valide");
                }
                let ctx = Arc::new(DnsCtx::new(
                    filter.clone(),
                    sink.clone(),
                    upstreams,
                    cfg.dns.block_mode,
                    cfg.dns.cache_entries.max(100),
                    Duration::from_millis(cfg.dns.timeout_ms.max(200)),
                ));
                let addr = resolve_addr(&cfg.dns.listen)?;
                let udp = UdpSocket::bind(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("DNS UDP {} : {e}", cfg.dns.listen))?;
                let tcp = TcpListener::bind(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("DNS TCP {} : {e}", cfg.dns.listen))?;
                listeners.push(("DNS UDP/TCP".into(), cfg.dns.listen.clone()));
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
