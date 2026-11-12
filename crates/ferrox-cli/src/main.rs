//! ferroxd : Ferrox sans interface graphique.
//!
//!   ferroxd [run] [-c fichier.toml]   démarre le proxy et le DNS
//!   ferroxd init  [-c fichier.toml]   écrit la configuration par défaut
//!   ferroxd update-lists [-c ...]     télécharge les listes de blocage
//!   ferroxd ca    [-c ...] [--renew]  crée (ou régénère) la CA d'interception
//!   ferroxd check [-c ...]            vérifie la configuration et les règles
//!   ferroxd rules [-c ...]            liste les règles de détection TOML
//!   ferroxd pac   [-c ...]            affiche le fichier PAC servi par le proxy
//!   ferroxd version                   affiche la version
//!
//! En service : SIGTERM ou Ctrl+C arrêtent proprement ; SIGHUP relit la configuration
//! (filtrage, détection, rétention) et les règles sans couper les connexions.

use ferrox_core::{Config, Engine, Paths, SnapshotOpts};
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "ferroxd {} : proxy web et DNS de surveillance\n\n\
         usage : ferroxd [commande] [-c config.toml]\n\n\
         commandes :\n\
         \x20 run            démarre le proxy, le DNS et l'API (par défaut)\n\
         \x20 init           écrit la configuration par défaut\n\
         \x20 check          vérifie la configuration et les règles\n\
         \x20 update-lists   télécharge les listes de blocage\n\
         \x20 ca [--renew]   crée ou régénère la CA d'interception\n\
         \x20 rules          liste les règles de détection\n\
         \x20 pac            affiche le fichier PAC\n\
         \x20 version        affiche la version\n\n\
         configuration par défaut : {}",
        env!("CARGO_PKG_VERSION"),
        Paths::default_for_platform().config_file.display()
    );
    std::process::exit(2)
}

fn human(b: u64) -> String {
    let f = b as f64;
    match b {
        0..=1023 => format!("{b} o"),
        1024..=1_048_575 => format!("{:.1} Ko", f / 1024.0),
        1_048_576..=1_073_741_823 => format!("{:.1} Mo", f / 1_048_576.0),
        _ => format!("{:.2} Go", f / 1_073_741_824.0),
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let mut cmd = "run".to_string();
    let mut renew = false;
    let mut paths = Paths::default_for_platform();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => paths = Paths::with_config(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            "-V" | "--version" | "version" => {
                println!("ferroxd {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "run" | "init" | "check" | "update-lists" | "ca" | "rules" | "pac" => cmd = a,
            "--renew" => renew = true,
            _ => usage(),
        }
    }

    let cfg = Config::load_or_init(&paths.config_file)?;
    match cmd.as_str() {
        "init" => {
            println!("configuration : {}", paths.config_file.display());
            println!("données       : {}", paths.data_dir.display());
        }
        "check" => {
            ferrox_core::engine::check_config(&cfg)?;
            let rules = paths.rules_file(&cfg.detect);
            if rules.exists() {
                let set = ferrox_core::detect::rules::RuleSet::load(&rules)
                    .map_err(|e| anyhow::anyhow!("règles : {e}"))?;
                println!(
                    "règles valides       : {} ({} actives)",
                    rules.display(),
                    set.enabled()
                );
            }
            println!("configuration valide : {}", paths.config_file.display());
        }
        "ca" => {
            let p = if renew {
                eprintln!("nouvelle CA : retirez l'ancienne des postes et installez celle-ci");
                ferrox_core::renew_ca(&cfg, &paths)?
            } else {
                ferrox_core::ensure_ca(&cfg, &paths)?
            };
            println!("{}", p.display());
        }
        "rules" => {
            let path = paths.rules_file(&cfg.detect);
            let set = ferrox_core::detect::rules::RuleSet::load(&path)
                .map_err(|e| anyhow::anyhow!("règles : {e}"))?;
            println!("{}", path.display());
            for r in &set.rules {
                println!(
                    "  {} {:<22} {:<9} {}",
                    if r.def.enabled { "●" } else { "○" },
                    r.def.id,
                    r.severity.label(),
                    r.def.name
                );
            }
        }
        "pac" => print!("{}", ferrox_core::proxy::pac_script(&cfg.proxy.listen)),
        "update-lists" => {
            let rt = tokio::runtime::Runtime::new()?;
            for r in rt.block_on(ferrox_core::filter::lists::update_lists(
                &cfg.filter,
                &paths,
            )) {
                println!(
                    "{:<20} {} {}",
                    r.name,
                    if r.ok { "ok " } else { "ERR" },
                    r.message
                );
            }
        }
        _ => run(cfg, paths)?,
    }
    Ok(())
}

fn run(cfg: Config, paths: Paths) -> anyhow::Result<()> {
    let t0 = std::time::Instant::now();
    let engine = Engine::start(&cfg, &paths)?;
    eprintln!(
        "Ferrox {} prêt en {} ms — configuration {}",
        env!("CARGO_PKG_VERSION"),
        t0.elapsed().as_millis(),
        paths.config_file.display()
    );
    for (name, addr) in &engine.listeners {
        eprintln!("  {name:<18} {addr}");
    }
    eprintln!(
        "  filtrage           {} domaines",
        engine.filter_report.total_domains
    );
    for e in &engine.filter_report.errors {
        eprintln!("  ! {e}");
    }
    if let Some(ca) = engine.ca_cert_path() {
        eprintln!("  CA d'interception  {}", ca.display());
    }
    let info = engine.info();
    eprintln!(
        "  règles             {} actives ({})",
        info.rules_loaded, info.rules_file
    );
    if let Some(e) = &info.rules_error {
        eprintln!("  ! règles : {e}");
    }
    if let Some(h) = engine.history_path() {
        eprintln!("  historique         {}", h.display());
    }

    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    let stop = Arc::new(AtomicBool::new(false));
    let hup = Arc::new(AtomicBool::new(false));
    {
        let (stop, hup) = (stop.clone(), hup.clone());
        std::thread::spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            rt.block_on(signals(stop, hup));
        });
    }

    let stats = engine.stats();
    let mut last_alert = 0u64;
    let mut tick = 0u32;
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
        tick += 1;
        if hup.swap(false, Ordering::Relaxed) {
            match Config::load(&paths.config_file) {
                Ok(next) => {
                    if cfg.restart_needed(&next) {
                        eprintln!("SIGHUP : écoute, TLS ou API modifiés, redémarrez le service");
                    }
                    let r = engine.reload_filter(&next.filter);
                    engine.apply_live(&next);
                    engine.reload_rules();
                    eprintln!(
                        "SIGHUP : configuration relue, {} domaines filtrés",
                        r.total_domains
                    );
                }
                Err(e) => eprintln!("SIGHUP : configuration illisible, inchangée : {e}"),
            }
        }
        for a in stats.alerts_since(last_alert) {
            println!("{}", serde_json::to_string(&a).unwrap_or_default());
            last_alert = a.id;
        }
        if tick.is_multiple_of(20) {
            let s = engine.snapshot(SnapshotOpts {
                recent: 0,
                alerts: 0,
                series: 0,
                top: 0,
            });
            let t = s.totals;
            eprintln!(
                "req {} | bloquées {} | DNS {} ({} bloquées) | ↑ {} ↓ {} | alertes {} | conn {}",
                t.requests,
                t.blocked,
                t.dns_queries,
                t.dns_blocked,
                human(t.bytes_up),
                human(t.bytes_down),
                t.alerts,
                t.active_connections
            );
        }
    }
    eprintln!("arrêt…");
    drop(engine);
    Ok(())
}

/// Attend Ctrl+C ou SIGTERM (arrêt), et SIGHUP (rechargement).
async fn signals(
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    hup: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    use std::sync::atomic::Ordering;
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let (Ok(mut term), Ok(mut hangup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) else {
            let _ = tokio::signal::ctrl_c().await;
            stop.store(true, Ordering::Relaxed);
            return;
        };
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
                _ = hangup.recv() => hup.store(true, Ordering::Relaxed),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = hup;
        let _ = tokio::signal::ctrl_c().await;
    }
    stop.store(true, Ordering::Relaxed);
}
