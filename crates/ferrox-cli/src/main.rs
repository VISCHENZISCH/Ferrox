//! ferroxd : Ferrox sans interface graphique.
//!
//!   ferroxd [run] [-c fichier.toml]   démarre le proxy et le DNS
//!   ferroxd init  [-c fichier.toml]   écrit la configuration par défaut
//!   ferroxd update-lists [-c ...]     télécharge les listes de blocage
//!   ferroxd ca    [-c ...]            crée la CA d'interception et affiche son chemin
//!   ferroxd check [-c ...]            vérifie la configuration sans rien démarrer
//!   ferroxd version                   affiche la version

use ferrox_core::{Config, Engine, Paths, SnapshotOpts};
use std::time::Duration;

fn usage() -> ! {
    eprintln!(
        "usage : ferroxd [run|init|check|update-lists|ca|version] [-c config.toml]\n\
         configuration par défaut : {}",
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
    let mut paths = Paths::default_for_platform();
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "--config" => paths = Paths::with_config(args.next().unwrap_or_else(|| usage())),
            "-h" | "--help" => usage(),
            "-V" | "--version" | "version" => {
                println!("ferroxd {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            "run" | "init" | "check" | "update-lists" | "ca" => cmd = a,
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
            println!("configuration valide : {}", paths.config_file.display());
        }
        "ca" => {
            let p = ferrox_core::ensure_ca(&cfg, &paths)?;
            println!("{}", p.display());
        }
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
    let engine = Engine::start(&cfg, &paths)?;
    eprintln!(
        "Ferrox démarré — configuration {}",
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

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let _ = tokio::signal::ctrl_c().await;
            });
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
        });
    }

    let stats = engine.stats();
    let mut last_alert = 0u64;
    let mut tick = 0u32;
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
        tick += 1;
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
