//! Ferrox : proxy web et DNS de surveillance réseau.
//!
//! - journalisation du trafic (qui contacte quoi, quand, quel volume) en JSON ECS ;
//! - filtrage (listes de blocage, catégories, types de fichiers) ;
//! - détection (balises C2, exfiltration, DNS anormal, User-Agent suspects).

pub mod access;
pub mod api;
pub mod config;
pub mod detect;
pub mod dns;
pub mod engine;
pub mod event;
pub mod filter;
pub mod history;
pub mod http_client;
pub mod logger;
pub mod proxy;
pub mod stats;
pub mod tls;

pub use config::{Config, Paths};
pub use engine::Engine;
pub use stats::{Snapshot, SnapshotOpts};

/// Installe le fournisseur cryptographique rustls (ring) pour le processus.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Crée (si besoin) la CA d'interception et renvoie le chemin du certificat à installer.
pub fn ensure_ca(cfg: &Config, paths: &Paths) -> anyhow::Result<std::path::PathBuf> {
    install_crypto_provider();
    Ok(
        tls::CertAuthority::load_or_create_with(&paths.ca_dir(&cfg.tls), cfg.tls.ca_validity_days)?
            .cert_path,
    )
}

/// Régénère la CA d'interception (l'ancienne doit être retirée des postes).
pub fn renew_ca(cfg: &Config, paths: &Paths) -> anyhow::Result<std::path::PathBuf> {
    install_crypto_provider();
    Ok(tls::CertAuthority::renew(&paths.ca_dir(&cfg.tls), cfg.tls.ca_validity_days)?.cert_path)
}
