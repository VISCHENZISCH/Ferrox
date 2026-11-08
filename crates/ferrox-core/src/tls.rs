//! Autorité de certification locale pour l'interception TLS.
//!
//! La CA est générée une fois (ECDSA P-256) et stockée dans `ca.pem` / `ca.key`.
//! Les certificats feuilles sont signés à la volée et mis en cache par nom d'hôte ;
//! une seule clé feuille est partagée, ce qui évite une génération de clé par site.

use dashmap::DashMap;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CACHE_MAX: usize = 8192;

pub struct CertAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    leaf_key: KeyPair,
    leaf_signing: Arc<dyn rustls::sign::SigningKey>,
    cache: DashMap<String, Arc<CertifiedKey>>,
    pub cert_path: PathBuf,
}

fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Ferrox Local Interception CA");
    dn.push(DnType::OrganizationName, "Ferrox");
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    // Dates fixes : la CA peut être reconstruite à l'identique à partir de sa clé.
    p.not_before = rcgen::date_time_ymd(2025, 1, 1);
    p.not_after = rcgen::date_time_ymd(2035, 1, 1);
    p
}

impl CertAuthority {
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("ferrox-ca.pem");
        let key_path = dir.join("ferrox-ca.key");

        let ca_key = if key_path.exists() {
            KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?
        } else {
            let k = KeyPair::generate()?;
            write_private(&key_path, k.serialize_pem().as_bytes())?;
            k
        };
        let ca_cert = ca_params().self_signed(&ca_key)?;
        if !cert_path.exists() {
            std::fs::write(&cert_path, ca_cert.pem())?;
        }

        let leaf_key = KeyPair::generate()?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signing = rustls::crypto::ring::sign::any_supported_type(&der)
            .map_err(|e| anyhow::anyhow!("clé feuille : {e}"))?;

        Ok(Self {
            ca_cert,
            ca_key,
            leaf_key,
            leaf_signing,
            cache: DashMap::new(),
            cert_path,
        })
    }

    pub fn certified_key(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(c) = self.cache.get(host) {
            return Some(c.clone());
        }
        let ck = Arc::new(self.issue(host).ok()?);
        if self.cache.len() >= CACHE_MAX {
            self.cache.clear();
        }
        self.cache.insert(host.to_string(), ck.clone());
        Some(ck)
    }

    fn issue(&self, host: &str) -> anyhow::Result<CertifiedKey> {
        let mut p = CertificateParams::new(vec![host.to_string()])?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host);
        p.distinguished_name = dn;
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let now = time::OffsetDateTime::now_utc();
        p.not_before = now - time::Duration::days(1);
        p.not_after = now + time::Duration::days(365);
        let mut serial = [0u8; 16];
        serial[..8].copy_from_slice(&(crate::event::now_ms() as u64).to_be_bytes());
        serial[8..].copy_from_slice(&(fxhash(host)).to_be_bytes());
        serial[0] &= 0x7f;
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        let cert = p.signed_by(&self.leaf_key, &self.ca_cert, &self.ca_key)?;
        let chain = vec![
            CertificateDer::from(cert.der().to_vec()),
            CertificateDer::from(self.ca_cert.der().to_vec()),
        ];
        Ok(CertifiedKey::new(chain, self.leaf_signing.clone()))
    }

    /// Configuration serveur TLS pour une connexion interceptée.
    /// `fallback` sert quand le client n'envoie pas de SNI.
    pub fn server_config(self: &Arc<Self>, fallback: &str) -> Arc<ServerConfig> {
        let resolver = Arc::new(Resolver {
            ca: self.clone(),
            fallback: fallback.to_string(),
        });
        let mut cfg =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("versions TLS")
                .with_no_client_auth()
                .with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    }
}

fn fxhash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(data)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
    }
}

struct Resolver {
    ca: Arc<CertAuthority>,
    fallback: String,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("fallback", &self.fallback)
            .finish()
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello
            .server_name()
            .map(|s| s.to_ascii_lowercase())
            .unwrap_or_else(|| self.fallback.clone());
        self.ca.certified_key(&name)
    }
}
