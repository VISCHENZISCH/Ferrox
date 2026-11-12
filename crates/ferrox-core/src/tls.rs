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
    /// Certificat tel qu'il est sur disque (celui installé sur les postes).
    ca_der: CertificateDer<'static>,
    /// Fin de validité de la CA.
    pub not_after: time::OffsetDateTime,
    ca_key: KeyPair,
    leaf_key: KeyPair,
    leaf_signing: Arc<dyn rustls::sign::SigningKey>,
    cache: DashMap<String, Arc<CertifiedKey>>,
    pub cert_path: PathBuf,
}

fn ca_params(validity_days: u32) -> CertificateParams {
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
    let now = time::OffsetDateTime::now_utc();
    p.not_before = now - time::Duration::days(1);
    p.not_after = now + time::Duration::days(i64::from(validity_days.clamp(1, 3650)));
    p
}

/// Durée de validité par défaut d'une nouvelle CA, en jours.
pub const DEFAULT_CA_DAYS: u32 = 825;

impl CertAuthority {
    pub fn load_or_create(dir: &Path) -> anyhow::Result<Self> {
        Self::load_or_create_with(dir, DEFAULT_CA_DAYS)
    }

    /// Charge la CA du dossier, ou en crée une valable `validity_days` jours.
    pub fn load_or_create_with(dir: &Path, validity_days: u32) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let cert_path = dir.join("ferrox-ca.pem");
        let key_path = dir.join("ferrox-ca.key");

        let (ca_key, created) = if key_path.exists() {
            (
                KeyPair::from_pem(&std::fs::read_to_string(&key_path)?)?,
                false,
            )
        } else {
            let k = KeyPair::generate()?;
            write_private(&key_path, k.serialize_pem().as_bytes())?;
            (k, true)
        };
        // Certificat existant : ses paramètres (dates comprises) sont repris tels quels ;
        // le certificat envoyé aux clients est celui du disque.
        let existing = if created {
            None
        } else {
            std::fs::read_to_string(&cert_path).ok()
        };
        let (params, pem) = match existing {
            Some(pem) => (CertificateParams::from_ca_cert_pem(&pem)?, Some(pem)),
            None => (ca_params(validity_days), None),
        };
        let not_after = params.not_after;
        let ca_cert = params.self_signed(&ca_key)?;
        let ca_der = match pem {
            Some(pem) => pem_to_der(&pem)?,
            None => {
                std::fs::write(&cert_path, ca_cert.pem())?;
                CertificateDer::from(ca_cert.der().to_vec())
            }
        };

        let leaf_key = KeyPair::generate()?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let leaf_signing = rustls::crypto::ring::sign::any_supported_type(&der)
            .map_err(|e| anyhow::anyhow!("clé feuille : {e}"))?;

        let ca = Self {
            ca_cert,
            ca_der,
            not_after,
            ca_key,
            leaf_key,
            leaf_signing,
            cache: DashMap::new(),
            cert_path,
        };
        let left = ca.days_left();
        if left < 0 {
            tracing::warn!("CA d'interception expirée : régénérez-la (ferroxd ca --renew)");
        } else if left < 30 {
            tracing::warn!("CA d'interception : expire dans {left} jours (ferroxd ca --renew)");
        }
        Ok(ca)
    }

    /// Supprime la CA du dossier et en crée une nouvelle (à réinstaller sur les postes).
    pub fn renew(dir: &Path, validity_days: u32) -> anyhow::Result<Self> {
        for f in ["ferrox-ca.pem", "ferrox-ca.key"] {
            match std::fs::remove_file(dir.join(f)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        Self::load_or_create_with(dir, validity_days)
    }

    /// Jours restants avant expiration (négatif si expirée).
    pub fn days_left(&self) -> i64 {
        (self.not_after - time::OffsetDateTime::now_utc()).whole_days()
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
        // Jamais au-delà de la CA ; 397 jours au plus (limite des navigateurs).
        p.not_after = (now + time::Duration::days(397)).min(self.not_after);
        let mut serial = [0u8; 16];
        serial[..8].copy_from_slice(&(crate::event::now_ms() as u64).to_be_bytes());
        serial[8..].copy_from_slice(&(fxhash(host)).to_be_bytes());
        serial[0] &= 0x7f;
        p.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        let cert = p.signed_by(&self.leaf_key, &self.ca_cert, &self.ca_key)?;
        let chain = vec![
            CertificateDer::from(cert.der().to_vec()),
            self.ca_der.clone(),
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
        // HTTP/2 proposé aux clients interceptés (FP-14), HTTP/1.1 sinon.
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
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
    #[cfg(windows)]
    {
        std::fs::write(path, data)?;
        restrict_windows_acl(path);
        Ok(())
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, data)
    }
}

/// Sous Windows : retire l'héritage des droits et ne laisse l'accès qu'à l'utilisateur courant,
/// aux administrateurs et au système.
#[cfg(windows)]
fn restrict_windows_acl(path: &Path) {
    let user = std::env::var("USERNAME").unwrap_or_default();
    let mut cmd = std::process::Command::new("icacls");
    cmd.arg(path).arg("/inheritance:r");
    if !user.is_empty() {
        cmd.arg("/grant:r").arg(format!("{user}:F"));
    }
    cmd.args(["/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F"]);
    match cmd.output() {
        Ok(o) if o.status.success() => {}
        _ => tracing::warn!("icacls : droits de {} non restreints", path.display()),
    }
}

fn pem_to_der(pem: &str) -> anyhow::Result<CertificateDer<'static>> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| anyhow::anyhow!("certificat CA illisible : {e}"))?;
    Ok(CertificateDer::from(der))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_is_reloaded_and_renewed() {
        crate::install_crypto_provider();
        let dir = std::env::temp_dir().join(format!("ferrox-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let a = CertAuthority::load_or_create_with(&dir, 90).unwrap();
        assert!((88..=91).contains(&a.days_left()));
        let pem = std::fs::read_to_string(&a.cert_path).unwrap();
        // Rechargement : même certificat sur disque, même date de fin.
        let b = CertAuthority::load_or_create_with(&dir, 3000).unwrap();
        assert_eq!(std::fs::read_to_string(&b.cert_path).unwrap(), pem);
        assert_eq!(a.not_after.date(), b.not_after.date());
        assert_eq!(b.ca_der, a.ca_der);
        assert!(b.certified_key("example.com").is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("ferrox-ca.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let c = CertAuthority::renew(&dir, 10).unwrap();
        assert_ne!(std::fs::read_to_string(&c.cert_path).unwrap(), pem);
        assert!(c.days_left() <= 10);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
