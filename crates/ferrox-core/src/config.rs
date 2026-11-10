//! Configuration Ferrox (TOML) et chemins de l'application.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Emplacements standards : configuration et données (CA, listes, journaux).
#[derive(Clone, Debug)]
pub struct Paths {
    pub config_file: PathBuf,
    pub data_dir: PathBuf,
}

impl Paths {
    /// Chemins par défaut selon la plateforme (XDG, AppData, Library).
    pub fn default_for_platform() -> Self {
        match directories::ProjectDirs::from("org", "ferrox", "Ferrox") {
            Some(d) => Paths {
                config_file: d.config_dir().join("config.toml"),
                data_dir: d.data_dir().to_path_buf(),
            },
            None => Paths {
                config_file: PathBuf::from("ferrox.toml"),
                data_dir: PathBuf::from("ferrox-data"),
            },
        }
    }

    pub fn with_config(config_file: impl Into<PathBuf>) -> Self {
        let mut p = Self::default_for_platform();
        p.config_file = config_file.into();
        p
    }

    pub fn lists_dir(&self) -> PathBuf {
        self.data_dir.join("lists")
    }
    pub fn logs_dir(&self, cfg: &LogConfig) -> PathBuf {
        cfg.dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("logs"))
    }
    pub fn ca_dir(&self, cfg: &TlsConfig) -> PathBuf {
        cfg.ca_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("ca"))
    }
    pub fn categories_dir(&self, cfg: &FilterConfig) -> PathBuf {
        cfg.categories_dir
            .clone()
            .unwrap_or_else(|| self.data_dir.join("categories"))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub dns: DnsConfig,
    pub tls: TlsConfig,
    pub filter: FilterConfig,
    pub detect: DetectConfig,
    pub log: LogConfig,
    pub ui: UiConfig,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let mut cfg: Config = toml::from_str(&text)?;
        cfg.migrate();
        Ok(cfg)
    }

    /// Met à jour les sources connues pour avoir changé d'adresse.
    fn migrate(&mut self) {
        for l in &mut self.filter.lists {
            if l.url
                .starts_with("https://urlhaus.abuse.ch/downloads/hostfile")
            {
                l.url = "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"
                    .into();
            }
        }
    }

    /// Charge la configuration, ou crée le fichier par défaut s'il n'existe pas.
    pub fn load_or_init(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            let cfg = Config::default();
            cfg.save(path)?;
            Ok(cfg)
        }
    }

    /// Vrai si passer de `self` à `next` demande de redémarrer le moteur ;
    /// les seuils de détection et le thème s'appliquent à chaud.
    pub fn restart_needed(&self, next: &Config) -> bool {
        let key = |c: &Config| {
            let mut c = c.clone();
            c.detect = DetectConfig::default();
            c.ui = UiConfig::default();
            toml::to_string(&c).unwrap_or_default()
        };
        key(self) != key(next)
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let text = toml::to_string_pretty(self)?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ProxyConfig {
    pub enabled: bool,
    /// Proxy explicite (navigateurs configurés manuellement) : HTTP + CONNECT.
    pub listen: String,
    /// Proxy transparent HTTP (trafic du port 80 redirigé par iptables/pf).
    pub transparent_http: Option<String>,
    /// Proxy transparent HTTPS (trafic du port 443 redirigé), routage par SNI.
    pub transparent_https: Option<String>,
    /// Réseaux clients autorisés (CIDR). Vide : boucle locale seulement.
    /// `0.0.0.0/0` et `::/0` ouvrent à tous : à réserver à un réseau de confiance.
    pub allow: Vec<String>,
    /// Ports de destination acceptés pour CONNECT (relais SMTP, SSRF sinon).
    pub connect_ports: Vec<u16>,
    /// Connexions clientes simultanées au maximum (tous écouteurs du proxy).
    pub max_connections: usize,
    /// Authentification Basic du proxy explicite (facultative).
    pub auth: Option<ProxyAuth>,
    pub connect_timeout_ms: u64,
    /// Délai d'attente des en-têtes de réponse du serveur amont.
    pub response_timeout_s: u64,
    /// Délai d'inactivité d'un tunnel (CONNECT, transparent HTTPS) avant fermeture.
    pub idle_timeout_s: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ProxyAuth {
    pub user: String,
    pub password: String,
}

pub fn default_allow() -> Vec<String> {
    vec!["127.0.0.0/8".into(), "::1/128".into()]
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:3128".into(),
            transparent_http: None,
            transparent_https: None,
            allow: default_allow(),
            connect_ports: vec![443, 8443],
            max_connections: 4096,
            auth: None,
            connect_timeout_ms: 8000,
            response_timeout_s: 60,
            idle_timeout_s: 300,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsBlockMode {
    /// Répond « domaine inexistant ».
    Nxdomain,
    /// Répond 0.0.0.0 / :: pour A et AAAA.
    Sinkhole,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    pub listen: String,
    pub upstreams: Vec<String>,
    pub block_mode: DnsBlockMode,
    pub cache_entries: usize,
    pub timeout_ms: u64,
    /// Réseaux clients autorisés (CIDR). Vide : boucle locale seulement.
    /// Un résolveur ouvert sert à l'amplification : n'ouvrez que vos réseaux.
    pub allow: Vec<String>,
    /// Connexions DNS sur TCP simultanées au maximum.
    pub max_tcp_clients: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:5335".into(),
            upstreams: vec!["1.1.1.1:53".into(), "9.9.9.9:53".into()],
            block_mode: DnsBlockMode::Nxdomain,
            cache_entries: 20_000,
            timeout_ms: 2000,
            allow: default_allow(),
            max_tcp_clients: 256,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct TlsConfig {
    /// Interception TLS (MITM) : nécessite d'installer le certificat CA sur les clients.
    pub mitm: bool,
    pub ca_dir: Option<PathBuf>,
    /// Domaines jamais interceptés (banques, applis avec épinglage de certificat).
    pub bypass: Vec<String>,
    /// Échecs de poignée de main interceptée avant le passage en tunnel direct.
    pub auto_bypass_failures: u32,
    /// Durée de ce passage en tunnel direct, en secondes.
    pub auto_bypass_ttl_s: u64,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mitm: false,
            ca_dir: None,
            auto_bypass_failures: 3,
            auto_bypass_ttl_s: 3600,
            bypass: vec![
                "apple.com".into(),
                "icloud.com".into(),
                "windowsupdate.com".into(),
                "update.microsoft.com".into(),
            ],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ListSource {
    pub name: String,
    pub url: String,
    /// Catégorie associée (malware, phishing, ads...), reprise dans les journaux.
    pub category: String,
    pub enabled: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct FilterConfig {
    pub lists: Vec<ListSource>,
    /// Domaines bloqués à la main (les sous-domaines sont inclus).
    pub custom_block: Vec<String>,
    /// Domaines toujours autorisés (prioritaire sur les listes).
    pub allow: Vec<String>,
    /// Dossier de catégories au format UT1 : `<dossier>/<catégorie>/domains`.
    pub categories_dir: Option<PathBuf>,
    pub blocked_categories: Vec<String>,
    /// Extensions de fichiers bloquées (sans le point).
    pub blocked_extensions: Vec<String>,
    /// Préfixes de Content-Type bloqués.
    pub blocked_mime: Vec<String>,
    /// Inspecte les premiers octets des réponses (signatures de fichiers).
    pub sniff_magic: bool,
}

impl Default for FilterConfig {
    fn default() -> Self {
        Self {
            lists: vec![
                ListSource {
                    name: "urlhaus".into(),
                    url: "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt"
                        .into(),
                    category: "malware".into(),
                    enabled: true,
                },
                ListSource {
                    name: "phishing-army".into(),
                    url: "https://phishing.army/download/phishing_army_blocklist.txt".into(),
                    category: "phishing".into(),
                    enabled: true,
                },
                ListSource {
                    name: "stevenblack".into(),
                    url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
                    category: "ads".into(),
                    enabled: false,
                },
            ],
            custom_block: vec![],
            allow: vec![],
            categories_dir: None,
            blocked_categories: vec![],
            blocked_extensions: vec![],
            blocked_mime: vec![],
            sniff_magic: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct BeaconConfig {
    pub enabled: bool,
    /// Nombre minimal de connexions avant d'évaluer la régularité.
    pub min_events: usize,
    /// Coefficient de variation maximal des intervalles (0.15 = 15 % de gigue).
    pub max_cv: f64,
    pub min_interval_s: f64,
    pub max_interval_s: f64,
    /// Domaines ignorés (mises à jour, NTP, télémétrie connue).
    pub ignore: Vec<String>,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_events: 8,
            max_cv: 0.15,
            min_interval_s: 4.0,
            max_interval_s: 3600.0,
            ignore: vec![],
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct ExfilConfig {
    pub enabled: bool,
    /// Un seul envoi au-delà de ce volume déclenche une alerte.
    pub single_upload_mb: f64,
    pub window_s: u64,
    /// Volume envoyé par un client sur la fenêtre glissante.
    pub window_upload_mb: f64,
    /// Rapport envoyé/reçu vers un même domaine.
    pub ratio: f64,
    pub ratio_min_mb: f64,
}

impl Default for ExfilConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            single_upload_mb: 20.0,
            window_s: 300,
            window_upload_mb: 100.0,
            ratio: 10.0,
            ratio_min_mb: 5.0,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct UaConfig {
    pub enabled: bool,
    /// Fragments de User-Agent suspects (outils, scripts, implants courants).
    pub suspicious: Vec<String>,
    /// Nombre de User-Agents distincts par client sur 10 minutes.
    pub max_distinct: usize,
    pub alert_empty: bool,
}

impl Default for UaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            suspicious: [
                "curl/",
                "wget/",
                "python-requests",
                "python-urllib",
                "aiohttp",
                "go-http-client",
                "powershell",
                "winhttp",
                "libwww-perl",
                "nikto",
                "sqlmap",
                "nmap",
                "masscan",
                "zgrab",
                "msie 6.0",
                "certutil",
                "bitsadmin",
                "java/",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            max_distinct: 6,
            alert_empty: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct DnsDetectConfig {
    pub enabled: bool,
    /// Entropie de Shannon (bits/caractère) au-delà de laquelle un nom paraît aléatoire.
    pub entropy_threshold: f64,
    pub min_label_len: usize,
    pub max_qname_len: usize,
    pub max_label_len: usize,
    pub txt_per_min: u32,
    pub unique_sub_per_min: u32,
    pub nx_ratio: f64,
    pub nx_min: u32,
}

impl Default for DnsDetectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            entropy_threshold: 3.5,
            min_label_len: 12,
            max_qname_len: 100,
            max_label_len: 50,
            txt_per_min: 30,
            unique_sub_per_min: 60,
            nx_ratio: 0.5,
            nx_min: 20,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct DetectConfig {
    pub beacon: BeaconConfig,
    pub exfil: ExfilConfig,
    pub user_agent: UaConfig,
    pub dns: DnsDetectConfig,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct LogConfig {
    pub dir: Option<PathBuf>,
    pub jsonl: bool,
    /// Envoi syslog UDP (RFC 5424, charge JSON) vers un SIEM : "hôte:port".
    pub syslog: Option<String>,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            dir: None,
            jsonl: true,
            syslog: None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct UiConfig {
    /// "dark" ou "light".
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            theme: "dark".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_changes_apply_hot() {
        let a = Config::default();
        let mut b = a.clone();
        b.detect.beacon.max_cv = 0.3;
        assert!(!a.restart_needed(&b));
        b.proxy.listen = "127.0.0.1:3129".into();
        assert!(a.restart_needed(&b));
    }

    #[test]
    fn old_config_files_still_load() {
        // Fichier 0.1 : sans allow, connect_ports ni auth.
        let c: Config = toml::from_str("[proxy]\nlisten = \"127.0.0.1:3128\"\n").unwrap();
        assert_eq!(c.proxy.connect_ports, vec![443, 8443]);
        assert_eq!(c.proxy.allow, default_allow());
        assert!(c.proxy.auth.is_none());
    }
}
