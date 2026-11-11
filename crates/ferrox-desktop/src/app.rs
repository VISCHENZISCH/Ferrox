//! État de l'application de bureau, messages et mise à jour.

use crate::icons::Brand;
use crate::theme::Pal;
use ferrox_core::config::DnsBlockMode;
use ferrox_core::event::now_ms;
use ferrox_core::filter::lists::UpdateResult;
use ferrox_core::{Config, Engine, Paths, Snapshot, SnapshotOpts};
use iced::{Subscription, Task, Theme};
use std::path::PathBuf;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Traffic,
    Dns,
    Alerts,
    Filter,
    Settings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionFilter {
    All,
    Allowed,
    Blocked,
}

#[derive(Debug, Clone, Copy)]
pub enum Field {
    ProxyListen,
    TransparentHttp,
    TransparentHttps,
    DnsListen,
    Upstreams,
    Bypass,
    LogDir,
    Syslog,
    BeaconCv,
    BeaconMin,
    SingleMb,
    WindowMb,
    Entropy,
    CategoriesDir,
    ProxyAllow,
    DnsAllow,
    ConnectPorts,
    AuthUser,
    AuthPassword,
}

#[derive(Debug, Clone, Copy)]
pub enum Toggle {
    Proxy,
    Dns,
    Mitm,
    Jsonl,
    Sniff,
    UaEmpty,
}

#[derive(Debug, Clone, Copy)]
pub enum ListKind {
    Block,
    Allow,
    Ext,
    Category,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    Nav(Page),
    SetTheme(bool),
    ToggleTheme,
    StartEngine,
    StopEngine,
    TogglePause,
    Search(String),
    SubmitSearch,
    TrafficQuery(String),
    TrafficFilter(ActionFilter),
    DnsQuery(String),
    DnsFilter(ActionFilter),
    Input(ListKind, String),
    AddItem(ListKind),
    RemoveItem(ListKind, usize),
    ToggleList(usize, bool),
    UpdateLists,
    ListsUpdated(Vec<UpdateResult>),
    ApplyFilter,
    QuickBlock(String),
    Form(Field, String),
    Flag(Toggle, bool),
    BlockMode(DnsBlockMode),
    SaveSettings,
    GenerateCa,
    Copy(String),
    OpenFolder(PathBuf),
    ClearAlerts,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ToastKind {
    Info,
    Ok,
    Error,
}

pub struct Toast {
    pub text: String,
    /// Gardé pour un style par type ; l'interface monochrome ne le distingue pas encore.
    #[allow(dead_code)]
    pub kind: ToastKind,
    pub at: Instant,
}

/// Débit du proxy en temps réel, calculé à partir des compteurs d'octets du moteur.
#[derive(Default)]
pub struct Throughput {
    last: Option<(Instant, u64, u64)>,
    /// Débits lissés, en octets par seconde.
    pub up: f64,
    pub down: f64,
    /// Débits totaux de la dernière minute, pour l'échelle de la jauge.
    recent: std::collections::VecDeque<f64>,
}

impl Throughput {
    const WINDOW: usize = 120; // 60 s à 2 mesures par seconde
    const MIN_SCALE: f64 = 100.0 * 1024.0; // 100 Ko/s

    pub fn update(&mut self, up_total: u64, down_total: u64) {
        let now = Instant::now();
        if let Some((t, u, d)) = self.last {
            let dt = now.duration_since(t).as_secs_f64();
            if up_total < u || down_total < d {
                // Moteur redémarré : les compteurs repartent de zéro.
                *self = Self::default();
            } else if dt > 0.05 {
                let ru = (up_total - u) as f64 / dt;
                let rd = (down_total - d) as f64 / dt;
                // Lissage exponentiel : l'aiguille suit le trafic sans trembler.
                self.up = 0.5 * self.up + 0.5 * ru;
                self.down = 0.5 * self.down + 0.5 * rd;
                self.recent.push_back(ru + rd);
                while self.recent.len() > Self::WINDOW {
                    self.recent.pop_front();
                }
            }
        }
        self.last = Some((now, up_total, down_total));
    }

    #[cfg(test)]
    fn with_peak(peak: f64) -> Self {
        let mut t = Self::default();
        t.recent.push_back(peak);
        t
    }

    pub fn total(&self) -> f64 {
        self.up + self.down
    }

    /// Fond d'échelle « rond » au-dessus du pic récent : 100, 200, 500 Ko/s, 1, 2, 5, 10 Mo/s…
    pub fn scale(&self) -> f64 {
        let peak = self
            .recent
            .iter()
            .copied()
            .fold(self.total(), f64::max)
            .max(Self::MIN_SCALE);
        let mut unit = 1024.0; // Ko
        loop {
            for step in [100.0, 200.0, 500.0] {
                if step * unit >= peak {
                    return step * unit;
                }
            }
            for step in [1.0, 2.0, 5.0, 10.0, 20.0, 50.0] {
                if step * unit * 1024.0 >= peak {
                    return step * unit * 1024.0;
                }
            }
            unit *= 1024.0;
        }
    }
}

/// Champs texte de la page Paramètres (validés à l'enregistrement).
#[derive(Default, Clone)]
pub struct Form {
    pub proxy_listen: String,
    pub transparent_http: String,
    pub transparent_https: String,
    pub dns_listen: String,
    pub upstreams: String,
    pub bypass: String,
    pub log_dir: String,
    pub syslog: String,
    pub beacon_cv: String,
    pub beacon_min: String,
    pub single_mb: String,
    pub window_mb: String,
    pub entropy: String,
    pub categories_dir: String,
    pub proxy_allow: String,
    pub dns_allow: String,
    pub connect_ports: String,
    pub auth_user: String,
    pub auth_password: String,
}

impl Form {
    fn from_config(c: &Config) -> Self {
        Self {
            proxy_listen: c.proxy.listen.clone(),
            transparent_http: c.proxy.transparent_http.clone().unwrap_or_default(),
            transparent_https: c.proxy.transparent_https.clone().unwrap_or_default(),
            dns_listen: c.dns.listen.clone(),
            upstreams: c.dns.upstreams.join(", "),
            bypass: c.tls.bypass.join(", "),
            log_dir: c
                .log
                .dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            syslog: c.log.syslog.clone().unwrap_or_default(),
            beacon_cv: format!("{:.0}", c.detect.beacon.max_cv * 100.0),
            beacon_min: c.detect.beacon.min_events.to_string(),
            single_mb: format!("{}", c.detect.exfil.single_upload_mb),
            window_mb: format!("{}", c.detect.exfil.window_upload_mb),
            entropy: format!("{}", c.detect.dns.entropy_threshold),
            categories_dir: c
                .filter
                .categories_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            proxy_allow: c.proxy.allow.join(", "),
            dns_allow: c.dns.allow.join(", "),
            connect_ports: c
                .proxy
                .connect_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            auth_user: c
                .proxy
                .auth
                .as_ref()
                .map(|a| a.user.clone())
                .unwrap_or_default(),
            auth_password: c
                .proxy
                .auth
                .as_ref()
                .map(|a| a.password.clone())
                .unwrap_or_default(),
        }
    }

    /// Applique le formulaire à une configuration ; renvoie la liste des erreurs.
    fn apply(&self, c: &mut Config) -> Vec<String> {
        let mut errs = Vec::new();
        let opt = |s: &str| {
            let s = s.trim();
            (!s.is_empty()).then(|| s.to_string())
        };
        let list = |s: &str| -> Vec<String> {
            s.split([',', '\n', ' '])
                .map(str::trim)
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        };
        let addr_ok = |s: &str| s.parse::<std::net::SocketAddr>().is_ok();
        for (name, v) in [
            (
                "proxy explicite",
                Some(self.proxy_listen.trim().to_string()),
            ),
            ("transparent HTTP", opt(&self.transparent_http)),
            ("transparent HTTPS", opt(&self.transparent_https)),
            ("DNS", Some(self.dns_listen.trim().to_string())),
        ] {
            if let Some(v) = v {
                if !addr_ok(&v) {
                    errs.push(format!(
                        "adresse {name} invalide : « {v} » (attendu ip:port)"
                    ));
                }
            }
        }
        c.proxy.listen = self.proxy_listen.trim().to_string();
        c.proxy.transparent_http = opt(&self.transparent_http);
        c.proxy.transparent_https = opt(&self.transparent_https);
        c.dns.listen = self.dns_listen.trim().to_string();
        c.dns.upstreams = list(&self.upstreams);
        if c.dns.upstreams.is_empty() {
            errs.push("au moins un résolveur DNS amont est nécessaire".into());
        }
        for u in &c.dns.upstreams {
            if let Err(e) = ferrox_core::engine::parse_upstream(u) {
                errs.push(e);
            }
        }
        for (name, raw, dst) in [
            ("proxy", &self.proxy_allow, &mut c.proxy.allow),
            ("DNS", &self.dns_allow, &mut c.dns.allow),
        ] {
            let v = list(raw);
            for n in &v {
                if ferrox_core::access::Cidr::parse(n).is_none() {
                    errs.push(format!(
                        "réseau autorisé {name} invalide : « {n} » (ex. 192.168.1.0/24)"
                    ));
                }
            }
            *dst = if v.is_empty() {
                ferrox_core::config::default_allow()
            } else {
                v
            };
        }
        let mut ports = Vec::new();
        for p in list(&self.connect_ports) {
            match p.parse::<u16>() {
                Ok(n) if n > 0 => ports.push(n),
                _ => errs.push(format!("port CONNECT invalide : « {p} »")),
            }
        }
        c.proxy.connect_ports = ports;
        let user = self.auth_user.trim();
        c.proxy.auth = (!user.is_empty()).then(|| ferrox_core::config::ProxyAuth {
            user: user.to_string(),
            password: self.auth_password.clone(),
        });
        if user.contains(':') {
            errs.push("identifiant proxy : le caractère « : » est interdit".into());
        }
        c.tls.bypass = list(&self.bypass);
        c.log.dir = opt(&self.log_dir).map(PathBuf::from);
        c.log.syslog = opt(&self.syslog);
        c.filter.categories_dir = opt(&self.categories_dir).map(PathBuf::from);
        let mut num = |name: &str, s: &str, lo: f64, hi: f64| -> Option<f64> {
            match s.trim().replace(',', ".").parse::<f64>() {
                Ok(v) if v >= lo && v <= hi => Some(v),
                _ => {
                    errs.push(format!("{name} : valeur entre {lo} et {hi} attendue"));
                    None
                }
            }
        };
        if let Some(v) = num("gigue maximale (%)", &self.beacon_cv, 1.0, 100.0) {
            c.detect.beacon.max_cv = v / 100.0;
        }
        if let Some(v) = num("contacts minimum", &self.beacon_min, 4.0, 24.0) {
            c.detect.beacon.min_events = v as usize;
        }
        if let Some(v) = num("envoi unique (Mo)", &self.single_mb, 0.1, 100_000.0) {
            c.detect.exfil.single_upload_mb = v;
        }
        if let Some(v) = num("volume sur fenêtre (Mo)", &self.window_mb, 0.1, 1_000_000.0) {
            c.detect.exfil.window_upload_mb = v;
        }
        if let Some(v) = num("seuil d'entropie", &self.entropy, 2.0, 5.0) {
            c.detect.dns.entropy_threshold = v;
        }
        errs
    }
}

pub struct App {
    pub paths: Paths,
    pub config: Config,
    pub draft: Config,
    pub form: Form,
    pub engine: Option<Engine>,
    pub engine_error: Option<String>,
    pub snap: Snapshot,
    pub rate: Throughput,
    pub page: Page,
    pub dark: bool,
    pub paused: bool,
    pub brand_dark: Brand,
    pub brand_light: Brand,
    theme_dark: Theme,
    theme_light: Theme,
    pub search: String,
    pub traffic_query: String,
    pub traffic_filter: ActionFilter,
    pub dns_query: String,
    pub dns_filter: ActionFilter,
    pub alerts_cleared_at: u64,
    pub inputs: [String; 4],
    pub list_status: Vec<UpdateResult>,
    pub updating: bool,
    pub filter_domains: usize,
    pub filter_errors: Vec<String>,
    pub ca_path: Option<PathBuf>,
    pub toast: Option<Toast>,
    pub now: i64,
}

impl App {
    pub fn new() -> (Self, Task<Message>) {
        // FERROX_CONFIG / FERROX_DATA : autre configuration (tests, plusieurs profils).
        let mut paths = match std::env::var_os("FERROX_CONFIG") {
            Some(c) => Paths::with_config(PathBuf::from(c)),
            None => Paths::default_for_platform(),
        };
        if let Some(d) = std::env::var_os("FERROX_DATA") {
            paths.data_dir = PathBuf::from(d);
        }
        let (config, load_err) = match Config::load_or_init(&paths.config_file) {
            Ok(c) => (c, None),
            Err(e) => (
                Config::default(),
                Some(format!("configuration illisible, valeurs par défaut : {e}")),
            ),
        };
        let dark = match std::env::var("FERROX_THEME").as_deref() {
            Ok("light") => false,
            Ok("dark") => true,
            _ => config.ui.theme != "light",
        };
        let mut app = App {
            paths,
            draft: config.clone(),
            form: Form::from_config(&config),
            config,
            engine: None,
            engine_error: None,
            snap: Snapshot::default(),
            rate: Throughput::default(),
            page: match std::env::var("FERROX_PAGE").as_deref() {
                Ok("traffic") => Page::Traffic,
                Ok("dns") => Page::Dns,
                Ok("alerts") => Page::Alerts,
                Ok("filter") => Page::Filter,
                Ok("settings") => Page::Settings,
                _ => Page::Overview,
            },
            dark,
            paused: false,
            brand_dark: Brand::new(Pal::DARK),
            brand_light: Brand::new(Pal::LIGHT),
            theme_dark: Pal::DARK.theme(),
            theme_light: Pal::LIGHT.theme(),
            search: String::new(),
            traffic_query: String::new(),
            traffic_filter: ActionFilter::All,
            dns_query: String::new(),
            dns_filter: ActionFilter::All,
            alerts_cleared_at: 0,
            inputs: Default::default(),
            list_status: Vec::new(),
            updating: false,
            filter_domains: 0,
            filter_errors: Vec::new(),
            ca_path: None,
            toast: None,
            now: now_ms(),
        };
        app.start_engine();
        if let Some(e) = load_err {
            app.notify(e, ToastKind::Error);
        }
        // Premier lancement (aucune liste sur disque) : téléchargement automatique.
        let missing = std::fs::read_dir(app.paths.lists_dir())
            .map(|mut d| d.next().is_none())
            .unwrap_or(true);
        let task = if missing {
            Task::done(Message::UpdateLists)
        } else {
            Task::none()
        };
        (app, task)
    }

    pub fn pal(&self) -> Pal {
        Pal::get(self.dark)
    }

    pub fn brand(&self) -> &Brand {
        if self.dark {
            &self.brand_dark
        } else {
            &self.brand_light
        }
    }

    pub fn theme(&self) -> Theme {
        if self.dark {
            self.theme_dark.clone()
        } else {
            self.theme_light.clone()
        }
    }

    pub fn subscription(&self) -> Subscription<Message> {
        Subscription::batch([
            iced::time::every(Duration::from_millis(500)).map(|_| Message::Tick),
            iced::keyboard::on_key_press(shortcut),
        ])
    }

    fn notify(&mut self, text: impl Into<String>, kind: ToastKind) {
        self.toast = Some(Toast {
            text: text.into(),
            kind,
            at: Instant::now(),
        });
    }

    fn start_engine(&mut self) {
        self.stop_engine();
        match Engine::start(&self.config, &self.paths) {
            Ok(e) => {
                self.filter_domains = e.filter_report.total_domains;
                self.filter_errors = e.filter_report.errors.clone();
                self.ca_path = e.ca_cert_path().or(self.ca_path.take());
                self.engine = Some(e);
                self.engine_error = None;
                self.refresh();
            }
            Err(e) => {
                self.engine_error = Some(e.to_string());
                self.notify(format!("Démarrage impossible : {e}"), ToastKind::Error);
            }
        }
    }

    fn stop_engine(&mut self) {
        if let Some(mut e) = self.engine.take() {
            e.shutdown();
        }
    }

    fn refresh(&mut self) {
        self.now = now_ms();
        if let Some(e) = &self.engine {
            self.snap = e.snapshot(SnapshotOpts {
                recent: 400,
                alerts: 500,
                series: 120,
                top: 10,
            });
            let t = self.snap.totals;
            self.rate.update(t.live_bytes_up, t.live_bytes_down);
        }
    }

    fn save_config(&mut self) -> bool {
        match self.config.save(&self.paths.config_file) {
            Ok(()) => true,
            Err(e) => {
                self.notify(format!("Enregistrement impossible : {e}"), ToastKind::Error);
                false
            }
        }
    }

    fn apply_filter(&mut self) {
        self.config.filter = self.draft.filter.clone();
        if !self.save_config() {
            return;
        }
        if let Some(e) = &self.engine {
            let r = e.reload_filter(&self.config.filter);
            self.filter_domains = r.total_domains;
            self.filter_errors = r.errors;
            let n = crate::fmt::count(r.total_domains as u64);
            self.notify(
                format!("Filtrage rechargé à chaud : {n} domaines"),
                ToastKind::Ok,
            );
        } else {
            self.notify("Filtrage enregistré (moteur arrêté)", ToastKind::Info);
        }
    }

    fn list_mut(&mut self, k: ListKind) -> &mut Vec<String> {
        match k {
            ListKind::Block => &mut self.draft.filter.custom_block,
            ListKind::Allow => &mut self.draft.filter.allow,
            ListKind::Ext => &mut self.draft.filter.blocked_extensions,
            ListKind::Category => &mut self.draft.filter.blocked_categories,
        }
    }

    pub fn filter_dirty(&self) -> bool {
        let a = &self.draft.filter;
        let b = &self.config.filter;
        a.custom_block != b.custom_block
            || a.allow != b.allow
            || a.blocked_extensions != b.blocked_extensions
            || a.blocked_categories != b.blocked_categories
            || a.sniff_magic != b.sniff_magic
            || a.lists
                .iter()
                .map(|l| l.enabled)
                .ne(b.lists.iter().map(|l| l.enabled))
    }

    pub fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            Message::Tick => {
                if !self.paused {
                    self.refresh();
                }
                if self
                    .toast
                    .as_ref()
                    .is_some_and(|t| t.at.elapsed() > Duration::from_secs(5))
                {
                    self.toast = None;
                }
            }
            Message::Nav(p) => self.page = p,
            Message::SetTheme(dark) => {
                self.dark = dark;
                self.config.ui.theme = if dark { "dark" } else { "light" }.into();
                self.draft.ui.theme = self.config.ui.theme.clone();
                let _ = self.config.save(&self.paths.config_file);
            }
            Message::ToggleTheme => return self.update(Message::SetTheme(!self.dark)),
            Message::StartEngine => {
                self.start_engine();
                if self.engine.is_some() {
                    self.notify("Moteur démarré", ToastKind::Ok);
                }
            }
            Message::StopEngine => {
                self.stop_engine();
                self.notify("Moteur arrêté", ToastKind::Info);
            }
            Message::TogglePause => self.paused = !self.paused,
            Message::Search(q) => self.search = q,
            Message::SubmitSearch => {
                // Recherche globale : affiche le trafic web filtré.
                self.traffic_query = self.search.trim().to_string();
                self.page = Page::Traffic;
            }
            Message::TrafficQuery(q) => self.traffic_query = q,
            Message::TrafficFilter(f) => self.traffic_filter = f,
            Message::DnsQuery(q) => self.dns_query = q,
            Message::DnsFilter(f) => self.dns_filter = f,
            Message::ClearAlerts => {
                self.alerts_cleared_at = self.snap.alerts.last().map(|a| a.id).unwrap_or(0);
            }
            Message::Input(k, v) => self.inputs[k as usize] = v,
            Message::AddItem(k) => {
                let raw = self.inputs[k as usize].trim().to_string();
                let v = match k {
                    ListKind::Ext => raw.trim_start_matches('.').to_ascii_lowercase(),
                    ListKind::Category => raw.clone(),
                    _ => ferrox_core::filter::normalize_host(
                        raw.trim_start_matches("https://")
                            .trim_start_matches("http://")
                            .split('/')
                            .next()
                            .unwrap_or(""),
                    ),
                };
                let ok = !v.is_empty()
                    && match k {
                        ListKind::Block | ListKind::Allow => v.contains('.') && !v.contains(' '),
                        _ => !v.contains(' '),
                    };
                if ok {
                    let l = self.list_mut(k);
                    if !l.contains(&v) {
                        l.push(v);
                    }
                    self.inputs[k as usize].clear();
                } else {
                    self.notify(format!("Valeur invalide : « {raw} »"), ToastKind::Error);
                }
            }
            Message::RemoveItem(k, i) => {
                let l = self.list_mut(k);
                if i < l.len() {
                    l.remove(i);
                }
            }
            Message::ToggleList(i, v) => {
                if let Some(l) = self.draft.filter.lists.get_mut(i) {
                    l.enabled = v;
                }
            }
            Message::UpdateLists => {
                if self.updating {
                    return Task::none();
                }
                self.updating = true;
                self.config.filter.lists = self.draft.filter.lists.clone();
                let cfg = self.config.filter.clone();
                let paths = self.paths.clone();
                return Task::perform(
                    async move { ferrox_core::filter::lists::update_lists(&cfg, &paths).await },
                    Message::ListsUpdated,
                );
            }
            Message::ListsUpdated(r) => {
                self.updating = false;
                let ok = r.iter().filter(|x| x.ok).count();
                let total = r.len();
                self.list_status = r;
                self.apply_filter();
                self.notify(
                    format!(
                        "Listes mises à jour : {ok}/{total} — {} domaines actifs",
                        crate::fmt::count(self.filter_domains as u64)
                    ),
                    if ok == total {
                        ToastKind::Ok
                    } else {
                        ToastKind::Error
                    },
                );
            }
            Message::ApplyFilter => self.apply_filter(),
            Message::QuickBlock(host) => {
                if !self.draft.filter.custom_block.contains(&host) {
                    self.draft.filter.custom_block.push(host.clone());
                }
                if !self.config.filter.custom_block.contains(&host) {
                    self.config.filter.custom_block.push(host.clone());
                }
                if self.save_config() {
                    if let Some(e) = &self.engine {
                        let r = e.reload_filter(&self.config.filter);
                        self.filter_domains = r.total_domains;
                    }
                    self.notify(format!("{host} ajouté au blocage manuel"), ToastKind::Ok);
                }
            }
            Message::Form(f, v) => {
                let s = &mut self.form;
                *match f {
                    Field::ProxyListen => &mut s.proxy_listen,
                    Field::TransparentHttp => &mut s.transparent_http,
                    Field::TransparentHttps => &mut s.transparent_https,
                    Field::DnsListen => &mut s.dns_listen,
                    Field::Upstreams => &mut s.upstreams,
                    Field::Bypass => &mut s.bypass,
                    Field::LogDir => &mut s.log_dir,
                    Field::Syslog => &mut s.syslog,
                    Field::BeaconCv => &mut s.beacon_cv,
                    Field::BeaconMin => &mut s.beacon_min,
                    Field::SingleMb => &mut s.single_mb,
                    Field::WindowMb => &mut s.window_mb,
                    Field::Entropy => &mut s.entropy,
                    Field::CategoriesDir => &mut s.categories_dir,
                    Field::ProxyAllow => &mut s.proxy_allow,
                    Field::DnsAllow => &mut s.dns_allow,
                    Field::ConnectPorts => &mut s.connect_ports,
                    Field::AuthUser => &mut s.auth_user,
                    Field::AuthPassword => &mut s.auth_password,
                } = v;
            }
            Message::Flag(t, v) => match t {
                Toggle::Proxy => self.draft.proxy.enabled = v,
                Toggle::Dns => self.draft.dns.enabled = v,
                Toggle::Mitm => self.draft.tls.mitm = v,
                Toggle::Jsonl => self.draft.log.jsonl = v,
                Toggle::Sniff => self.draft.filter.sniff_magic = v,
                Toggle::UaEmpty => self.draft.detect.user_agent.alert_empty = v,
            },
            Message::BlockMode(m) => self.draft.dns.block_mode = m,
            Message::SaveSettings => {
                // Le filtrage a sa propre page : seules ses options d'emplacement viennent d'ici.
                let mut next = self.draft.clone();
                next.filter = self.config.filter.clone();
                let errs = self.form.apply(&mut next);
                if !errs.is_empty() {
                    self.notify(errs.join(" · "), ToastKind::Error);
                    return Task::none();
                }
                let restart = self.config.restart_needed(&next);
                self.config = next;
                self.draft.proxy = self.config.proxy.clone();
                self.draft.dns = self.config.dns.clone();
                self.draft.tls = self.config.tls.clone();
                self.draft.detect = self.config.detect.clone();
                self.draft.log = self.config.log.clone();
                self.draft.filter.categories_dir = self.config.filter.categories_dir.clone();
                if self.save_config() {
                    match &self.engine {
                        // Seuils de détection seulement : appliqués à chaud, statistiques conservées.
                        Some(engine) if !restart => {
                            engine.set_detect_config(self.config.detect.clone());
                            self.notify("Paramètres enregistrés et appliqués", ToastKind::Ok);
                        }
                        Some(_) => {
                            self.start_engine();
                            if self.engine.is_some() {
                                self.notify(
                                    "Paramètres enregistrés, moteur redémarré",
                                    ToastKind::Ok,
                                );
                            }
                        }
                        None => self.notify("Paramètres enregistrés", ToastKind::Ok),
                    }
                }
            }
            Message::GenerateCa => match ferrox_core::ensure_ca(&self.config, &self.paths) {
                Ok(p) => {
                    self.ca_path = Some(p.clone());
                    self.notify(
                        format!("Certificat CA prêt : {}", p.display()),
                        ToastKind::Ok,
                    );
                }
                Err(e) => self.notify(format!("CA : {e}"), ToastKind::Error),
            },
            Message::Copy(s) => {
                self.notify("Copié dans le presse-papiers", ToastKind::Info);
                return iced::clipboard::write(s);
            }
            Message::OpenFolder(p) => {
                let _ = std::fs::create_dir_all(&p);
                let opener = if cfg!(target_os = "macos") {
                    "open"
                } else if cfg!(target_os = "windows") {
                    "explorer"
                } else {
                    "xdg-open"
                };
                if let Err(e) = std::process::Command::new(opener).arg(&p).spawn() {
                    self.notify(format!("Ouverture impossible : {e}"), ToastKind::Error);
                }
            }
        }
        Task::none()
    }
}

/// Raccourcis : Ctrl+1…6 pages, Ctrl+T thème, Ctrl+P pause du direct.
fn shortcut(key: iced::keyboard::Key, mods: iced::keyboard::Modifiers) -> Option<Message> {
    use iced::keyboard::Key;
    if !mods.command() {
        return None;
    }
    let Key::Character(c) = key else { return None };
    Some(match c.as_str() {
        "1" | "&" => Message::Nav(Page::Overview),
        "2" | "é" => Message::Nav(Page::Traffic),
        "3" | "\"" => Message::Nav(Page::Dns),
        "4" | "'" => Message::Nav(Page::Alerts),
        "5" | "(" => Message::Nav(Page::Filter),
        "6" | "-" => Message::Nav(Page::Settings),
        "t" => Message::ToggleTheme,
        "p" => Message::TogglePause,
        _ => return None,
    })
}

impl Drop for App {
    fn drop(&mut self) {
        self.stop_engine();
    }
}

#[cfg(test)]
mod tests {
    use super::Throughput;

    #[test]
    fn gauge_scale_is_round() {
        const K: f64 = 1024.0;
        assert_eq!(Throughput::with_peak(0.0).scale(), 100.0 * K);
        assert_eq!(Throughput::with_peak(150.0 * K).scale(), 200.0 * K);
        assert_eq!(Throughput::with_peak(578.0 * K).scale(), K * K);
        assert_eq!(Throughput::with_peak(3.0 * K * K).scale(), 5.0 * K * K);
        assert_eq!(Throughput::with_peak(70.0 * K * K).scale(), 100.0 * K * K);
    }

    #[test]
    fn rate_follows_counters_and_resets() {
        let mut t = Throughput::default();
        t.update(0, 0);
        std::thread::sleep(std::time::Duration::from_millis(100));
        t.update(0, 1_000_000);
        assert!(t.down > 0.0 && t.up == 0.0);
        t.update(0, 0); // moteur redémarré
        assert_eq!(t.total(), 0.0);
    }
}
