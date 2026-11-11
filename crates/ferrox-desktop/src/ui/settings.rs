//! Page Paramètres : écoute, DNS, interception TLS, détection, journaux.

use super::widgets::{btn, card, field, hint, mono_wrap, secret_field, seg, toggle_row, El, Kind};
use crate::app::{App, Field, Message, Toggle};
use crate::icons::Ico;
use crate::theme::{self, size, Pal};
use ferrox_core::config::DnsBlockMode;
use iced::widget::{column, container, horizontal_space, row, text};
use iced::{Alignment, Length, Padding};

fn code<'a>(p: Pal, s: &str) -> El<'a> {
    container(
        iced::widget::text(s.to_string())
            .size(size::CAPTION)
            .font(crate::theme::CODE)
            .color(p.text),
    )
    .padding(Padding::from([10, 14]))
    .width(Length::Fill)
    .style(theme::raised(p))
    .into()
}

pub fn view(app: &App, p: Pal) -> El<'_> {
    let d = &app.draft;
    let fm = &app.form;

    let proxy = card(
        p,
        "Proxy",
        Some(Ico::Traffic),
        None,
        column![
            toggle_row(p, "Proxy actif", "HTTP, HTTPS (CONNECT) et modes transparents.", d.proxy.enabled, |v| Message::Flag(Toggle::Proxy, v)),
            field(p, "Proxy explicite (navigateurs, système)", &fm.proxy_listen, "127.0.0.1:3128", |v| Message::Form(Field::ProxyListen, v)),
            row![
                field(p, "Transparent HTTP", &fm.transparent_http, "désactivé · ex. 0.0.0.0:8081", |v| Message::Form(Field::TransparentHttp, v)),
                field(p, "Transparent HTTPS (SNI)", &fm.transparent_https, "désactivé · ex. 0.0.0.0:8443", |v| Message::Form(Field::TransparentHttps, v)),
            ]
            .spacing(12),
            row![
                field(p, "Clients autorisés (réseaux)", &fm.proxy_allow, "127.0.0.0/8, ::1/128 · ex. 192.168.1.0/24", |v| Message::Form(Field::ProxyAllow, v)),
                field(p, "Ports CONNECT autorisés", &fm.connect_ports, "443, 8443", |v| Message::Form(Field::ConnectPorts, v)),
            ]
            .spacing(12),
            row![
                field(p, "Identifiant (authentification Basic)", &fm.auth_user, "désactivée", |v| Message::Form(Field::AuthUser, v)),
                secret_field(p, "Mot de passe", &fm.auth_password, "", |v| Message::Form(Field::AuthPassword, v)),
            ]
            .spacing(12),
            hint(p, "Hors des réseaux listés, les connexions sont refusées. 0.0.0.0/0 ouvre le proxy à tous : à éviter hors d'un réseau de confiance."),
            hint(p, "Mode transparent : redirigez le trafic du réseau vers Ferrox (passerelle Linux) :"),
            code(
                p,
                "iptables -t nat -A PREROUTING -i <lan> -p tcp --dport 80  -j REDIRECT --to-port 8081\n\
                 iptables -t nat -A PREROUTING -i <lan> -p tcp --dport 443 -j REDIRECT --to-port 8443"
            ),
        ]
        .spacing(12)
        .into(),
    );

    let dns = card(
        p,
        "DNS intégré",
        Some(Ico::Dns),
        None,
        column![
            toggle_row(p, "Résolveur actif", "Filtre, met en cache et analyse toutes les requêtes de noms.", d.dns.enabled, |v| Message::Flag(Toggle::Dns, v)),
            row![
                field(p, "Écoute (UDP et TCP)", &fm.dns_listen, "127.0.0.1:53", |v| Message::Form(Field::DnsListen, v)),
                field(p, "Résolveurs amont", &fm.upstreams, "1.1.1.1:53, 9.9.9.9:53", |v| Message::Form(Field::Upstreams, v)),
            ]
            .spacing(12),
            row![
                text("Réponse aux domaines bloqués").size(size::SMALL).color(p.muted),
                horizontal_space(),
                seg(
                    p,
                    vec![
                        ("NXDOMAIN".into(), d.dns.block_mode == DnsBlockMode::Nxdomain, Message::BlockMode(DnsBlockMode::Nxdomain)),
                        ("0.0.0.0".into(), d.dns.block_mode == DnsBlockMode::Sinkhole, Message::BlockMode(DnsBlockMode::Sinkhole)),
                    ]
                ),
            ]
            .align_y(Alignment::Center),
            field(p, "Clients autorisés (réseaux)", &fm.dns_allow, "127.0.0.0/8, ::1/128 · ex. 192.168.1.0/24", |v| Message::Form(Field::DnsAllow, v)),
            hint(p, "Un résolveur ouvert à Internet sert aux attaques par amplification : listez seulement vos réseaux."),
            hint(p, "Le port 53 demande des droits : sous Linux, sudo setcap cap_net_bind_service=+ep sur le binaire."),
        ]
        .spacing(12)
        .into(),
    );

    let ca_path = app.ca_path.as_ref().map(|p| p.display().to_string());
    let ca_dir = app.paths.ca_dir(&d.tls);
    let mut ca_actions = row![btn(
        p,
        "Générer la CA",
        Some(Ico::Lock),
        Kind::Ghost,
        Some(Message::GenerateCa)
    )]
    .spacing(8);
    if let Some(cp) = &ca_path {
        ca_actions = ca_actions.push(btn(
            p,
            "Copier le chemin",
            Some(Ico::Export),
            Kind::Ghost,
            Some(Message::Copy(cp.clone())),
        ));
    }
    ca_actions = ca_actions.push(btn(
        p,
        "Ouvrir le dossier",
        None,
        Kind::Ghost,
        Some(Message::OpenFolder(ca_dir)),
    ));
    let tls = card(
        p,
        "Interception TLS",
        Some(Ico::Lock),
        None,
        column![
            toggle_row(
                p,
                "Déchiffrer le HTTPS",
                "Donne l'URL, le User-Agent et les fichiers des sites chiffrés. Installez d'abord la CA sur les postes.",
                d.tls.mitm,
                |v| Message::Flag(Toggle::Mitm, v)
            ),
            column![
                text("Certificat CA à installer").size(size::CAPTION).color(p.muted),
                mono_wrap(ca_path.clone().unwrap_or_else(|| "non généré".into()), 12, if ca_path.is_some() { p.text } else { p.faint }),
            ]
            .spacing(4),
            ca_actions,
            field(p, "Jamais intercepter (épinglage, banques)", &fm.bypass, "apple.com, banque.fr", |v| Message::Form(Field::Bypass, v)),
            hint(p, "Un site qui refuse le certificat trois fois est relayé sans déchiffrement pendant une heure."),
        ]
        .spacing(12)
        .into(),
    );

    let detect = card(
        p,
        "Détection",
        Some(Ico::Alert),
        None,
        column![
            text("Balises C2").size(size::SMALL).color(p.text),
            row![
                field(p, "Gigue maximale (%)", &fm.beacon_cv, "15", |v| {
                    Message::Form(Field::BeaconCv, v)
                }),
                field(p, "Contacts minimum", &fm.beacon_min, "8", |v| {
                    Message::Form(Field::BeaconMin, v)
                }),
            ]
            .spacing(12),
            text("Exfiltration").size(size::SMALL).color(p.text),
            row![
                field(p, "Envoi unique (Mo)", &fm.single_mb, "20", |v| {
                    Message::Form(Field::SingleMb, v)
                }),
                field(p, "Volume sur 5 min (Mo)", &fm.window_mb, "100", |v| {
                    Message::Form(Field::WindowMb, v)
                }),
            ]
            .spacing(12),
            text("DNS et User-Agent").size(size::SMALL).color(p.text),
            row![
                field(p, "Entropie DGA (bits/car.)", &fm.entropy, "3.5", |v| {
                    Message::Form(Field::Entropy, v)
                }),
                container(toggle_row(
                    p,
                    "Alerter sans User-Agent",
                    "",
                    d.detect.user_agent.alert_empty,
                    |v| Message::Flag(Toggle::UaEmpty, v)
                ))
                .width(Length::Fill)
                .padding(Padding::ZERO.top(18)),
            ]
            .spacing(12),
        ]
        .spacing(10)
        .into(),
    );

    let logs_dir = app.paths.logs_dir(&d.log);
    let logs = card(
        p,
        "Journaux et SIEM",
        Some(Ico::List),
        Some(btn(
            p,
            "Ouvrir",
            Some(Ico::Export),
            Kind::Ghost,
            Some(Message::OpenFolder(logs_dir.clone())),
        )),
        column![
            toggle_row(
                p,
                "Fichiers JSON Lines (ECS)",
                "traffic-AAAA-MM-JJ.jsonl et alerts-AAAA-MM-JJ.jsonl",
                d.log.jsonl,
                |v| Message::Flag(Toggle::Jsonl, v)
            ),
            field(
                p,
                "Dossier",
                &fm.log_dir,
                &logs_dir.display().to_string(),
                |v| Message::Form(Field::LogDir, v)
            ),
            field(
                p,
                "Syslog UDP vers SIEM (hôte:port)",
                &fm.syslog,
                "désactivé · ex. 192.168.1.10:514",
                |v| Message::Form(Field::Syslog, v)
            ),
            field(
                p,
                "Dossier des catégories UT1",
                &fm.categories_dir,
                &app.paths.categories_dir(&d.filter).display().to_string(),
                |v| Message::Form(Field::CategoriesDir, v)
            ),
        ]
        .spacing(12)
        .into(),
    );

    let places = card(
        p,
        "Emplacements",
        Some(Ico::Settings),
        Some(btn(
            p,
            "Ouvrir les données",
            Some(Ico::Export),
            Kind::Ghost,
            Some(Message::OpenFolder(app.paths.data_dir.clone())),
        )),
        column![
            text("Configuration").size(size::CAPTION).color(p.muted),
            mono_wrap(app.paths.config_file.display().to_string(), 12, p.text),
            text("Données (CA, listes, journaux)")
                .size(size::CAPTION)
                .color(p.muted),
            mono_wrap(app.paths.data_dir.display().to_string(), 12, p.text),
        ]
        .spacing(6)
        .into(),
    );

    let footer = container(
        row![
            text("Les changements de ports et d'interception redémarrent le moteur.")
                .size(size::SMALL)
                .color(p.muted),
            horizontal_space(),
            btn(
                p,
                "Enregistrer et redémarrer",
                Some(Ico::Check),
                Kind::Primary,
                Some(Message::SaveSettings)
            ),
        ]
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([14, 20]))
    .style(theme::card(p));

    column![
        super::widgets::vscroll(
            p,
            column![row![
                column![proxy, dns, places]
                    .spacing(20)
                    .width(Length::FillPortion(1)),
                column![tls, detect, logs]
                    .spacing(20)
                    .width(Length::FillPortion(1)),
            ]
            .spacing(20),]
        ),
        footer,
    ]
    .spacing(20)
    .height(Length::Fill)
    .into()
}
