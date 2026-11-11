//! Structure générale : barre latérale, bandeau supérieur, pages, notification.

pub mod alerts;
pub mod chart;
pub mod filter;
pub mod overview;
pub mod settings;
pub mod traffic;
pub mod widgets;

use crate::app::{App, Message, Page};
use crate::icons::{icon, Ico};
use crate::theme::{self, size, Pal, UI_BOLD, UI_HEAVY, UI_STRONG};
use iced::widget::{
    button, column, container, horizontal_space, row, stack, svg, text, vertical_space, Space,
};
use iced::{Alignment, Length, Padding};
use widgets::{btn, El, Kind};

/// Hauteur commune de la barre supérieure et de l'en-tête de la barre latérale.
pub const BAR_H: f32 = 76.0;
/// Marge extérieure du contenu.
pub const EDGE: u16 = 32;

const NAV: [(Page, Ico, &str); 6] = [
    (Page::Overview, Ico::Overview, "Vue d'ensemble"),
    (Page::Traffic, Ico::Traffic, "Trafic web"),
    (Page::Dns, Ico::Dns, "DNS"),
    (Page::Alerts, Ico::Alert, "Alertes"),
    (Page::Filter, Ico::Filter, "Filtrage"),
    (Page::Settings, Ico::Settings, "Paramètres"),
];

pub fn view(app: &App) -> El<'_> {
    let p = app.pal();

    // Bandeau supérieur : barre d'outils + en-tête propre à la page.
    let header: El = match app.page {
        Page::Overview => overview::hero(app, p),
        _ => {
            let (title, subtitle) = match app.page {
                Page::Traffic => ("Trafic web", "Requêtes HTTP et HTTPS vues par le proxy"),
                Page::Dns => ("DNS", "Requêtes de noms reçues par le résolveur intégré"),
                Page::Alerts => ("Alertes", "Comportements suspects détectés sur le réseau"),
                Page::Filter => (
                    "Filtrage",
                    "Listes de blocage, catégories et types de fichiers",
                ),
                _ => (
                    "Paramètres",
                    "Écoute, interception TLS, détection et journaux",
                ),
            };
            let right: El = match app.page {
                Page::Alerts => btn(
                    p,
                    "Tout marquer comme lu",
                    Some(Ico::Check),
                    Kind::Ghost,
                    Some(Message::ClearAlerts),
                ),
                _ => Space::new(0, 0).into(),
            };
            row![
                column![
                    text(title)
                        .size(size::DISPLAY)
                        .font(UI_STRONG)
                        .color(p.text),
                    text(subtitle).size(size::BODY).color(p.muted),
                ]
                .spacing(6),
                horizontal_space(),
                right,
            ]
            .align_y(Alignment::End)
            .into()
        }
    };
    let band = column![
        container(
            column![topbar(app, p), header]
                .spacing(20)
                .padding(Padding::from([0, EDGE]).bottom(28)),
        )
        .width(Length::Fill)
        .style(theme::hero(p)),
        container(Space::new(Length::Fill, 1)).style(theme::rule(p)),
    ];

    let page: El = match app.page {
        Page::Overview => overview::view(app, p),
        Page::Traffic => traffic::http_view(app, p),
        Page::Dns => traffic::dns_view(app, p),
        Page::Alerts => alerts::view(app, p),
        Page::Filter => filter::view(app, p),
        Page::Settings => settings::view(app, p),
    };

    let main = column![
        band,
        container(page)
            .padding(Padding::from([28, EDGE]).bottom(24))
            .width(Length::Fill)
            .height(Length::Fill)
    ]
    .width(Length::Fill)
    .height(Length::Fill);

    let base = container(row![
        sidebar(app, p),
        container(Space::new(1, Length::Fill)).style(theme::rule(p)),
        main
    ])
    .width(Length::Fill)
    .height(Length::Fill)
    .style(theme::page_bg(p));

    match &app.toast {
        Some(t) => {
            let toast = container(
                text(t.text.clone())
                    .size(size::BODY)
                    .font(UI_BOLD)
                    .color(p.on_ink),
            )
            .padding(Padding::from([12, 20]))
            .max_width(640)
            .style(theme::toast(p, p.accent));
            stack![
                base,
                container(toast)
                    .width(Length::Fill)
                    .height(Length::Fill)
                    .padding(28)
                    .center_x(Length::Fill)
                    .align_bottom(Length::Fill)
            ]
            .into()
        }
        None => base.into(),
    }
}

/// Barre supérieure : recherche à gauche, actions à droite, centrées verticalement.
fn topbar(app: &App, p: Pal) -> El<'_> {
    let search = widgets::search_box(
        p,
        "Rechercher un domaine, un client, une URL…",
        &app.search,
        Message::Search,
        Some(Message::SubmitSearch),
        400.0,
    );

    let mut actions = row![].spacing(6).align_y(Alignment::Center);
    if app.engine.is_some() {
        actions = actions.push(btn(
            p,
            if app.paused { "En pause" } else { "En direct" },
            Some(if app.paused { Ico::Play } else { Ico::Pause }),
            Kind::Text,
            Some(Message::TogglePause),
        ));
    }
    actions = actions.push(btn(
        p,
        if app.dark { "Sombre" } else { "Clair" },
        Some(if app.dark { Ico::Moon } else { Ico::Sun }),
        Kind::Text,
        Some(Message::ToggleTheme),
    ));
    actions = actions.push(Space::with_width(10));
    actions = actions.push(if app.engine.is_some() {
        btn(
            p,
            "Arrêter le moteur",
            Some(Ico::Stop),
            Kind::Primary,
            Some(Message::StopEngine),
        )
    } else {
        btn(
            p,
            "Démarrer le moteur",
            Some(Ico::Play),
            Kind::Primary,
            Some(Message::StartEngine),
        )
    });

    container(row![search, horizontal_space(), actions].align_y(Alignment::Center))
        .height(Length::Fixed(BAR_H))
        .center_y(Length::Fixed(BAR_H))
        .into()
}

fn nav_item<'a>(
    p: Pal,
    ico: Ico,
    label: &'a str,
    badge: Option<String>,
    active: bool,
    msg: Message,
) -> El<'a> {
    // Icône posée sur une tuile de 30 px : signature visuelle de la navigation.
    let tile = container(icon(ico, 17.0, if active { p.on_accent } else { p.muted }))
        .width(30)
        .height(30)
        .center_x(30)
        .center_y(30)
        .style(theme::icon_tile(p, active));
    let mut r = row![
        tile,
        text(label)
            .size(size::BODY)
            .font(if active { UI_HEAVY } else { UI_BOLD })
            .color(if active { p.text } else { p.muted }),
        horizontal_space(),
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    if let Some(b) = badge {
        r = r.push(
            container(
                text(b)
                    .size(size::CAPTION)
                    .font(UI_HEAVY)
                    .color(p.on_accent),
            )
            .padding(Padding::from([2, 8]))
            .style(theme::fill_round(p.accent, 10.0)),
        );
    }
    button(r)
        .width(Length::Fill)
        .padding(Padding::from([5, 8]))
        .on_press(msg)
        .style(theme::btn_nav(p, active))
        .into()
}

fn side_label<'a>(p: Pal, s: &'a str) -> El<'a> {
    container(
        text(s.to_uppercase())
            .size(size::CAPTION)
            .font(UI_HEAVY)
            .color(p.faint),
    )
    .padding(Padding::from([0, 14]).bottom(4))
    .into()
}

fn side_info<'a>(p: Pal, ico: Ico, label: String, value: String) -> El<'a> {
    container(
        row![
            icon(ico, 16.0, p.muted),
            text(label).size(size::SMALL).color(p.text),
            horizontal_space(),
            text(value).size(size::CAPTION).color(p.muted),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([8, 14]))
    .into()
}

fn sidebar(app: &App, p: Pal) -> El<'_> {
    let logo = container(
        row![
            svg(app.brand().mark.clone()).width(30).height(30),
            text("Ferrox")
                .size(size::TITLE)
                .font(UI_HEAVY)
                .color(p.text),
        ]
        .spacing(11)
        .align_y(Alignment::Center),
    )
    .height(Length::Fixed(BAR_H))
    .center_y(Length::Fixed(BAR_H))
    .padding(Padding::from([0, 14]));

    let unseen = app
        .snap
        .alerts
        .iter()
        .filter(|a| a.id > app.alerts_cleared_at)
        .count();

    let mut nav = column![].spacing(2);
    for (page, ico, label) in NAV {
        let badge = (page == Page::Alerts && unseen > 0).then(|| unseen.min(999).to_string());
        nav = nav.push(nav_item(
            p,
            ico,
            label,
            badge,
            app.page == page,
            Message::Nav(page),
        ));
    }

    // Points d'écoute, présentés comme les « projets » de la référence.
    let mut listen = column![side_label(p, "Écoute")].spacing(2);
    if let Some(e) = &app.engine {
        for (name, addr) in &e.listeners {
            let ico = if name.starts_with("DNS") {
                Ico::Dns
            } else {
                Ico::Traffic
            };
            let short = name
                .replace("Proxy explicite", "Proxy")
                .replace("DNS UDP/TCP", "DNS")
                .replace("Transparent ", "Transp. ");
            listen = listen.push(side_info(p, ico, short, addr.clone()));
        }
        if app.config.tls.mitm {
            listen = listen.push(side_info(
                p,
                Ico::Lock,
                "Interception TLS".into(),
                "active".into(),
            ));
        }
    } else {
        listen = listen.push(side_info(
            p,
            Ico::Stop,
            "Aucun écouteur".into(),
            String::new(),
        ));
    }
    listen = listen.push(side_info(
        p,
        Ico::Filter,
        "Domaines filtrés".into(),
        crate::fmt::count(app.filter_domains as u64),
    ));

    // Pied : état du moteur, aligné sur le bas du contenu.
    let (state, sub, color) = match (&app.engine, &app.engine_error) {
        (Some(_), _) => (
            "Moteur actif",
            format!("depuis {}", crate::fmt::uptime(app.snap.uptime_s)),
            p.ok,
        ),
        (None, Some(e)) => ("Erreur", crate::fmt::truncate(e, 28), p.danger),
        (None, None) => ("Moteur arrêté", "aucune capture".into(), p.faint),
    };
    let footer = row![
        container(
            container(Space::new(0, 0))
                .width(10)
                .height(10)
                .style(theme::fill_round(color, 5.0))
        )
        .width(34)
        .height(34)
        .center_x(34)
        .center_y(34)
        .style(theme::fill_round(theme::alpha(color, 0.15), 17.0)),
        column![
            text(state).size(size::BODY).font(UI_BOLD).color(p.text),
            text(sub).size(size::CAPTION).color(p.muted),
        ]
        .spacing(2),
        horizontal_space(),
        button(icon(
            if app.engine.is_some() {
                Ico::Stop
            } else {
                Ico::Play
            },
            18.0,
            p.text
        ))
        .padding(8)
        .on_press(if app.engine.is_some() {
            Message::StopEngine
        } else {
            Message::StartEngine
        })
        .style(theme::btn_icon(p)),
    ]
    .spacing(12)
    .align_y(Alignment::Center);

    container(
        column![
            logo,
            Space::with_height(16),
            nav,
            Space::with_height(28),
            listen,
            vertical_space(),
            container(footer)
                .padding(Padding::from([12, 14]))
                .style(theme::card_soft(p)),
        ]
        .padding(Padding::from([0, 20]).bottom(24)),
    )
    .width(Length::Fixed(268.0))
    .height(Length::Fill)
    .style(theme::sidebar(p))
    .into()
}
