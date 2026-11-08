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
use crate::theme::{self, Pal, UI, UI_BOLD, UI_HEAVY};
use iced::widget::{
    button, column, container, horizontal_space, row, stack, svg, text, text_input, vertical_space,
    Space,
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
                    text(title).size(30).font(UI_HEAVY).color(p.text),
                    text(subtitle).size(14).color(p.muted),
                ]
                .spacing(6),
                horizontal_space(),
                right,
            ]
            .align_y(Alignment::End)
            .into()
        }
    };
    let band = container(
        column![topbar(app, p), header]
            .spacing(20)
            .padding(Padding::from([0, EDGE]).bottom(28)),
    )
    .width(Length::Fill)
    .style(theme::hero(p));

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

    let base = container(row![sidebar(app, p), main])
        .width(Length::Fill)
        .height(Length::Fill)
        .style(theme::page_bg(p));

    match &app.toast {
        Some(t) => {
            let toast = container(
                text(t.text.clone())
                    .size(14)
                    .font(UI_BOLD)
                    .color(p.on_accent),
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
    let search = row![
        icon(Ico::Search, 20.0, p.text),
        text_input("Rechercher un domaine, un client, une URL…", &app.search)
            .on_input(Message::Search)
            .on_submit(Message::SubmitSearch)
            .size(15)
            .padding(Padding::from([8, 0]))
            .style(theme::input_bare(p)),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .width(Length::Fixed(420.0));

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
    let mut r = row![
        icon(ico, 19.0, p.text),
        text(label)
            .size(15)
            .font(if active { UI_BOLD } else { UI })
            .color(p.text),
        horizontal_space(),
    ]
    .spacing(12)
    .align_y(Alignment::Center);
    if let Some(b) = badge {
        r = r.push(
            container(text(b).size(12).font(UI_BOLD).color(p.muted))
                .padding(Padding::from([2, 8]))
                .style(theme::fill_round(p.raised, 10.0)),
        );
    }
    button(r)
        .width(Length::Fill)
        .padding(Padding::from([10, 12]))
        .on_press(msg)
        .style(theme::btn_nav(p, active))
        .into()
}

fn side_label<'a>(p: Pal, s: &'a str) -> El<'a> {
    container(text(s).size(13).color(p.faint))
        .padding(Padding::from([0, 12]))
        .into()
}

fn side_info<'a>(p: Pal, ico: Ico, label: String, value: String) -> El<'a> {
    container(
        row![
            icon(ico, 18.0, p.text),
            text(label).size(14).color(p.text),
            horizontal_space(),
            text(value).size(12).color(p.muted),
        ]
        .spacing(12)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([8, 12]))
    .into()
}

fn sidebar(app: &App, p: Pal) -> El<'_> {
    let logo = container(
        row![
            svg(app.brand().mark.clone()).width(30).height(30),
            text("Ferrox").size(21).font(UI_HEAVY).color(p.text),
        ]
        .spacing(11)
        .align_y(Alignment::Center),
    )
    .height(Length::Fixed(BAR_H))
    .center_y(Length::Fixed(BAR_H))
    .padding(Padding::from([0, 12]));

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
        .style(theme::fill_round(p.raised, 17.0)),
        column![
            text(state).size(14).font(UI_BOLD).color(p.text),
            text(sub).size(12).color(p.muted),
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
            container(footer).padding(Padding::from([0, 12])),
        ]
        .padding(Padding::from([0, 20]).bottom(24)),
    )
    .width(Length::Fixed(268.0))
    .height(Length::Fill)
    .style(theme::sidebar(p))
    .into()
}
