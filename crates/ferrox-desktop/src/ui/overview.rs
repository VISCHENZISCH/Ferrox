//! Vue d'ensemble : bandeau d'indicateurs, puis colonnes de cartes
//! (domaines, clients, blocages récents, alertes).

use super::chart::{Bars, Gauge};
use super::widgets::{counter, empty_state, pill, section_title, vscroll, El, GAP};
use crate::app::{App, Message, Page};
use crate::fmt;
use crate::icons::{icon, Ico};
use crate::theme::{self, size, Pal, UI_BOLD, UI_HEAVY, UI_STRONG};
use ferrox_core::event::{Action, Severity};
use iced::widget::{button, canvas, column, container, horizontal_space, row, text, Space};
use iced::{Alignment, Color, Length, Padding};

const PER_COLUMN: usize = 6;

/// Couleur de catégorie : neutre, sauf menaces.
pub fn category_color(p: Pal, cat: &str) -> Color {
    match cat {
        "malware" | "c2" | "botnet" | "ransomware" | "phishing" => p.danger,
        _ => p.muted,
    }
}

/// Chiffre clé du bandeau : carte avec valeur, libellé et lien.
/// `highlight` la passe en couleur principale (comme la carte mise en avant de la référence).
fn stat<'a>(p: Pal, value: String, label: &str, to: Page, highlight: bool) -> El<'a> {
    let (fg, sub) = if highlight {
        (p.on_accent, theme::mix(p.on_accent, p.accent, 0.9))
    } else {
        (p.text, p.muted)
    };
    // « 409.5 Ko » : chiffre en grand, unité plus petite, sur une seule ligne.
    let (num, unit) = match value.rsplit_once(' ') {
        Some((n, u)) => (n.to_string(), Some(u.to_string())),
        None => (value, None),
    };
    let mut figure = row![text(num)
        .size(size::DISPLAY)
        .font(UI_STRONG)
        .color(fg)
        .wrapping(iced::widget::text::Wrapping::None)]
    .spacing(4)
    .align_y(Alignment::End);
    if let Some(u) = unit {
        figure = figure.push(
            container(
                text(u)
                    .size(size::HEADING)
                    .font(UI_HEAVY)
                    .color(sub)
                    .wrapping(iced::widget::text::Wrapping::None),
            )
            .padding(Padding::ZERO.bottom(4)),
        );
    }
    container(
        column![
            text(label.to_string())
                .size(size::SMALL)
                .font(UI_BOLD)
                .color(sub)
                .wrapping(iced::widget::text::Wrapping::None),
            Space::with_height(Length::Fill),
            row![
                figure,
                horizontal_space(),
                button(icon(Ico::Arrow, 18.0, fg))
                    .padding(6)
                    .on_press(Message::Nav(to))
                    .style(theme::btn_text(p)),
            ]
            .align_y(Alignment::End),
        ]
        .height(Length::Fill),
    )
    .padding(Padding::from([20, 22]))
    .height(Length::Fill)
    .width(Length::FillPortion(2))
    .style(move |t| {
        if highlight {
            theme::card_inverted(p)(t)
        } else {
            theme::card(p)(t)
        }
    })
    .into()
}

/// En-tête de la vue d'ensemble (dans le bandeau beige).
pub fn hero(app: &App, p: Pal) -> El<'_> {
    let s = &app.snap;
    let t = s.totals;

    // 12 intervalles de 10 s sur les 2 dernières minutes.
    let mut solid = Vec::with_capacity(12);
    let mut hatched = Vec::with_capacity(12);
    let mut labels = Vec::with_capacity(12);
    for (i, chunk) in s.series.chunks(10).enumerate() {
        solid.push(chunk.iter().map(|x| x.requests as f32).sum());
        hatched.push(chunk.iter().map(|x| x.dns as f32).sum());
        let ago = (12 - i) * 10;
        labels.push(match i {
            0 | 4 | 8 => format!("-{ago} s"),
            11 => "0 s".into(),
            _ => String::new(),
        });
    }

    let chart = column![
        row![
            text("Activité, par tranche de 10 s")
                .size(size::HEADING)
                .font(UI_HEAVY)
                .color(p.text),
            horizontal_space(),
            legend(p, true, "Web"),
            legend(p, false, "DNS"),
        ]
        .spacing(14)
        .align_y(Alignment::Center),
        canvas(Bars {
            solid,
            hatched,
            labels,
            pal: p
        })
        .width(Length::Fill)
        .height(Length::Fill),
    ]
    .spacing(12)
    .width(Length::FillPortion(5));

    // Débit en temps réel, échelle adaptée au pic de la dernière minute.
    let scale = app.rate.scale();
    let gauge = container(
        canvas(Gauge {
            ratio: (app.rate.total() / scale) as f32,
            value: fmt::rate(app.rate.total()),
            caption: format!(
                "\u{2191} {}   \u{2193} {}",
                fmt::rate(app.rate.up),
                fmt::rate(app.rate.down)
            ),
            min_label: "0".into(),
            max_label: fmt::rate_round(scale),
            pal: p,
        })
        .width(Length::Fixed(270.0))
        .height(Length::Fixed(196.0)),
    )
    .width(Length::FillPortion(3))
    .center_x(Length::FillPortion(3))
    .center_y(Length::Fill);

    let unseen = s
        .alerts
        .iter()
        .filter(|a| a.id > app.alerts_cleared_at)
        .count();
    row![
        chart,
        gauge,
        stat(
            p,
            fmt::count(unseen as u64),
            "Alertes non lues",
            Page::Alerts,
            true,
        ),
        stat(
            p,
            fmt::bytes(t.live_bytes_up + t.live_bytes_down),
            "Volume échangé",
            Page::Traffic,
            false,
        ),
    ]
    .spacing(20)
    .height(Length::Fixed(200.0))
    .into()
}

fn legend<'a>(p: Pal, solid: bool, label: &str) -> El<'a> {
    let sw: El = if solid {
        container(Space::new(10, 10))
            .style(theme::fill_round(p.series, 3.0))
            .into()
    } else {
        container(Space::new(10, 10))
            .style(move |_| container::Style {
                border: iced::Border {
                    color: p.muted,
                    width: 1.0,
                    radius: 2.0.into(),
                },
                ..Default::default()
            })
            .into()
    };
    row![sw, text(label.to_string()).size(size::SMALL).color(p.muted)]
        .spacing(6)
        .align_y(Alignment::Center)
        .into()
}

/// Carte de type « kanban » : titre, description, pied avec puce et méta-données.
pub struct CardSpec<'a> {
    pub title: String,
    pub desc: String,
    pub time: String,
    pub meta: Vec<(Ico, String)>,
    pub action: Option<(Ico, Message)>,
    pub inverted: bool,
    pub soft: bool,
    pub accent: Option<Color>,
    pub extra: Option<El<'a>>,
}

pub fn kcard<'a>(p: Pal, c: CardSpec<'a>) -> El<'a> {
    let (fg, sub, border) = if c.inverted {
        (
            p.on_accent,
            theme::mix(p.on_accent, p.accent, 0.9),
            theme::mix(p.on_accent, p.accent, 0.5),
        )
    } else {
        (p.text, p.muted, p.line_strong)
    };
    let mut head = row![].spacing(8).align_y(Alignment::Center);
    if let Some(col) = c.accent {
        // Sur la carte jaune, le point prend la couleur du texte pour rester visible.
        let col = if c.inverted { p.on_accent } else { col };
        head = head.push(container(Space::new(8, 8)).style(theme::fill_round(col, 4.0)));
    }
    head = head
        .push(
            text(c.title)
                .size(size::HEADING)
                .font(UI_HEAVY)
                .color(fg)
                .wrapping(iced::widget::text::Wrapping::None)
                .width(Length::Fill),
        )
        .height(28);
    if let Some((ico, msg)) = c.action {
        head = head.push(
            button(icon(ico, 16.0, sub))
                .padding(5)
                .on_press(msg)
                .style(theme::btn_icon(p)),
        );
    }
    let mut meta = row![].spacing(12).align_y(Alignment::Center);
    for (ico, v) in c.meta {
        meta = meta.push(
            row![icon(ico, 14.0, fg), text(v).size(size::CAPTION).color(fg)]
                .spacing(5)
                .align_y(Alignment::Center),
        );
    }
    let mut body = column![head, text(c.desc).size(size::SMALL).color(sub)].spacing(8);
    if let Some(x) = c.extra {
        body = body.push(x);
    }
    body = body.push(Space::with_height(4)).push(
        row![
            pill(Ico::Clock, c.time, sub, border),
            horizontal_space(),
            meta
        ]
        .align_y(Alignment::Center),
    );
    container(body)
        .padding(Padding::from([18, 20]))
        .width(Length::Fill)
        .style(move |t| {
            if c.inverted {
                theme::card_inverted(p)(t)
            } else if c.soft {
                theme::card_soft(p)(t)
            } else {
                theme::card(p)(t)
            }
        })
        .into()
}

pub fn kcolumn<'a>(p: Pal, title: &str, count: usize, cards: Vec<El<'a>>, empty: El<'a>) -> El<'a> {
    let mut col = column![row![
        section_title(title, p),
        horizontal_space(),
        counter(p, count)
    ]
    .align_y(Alignment::Center)
    .height(40)]
    .spacing(12)
    .width(Length::FillPortion(1));
    if cards.is_empty() {
        col = col.push(container(empty).style(theme::card(p)));
    }
    for c in cards {
        col = col.push(c);
    }
    col.into()
}

pub fn view(app: &App, p: Pal) -> El<'_> {
    let s = &app.snap;
    let now = app.now;

    let domains: Vec<El> = s
        .top_domains
        .iter()
        .take(PER_COLUMN)
        .map(|d| {
            kcard(
                p,
                CardSpec {
                    title: d.domain.clone(),
                    desc: format!(
                        "{} requêtes · {}",
                        fmt::count(d.requests),
                        fmt::bytes(d.bytes)
                    ),
                    time: fmt::ago(d.last_ts, now),
                    meta: vec![(Ico::Host, d.clients.to_string())],
                    action: Some((Ico::Filter, Message::QuickBlock(d.domain.clone()))),
                    inverted: false,
                    soft: d.blocked == d.requests && d.blocked > 0,
                    accent: None,
                    extra: None,
                },
            )
        })
        .collect();

    let clients: Vec<El> = s
        .top_clients
        .iter()
        .take(PER_COLUMN)
        .map(|c| {
            kcard(
                p,
                CardSpec {
                    title: c.client.to_string(),
                    desc: format!(
                        "{} requêtes web · {} DNS\nenvoyé {} · reçu {}",
                        fmt::count(c.requests),
                        fmt::count(c.dns),
                        fmt::bytes(c.bytes_up),
                        fmt::bytes(c.bytes_down)
                    ),
                    time: fmt::ago(c.last_ts, now),
                    meta: vec![
                        (Ico::Filter, c.blocked.to_string()),
                        (Ico::Alert, c.alerts.to_string()),
                    ],
                    action: None,
                    inverted: false,
                    soft: false,
                    accent: None,
                    extra: None,
                },
            )
        })
        .collect();

    // Blocages récents (web et DNS), un par hôte.
    let mut seen = std::collections::HashSet::new();
    let mut blocks: Vec<(i64, String, String, String, String)> = s
        .recent_http
        .iter()
        .filter(|e| e.action == Action::Block)
        .map(|e| {
            (
                e.ts,
                e.host.clone(),
                e.reason.clone().unwrap_or_default(),
                e.category.clone().unwrap_or_default(),
                e.client.to_string(),
            )
        })
        .chain(
            s.recent_dns
                .iter()
                .filter(|e| e.action == Action::Block)
                .map(|e| {
                    (
                        e.ts,
                        e.qname.clone(),
                        e.reason.clone().unwrap_or_default(),
                        e.category.clone().unwrap_or_default(),
                        e.client.to_string(),
                    )
                }),
        )
        .collect();
    blocks.sort_by_key(|b| std::cmp::Reverse(b.0));
    blocks.retain(|b| seen.insert(b.1.clone()));
    let n_blocks = blocks.len();
    let blocks: Vec<El> = blocks
        .into_iter()
        .take(PER_COLUMN)
        .map(|(ts, host, reason, cat, client)| {
            let threat = category_color(p, &cat) == p.danger;
            kcard(
                p,
                CardSpec {
                    title: host,
                    desc: reason,
                    time: fmt::clock(ts),
                    meta: vec![(Ico::Host, client)],
                    action: None,
                    inverted: false,
                    soft: true,
                    accent: threat.then_some(p.danger),
                    extra: None,
                },
            )
        })
        .collect();

    // Alertes : la plus récente non lue est mise en avant.
    let newest_unseen = s
        .alerts
        .iter()
        .rev()
        .find(|a| a.id > app.alerts_cleared_at)
        .map(|a| a.id);
    let alerts: Vec<El> = s
        .alerts
        .iter()
        .rev()
        .take(PER_COLUMN)
        .map(|a| {
            kcard(
                p,
                CardSpec {
                    title: a.kind.label().into(),
                    desc: fmt::truncate(&a.detail, 90),
                    time: fmt::clock(a.ts),
                    meta: vec![(Ico::Host, a.client.to_string())],
                    action: None,
                    inverted: Some(a.id) == newest_unseen,
                    soft: a.id <= app.alerts_cleared_at,
                    accent: (a.severity >= Severity::Medium).then(|| p.severity(a.severity)),
                    extra: None,
                },
            )
        })
        .collect();

    vscroll(
        p,
        row![
            kcolumn(
                p,
                "Domaines",
                s.top_domains.len(),
                domains,
                empty_state(
                    p,
                    Ico::Globe,
                    "Pas encore de trafic",
                    "Configurez un client sur le proxy."
                )
            ),
            kcolumn(
                p,
                "Clients",
                s.top_clients.len(),
                clients,
                empty_state(p, Ico::Host, "Aucun client", "Les postes apparaîtront ici.")
            ),
            kcolumn(
                p,
                "Blocages",
                n_blocks,
                blocks,
                empty_state(p, Ico::Filter, "Aucun blocage", "Rien n'a été filtré.")
            ),
            kcolumn(
                p,
                "Alertes",
                s.alerts.len(),
                alerts,
                empty_state(p, Ico::Check, "Aucune alerte", "Le trafic est conforme.")
            ),
        ]
        .spacing(GAP + 4),
    )
}
