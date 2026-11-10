//! Tableaux temps réel : trafic web et requêtes DNS.

use super::widgets::{caps, cell, divider, empty_state, icon_btn, mono, seg, vscroll, El, GAP};
use crate::app::{ActionFilter, App, Message};
use crate::fmt;
use crate::icons::{icon, Ico};
use crate::theme::{self, Pal, MONO, UI_BOLD};
use ferrox_core::event::{Action, Scheme};
use iced::widget::{column, container, horizontal_space, row, text, text_input, tooltip, Space};
use iced::{Alignment, Background, Color, Length, Padding, Theme};

const MAX_ROWS: usize = 250;

fn row_style(_p: Pal, _i: usize, _blocked: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style::default()
}

fn toolbar<'a>(
    p: Pal,
    query: &str,
    on_query: fn(String) -> Message,
    filter: ActionFilter,
    on_filter: fn(ActionFilter) -> Message,
    (shown, total): (usize, usize),
    placeholder: &str,
) -> El<'a> {
    let search = container(
        row![
            icon(Ico::Search, 17.0, p.muted),
            text_input(placeholder, query)
                .on_input(on_query)
                .font(MONO)
                .size(14)
                .padding(Padding::from([9, 0]))
                .style(move |t, s| {
                    let mut st = theme::input(p)(t, s);
                    st.border.width = 0.0;
                    st.background = Background::Color(Color::TRANSPARENT);
                    st
                }),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([0, 14]))
    .width(Length::Fixed(400.0))
    .style(theme::card(p));
    row![
        search,
        seg(
            p,
            vec![
                (
                    "Tout".into(),
                    filter == ActionFilter::All,
                    on_filter(ActionFilter::All)
                ),
                (
                    "Autorisé".into(),
                    filter == ActionFilter::Allowed,
                    on_filter(ActionFilter::Allowed)
                ),
                (
                    "Bloqué".into(),
                    filter == ActionFilter::Blocked,
                    on_filter(ActionFilter::Blocked)
                ),
            ]
        ),
        horizontal_space(),
        mono(format!("{shown} affichées sur {total}"), 13, p.muted),
    ]
    .spacing(12)
    .align_y(Alignment::Center)
    .into()
}

fn status_color(p: Pal, status: u16, blocked: bool) -> Color {
    if blocked {
        return p.danger;
    }
    match status {
        200..=299 => p.text,
        0 => p.faint,
        500.. => p.danger,
        _ => p.muted,
    }
}

fn pass(action: Action, f: ActionFilter) -> bool {
    match f {
        ActionFilter::All => true,
        ActionFilter::Allowed => action == Action::Allow,
        ActionFilter::Blocked => action == Action::Block,
    }
}

fn table<'a>(p: Pal, header: El<'a>, rows: Vec<El<'a>>, empty: El<'a>) -> El<'a> {
    let body: El = if rows.is_empty() {
        empty
    } else {
        let mut col = column![];
        for r in rows {
            col = col.push(r).push(divider(p));
        }
        vscroll(p, col)
    };
    container(
        column![
            container(header).padding(Padding::from([14, 20])),
            divider(p),
            body
        ]
        .height(Length::Fill),
    )
    .style(theme::card(p))
    .height(Length::Fill)
    .into()
}

pub fn http_view(app: &App, p: Pal) -> El<'_> {
    let q = app.traffic_query.to_ascii_lowercase();
    let all = &app.snap.recent_http;
    let rows_src: Vec<_> = all
        .iter()
        .rev()
        .filter(|e| pass(e.action, app.traffic_filter))
        .filter(|e| {
            q.is_empty()
                || e.host.contains(&q)
                || e.client.to_string().contains(&q)
                || e.path
                    .as_deref()
                    .is_some_and(|x| x.to_ascii_lowercase().contains(&q))
                || e.user_agent
                    .as_deref()
                    .is_some_and(|x| x.to_ascii_lowercase().contains(&q))
                || e.method.to_ascii_lowercase() == q
        })
        .take(MAX_ROWS)
        .collect();

    let w = |px: f32| Length::Fixed(px);
    let header = row![
        cell(caps("Heure", p), w(76.0)),
        cell(caps("Client", p), w(124.0)),
        cell(caps("Méthode", p), w(72.0)),
        cell(caps("Hôte", p), Length::FillPortion(3)),
        cell(caps("Chemin / motif", p), Length::FillPortion(4)),
        cell(caps("Statut", p), w(52.0)),
        cell(caps("Envoyé", p), w(72.0)),
        cell(caps("Reçu", p), w(72.0)),
        cell(caps("Durée", p), w(62.0)),
        Space::with_width(26),
    ]
    .spacing(10);

    let rows: Vec<El> = rows_src
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let blocked = e.action == Action::Block;
            let host_cell: El = {
                let mut r = row![].spacing(6).align_y(Alignment::Center);
                match e.scheme {
                    Scheme::Https => r = r.push(icon(Ico::Lock, 14.0, p.text)),
                    Scheme::Tunnel => r = r.push(icon(Ico::Lock, 14.0, p.faint)),
                    Scheme::Http => {}
                }
                let port = match (e.scheme, e.port) {
                    (Scheme::Http, 80) | (Scheme::Https | Scheme::Tunnel, 443) => String::new(),
                    (_, port) => format!(":{port}"),
                };
                r = r.push(mono(
                    fmt::truncate(&format!("{}{port}", e.host), 34),
                    13,
                    p.text,
                ));
                let inner = cell(r, Length::Fill);
                match &e.user_agent {
                    Some(ua) => tooltip(
                        inner,
                        container(mono(fmt::truncate(ua, 160), 11, p.text))
                            .padding(8)
                            .max_width(460)
                            .style(theme::raised(p)),
                        tooltip::Position::Bottom,
                    )
                    .into(),
                    None => inner,
                }
            };
            let detail: El = if blocked {
                mono(
                    fmt::truncate(&e.reason.clone().unwrap_or_default(), 48),
                    13,
                    p.danger,
                )
                .into()
            } else if let Some(r) = &e.reason {
                mono(r, 13, p.muted).into()
            } else if e.scheme == Scheme::Tunnel {
                text("tunnel chiffré").size(13).color(p.faint).into()
            } else {
                mono(
                    fmt::truncate(&e.path.clone().unwrap_or_default(), 56),
                    13,
                    p.muted,
                )
                .into()
            };
            container(
                row![
                    cell(mono(fmt::clock(e.ts), 13, p.muted), w(76.0)),
                    cell(mono(e.client, 13, p.text), w(124.0)),
                    cell(
                        text(e.method.clone()).size(13).font(UI_BOLD).color(p.muted),
                        w(72.0)
                    ),
                    container(host_cell)
                        .width(Length::FillPortion(3))
                        .clip(true),
                    cell(detail, Length::FillPortion(4)),
                    cell(
                        mono(e.status, 12, status_color(p, e.status, blocked)),
                        w(52.0)
                    ),
                    cell(mono(fmt::bytes(e.bytes_up), 13, p.muted), w(72.0)),
                    cell(mono(fmt::bytes(e.bytes_down), 13, p.muted), w(72.0)),
                    cell(mono(fmt::duration_ms(e.duration_ms), 13, p.faint), w(62.0)),
                    if blocked {
                        El::from(Space::with_width(26))
                    } else {
                        icon_btn(p, Ico::Filter, p.muted, Message::QuickBlock(e.host.clone()))
                    },
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            )
            .padding(Padding::from([8, 20]))
            .style(row_style(p, i, blocked))
            .into()
        })
        .collect();

    let shown = rows.len();
    column![
        toolbar(
            p,
            &app.traffic_query,
            Message::TrafficQuery,
            app.traffic_filter,
            Message::TrafficFilter,
            (shown, all.len()),
            "Filtrer : hôte, client, chemin, User-Agent…",
        ),
        table(
            p,
            header.into(),
            rows,
            empty_state(
                p,
                Ico::Traffic,
                "Aucune requête",
                "Configurez le navigateur ou le système pour utiliser le proxy Ferrox.",
            ),
        ),
    ]
    .spacing(GAP)
    .height(Length::Fill)
    .into()
}

pub fn dns_view(app: &App, p: Pal) -> El<'_> {
    let q = app.dns_query.to_ascii_lowercase();
    let all = &app.snap.recent_dns;
    let rows_src: Vec<_> = all
        .iter()
        .rev()
        .filter(|e| pass(e.action, app.dns_filter))
        .filter(|e| {
            q.is_empty()
                || e.qname.contains(&q)
                || e.client.to_string().contains(&q)
                || e.qtype.to_ascii_lowercase() == q
                || e.rcode.to_ascii_lowercase() == q
        })
        .take(MAX_ROWS)
        .collect();

    let w = |px: f32| Length::Fixed(px);
    let header = row![
        cell(caps("Heure", p), w(76.0)),
        cell(caps("Client", p), w(124.0)),
        cell(caps("Nom", p), Length::FillPortion(5)),
        cell(caps("Type", p), w(56.0)),
        cell(caps("Réponse", p), w(92.0)),
        cell(caps("Rép.", p), w(40.0)),
        cell(caps("Latence", p), w(66.0)),
        cell(caps("Source", p), w(68.0)),
        cell(caps("Motif", p), Length::FillPortion(3)),
        Space::with_width(26),
    ]
    .spacing(10);

    let rows: Vec<El> = rows_src
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let blocked = e.action == Action::Block;
            let rc_color = match e.rcode.as_str() {
                _ if blocked => p.danger,
                "NOERROR" => p.text,
                "NXDOMAIN" => p.muted,
                _ => p.danger,
            };
            let (src, src_c) = if blocked {
                ("filtre", p.danger)
            } else if e.cached {
                ("cache", p.text)
            } else {
                ("amont", p.muted)
            };
            container(
                row![
                    cell(mono(fmt::clock(e.ts), 13, p.muted), w(76.0)),
                    cell(mono(e.client, 13, p.text), w(124.0)),
                    cell(
                        mono(fmt::truncate(&e.qname, 64), 13, p.text),
                        Length::FillPortion(5)
                    ),
                    cell(
                        text(e.qtype.clone()).size(13).font(UI_BOLD).color(p.muted),
                        w(56.0)
                    ),
                    cell(mono(&e.rcode, 12, rc_color), w(92.0)),
                    cell(mono(e.answers, 13, p.muted), w(40.0)),
                    cell(mono(fmt::duration_ms(e.latency_ms), 13, p.faint), w(66.0)),
                    cell(mono(src, 12, src_c), w(68.0)),
                    cell(
                        mono(
                            e.reason.clone().unwrap_or_default(),
                            12,
                            if blocked { p.danger } else { p.muted }
                        ),
                        Length::FillPortion(3)
                    ),
                    if blocked {
                        El::from(Space::with_width(26))
                    } else {
                        icon_btn(
                            p,
                            Ico::Filter,
                            p.muted,
                            Message::QuickBlock(e.qname.clone()),
                        )
                    },
                ]
                .spacing(10)
                .align_y(Alignment::Center),
            )
            .padding(Padding::from([8, 20]))
            .style(row_style(p, i, blocked))
            .into()
        })
        .collect();

    let shown = rows.len();
    let listen = app.config.dns.listen.clone();
    column![
        toolbar(
            p,
            &app.dns_query,
            Message::DnsQuery,
            app.dns_filter,
            Message::DnsFilter,
            (shown, all.len()),
            "Filtrer : nom, client, type (TXT…), réponse (NXDOMAIN…)",
        ),
        table(
            p,
            header.into(),
            rows,
            empty_state(
                p,
                Ico::Dns,
                "Aucune requête DNS",
                &format!("Pointez le DNS des clients vers {listen}."),
            ),
        ),
    ]
    .spacing(GAP)
    .height(Length::Fill)
    .into()
}
