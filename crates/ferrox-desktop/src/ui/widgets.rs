//! Composants d'interface Ferrox.

use crate::app::Message;
use crate::icons::{icon, Ico};
use crate::theme::{self, size, Pal, MONO, UI, UI_BOLD, UI_HEAVY};
use iced::widget::{
    button, column, container, horizontal_space, row, scrollable, text, text_input, toggler, Space,
};
use iced::{Alignment, Color, Element, Length, Padding};

pub type El<'a> = Element<'a, Message>;

/// Espacements (grille de 4 px).
pub const GAP: u16 = 16;

/// Petit libellé discret (en-têtes de colonnes, légendes).
pub fn caps<'a>(s: &str, p: Pal) -> iced::widget::Text<'a> {
    text(s.to_string()).size(size::CAPTION).color(p.muted)
}

/// Titre de section.
pub fn section_title<'a>(s: &str, p: Pal) -> iced::widget::Text<'a> {
    text(s.to_string())
        .size(size::TITLE)
        .font(UI_HEAVY)
        .color(p.text)
}

/// Compteur teinté à droite d'un titre de section.
pub fn counter<'a>(p: Pal, n: usize) -> El<'a> {
    container(
        row![
            text(n.to_string())
                .size(size::CAPTION)
                .font(UI_HEAVY)
                .color(p.text),
            icon(Ico::Sort, 14.0, p.accent_ink),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([5, 10]))
    .style(theme::accent_chip(p))
    .into()
}

pub fn card<'a>(
    p: Pal,
    title: &str,
    _ico: Option<Ico>,
    right: Option<El<'a>>,
    body: El<'a>,
) -> El<'a> {
    let mut head = row![text(title.to_string())
        .size(size::HEADING)
        .font(UI_HEAVY)
        .color(p.text)]
    .spacing(10)
    .align_y(Alignment::Center)
    .height(32);
    head = head.push(horizontal_space());
    if let Some(r) = right {
        head = head.push(r);
    }
    container(column![head, body].spacing(16))
        .padding(Padding::from([20, 24]))
        .width(Length::Fill)
        .style(theme::card(p))
        .into()
}

#[derive(Clone, Copy)]
pub enum Kind {
    Primary,
    Ghost,
    /// Action destructive (style prêt, pas encore utilisé).
    #[allow(dead_code)]
    Danger,
    Text,
}

pub fn btn<'a>(p: Pal, label: &str, ico: Option<Ico>, kind: Kind, msg: Option<Message>) -> El<'a> {
    let fg = match kind {
        Kind::Primary => p.on_accent,
        Kind::Ghost | Kind::Text => p.text,
        Kind::Danger => p.danger,
    };
    let mut r = row![].spacing(8).align_y(Alignment::Center);
    if let Some(i) = ico {
        r = r.push(icon(i, 17.0, fg));
    }
    r = r.push(
        text(label.to_string())
            .size(size::BODY)
            .font(UI_HEAVY)
            .color(fg)
            .wrapping(iced::widget::text::Wrapping::None),
    );
    let pad = match kind {
        Kind::Primary => Padding::from([11, 20]),
        Kind::Text => Padding::from([9, 12]),
        _ => Padding::from([10, 16]),
    };
    let b = button(r).padding(pad).on_press_maybe(msg);
    match kind {
        Kind::Primary => b.style(theme::btn_primary(p)),
        Kind::Ghost => b.style(theme::btn_ghost(p)),
        Kind::Danger => b.style(theme::btn_danger(p)),
        Kind::Text => b.style(theme::btn_text(p)),
    }
    .into()
}

pub fn icon_btn<'a>(p: Pal, ico: Ico, color: Color, msg: Message) -> El<'a> {
    button(icon(ico, 16.0, color))
        .padding(6)
        .on_press(msg)
        .style(theme::btn_icon(p))
        .into()
}

/// Étiquette neutre ; la couleur ne sert qu'au texte.
pub fn chip<'a>(p: Pal, label: &str, color: Color) -> El<'a> {
    container(
        text(label.to_string())
            .size(size::CAPTION)
            .font(UI_BOLD)
            .color(color),
    )
    .padding(Padding::from([3, 9]))
    .style(theme::chip(color, p))
    .into()
}

/// Méta-donnée avec icône (heure, compteur) : sans cadre, discrète.
pub fn pill<'a>(ico: Ico, label: String, fg: Color, _border: Color) -> El<'a> {
    row![
        icon(ico, 14.0, fg),
        text(label).size(size::CAPTION).font(UI_BOLD).color(fg)
    ]
    .spacing(6)
    .align_y(Alignment::Center)
    .into()
}

/// État d'un échange : point et libellé sur un fond teinté de la même couleur.
pub fn state_chip<'a>(p: Pal, label: &str, color: Color) -> El<'a> {
    container(
        row![
            container(Space::new(6, 6)).style(theme::fill_round(color, 3.0)),
            text(label.to_string())
                .size(size::CAPTION)
                .font(UI_HEAVY)
                .color(color)
                .wrapping(iced::widget::text::Wrapping::None),
        ]
        .spacing(6)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([3, 8]))
    .style(theme::fill_round(
        theme::alpha(color, if p.dark { 0.14 } else { 0.1 }),
        6.0,
    ))
    .into()
}

/// Puce supprimable (listes manuelles, extensions...).
pub fn tag<'a>(p: Pal, label: &str, msg: Message) -> El<'a> {
    container(
        row![
            text(label.to_string()).size(size::SMALL).color(p.text),
            button(icon(Ico::Close, 13.0, p.muted))
                .padding(3)
                .on_press(msg)
                .style(theme::btn_icon(p)),
        ]
        .spacing(4)
        .align_y(Alignment::Center),
    )
    .padding(Padding::from([3, 4]).left(12))
    .style(theme::chip(p.text, p))
    .into()
}

pub fn seg<'a>(p: Pal, items: Vec<(String, bool, Message)>) -> El<'a> {
    let mut r = row![].spacing(2);
    for (label, active, msg) in items {
        r = r.push(
            button(
                text(label)
                    .size(size::SMALL)
                    .font(if active { UI_BOLD } else { UI }),
            )
            .padding(Padding::from([6, 14]))
            .on_press(msg)
            .style(theme::btn_seg(p, active)),
        );
    }
    container(r).padding(3).style(theme::seg_track(p)).into()
}

pub fn field<'a>(
    p: Pal,
    label: &str,
    value: &str,
    placeholder: &str,
    on: impl Fn(String) -> Message + 'a,
) -> El<'a> {
    column![
        text(label.to_string())
            .size(size::SMALL)
            .font(UI_BOLD)
            .color(p.muted),
        text_input(placeholder, value)
            .on_input(on)
            .font(MONO)
            .size(size::BODY)
            .padding(Padding::from([11, 14]))
            .style(theme::input(p)),
    ]
    .spacing(7)
    .width(Length::Fill)
    .into()
}

/// Boîte de recherche remplie (barre supérieure, tableaux).
pub fn search_box<'a>(
    p: Pal,
    placeholder: &str,
    value: &str,
    on: impl Fn(String) -> Message + 'a,
    submit: Option<Message>,
    width: f32,
) -> El<'a> {
    let mut input = text_input(placeholder, value)
        .on_input(on)
        .size(size::BODY)
        .padding(Padding::from([10, 0]))
        .style(theme::input_bare(p));
    if let Some(m) = submit {
        input = input.on_submit(m);
    }
    container(
        row![icon(Ico::Search, 18.0, p.muted), input]
            .spacing(10)
            .align_y(Alignment::Center),
    )
    .padding(Padding::from([0, 14]))
    .width(Length::Fixed(width))
    .style(theme::seg_track(p))
    .into()
}

/// Champ masqué (mot de passe).
pub fn secret_field<'a>(
    p: Pal,
    label: &str,
    value: &str,
    placeholder: &str,
    on: impl Fn(String) -> Message + 'a,
) -> El<'a> {
    column![
        text(label.to_string())
            .size(size::SMALL)
            .font(UI_BOLD)
            .color(p.muted),
        text_input(placeholder, value)
            .on_input(on)
            .secure(true)
            .font(MONO)
            .size(size::BODY)
            .padding(Padding::from([11, 14]))
            .style(theme::input(p)),
    ]
    .spacing(7)
    .width(Length::Fill)
    .into()
}

pub fn input_add<'a>(
    p: Pal,
    placeholder: &str,
    value: &str,
    on: impl Fn(String) -> Message + 'a,
    submit: Message,
) -> El<'a> {
    row![
        text_input(placeholder, value)
            .on_input(on)
            .on_submit(submit.clone())
            .font(MONO)
            .size(size::BODY)
            .padding(Padding::from([11, 14]))
            .style(theme::input(p)),
        button(icon(Ico::Plus, 18.0, p.on_accent))
            .padding(13)
            .on_press(submit)
            .style(theme::btn_primary(p)),
    ]
    .spacing(8)
    .align_y(Alignment::Center)
    .into()
}

pub fn toggle_row<'a>(
    p: Pal,
    label: &str,
    hint: &str,
    value: bool,
    on: impl Fn(bool) -> Message + 'a,
) -> El<'a> {
    let mut col = column![text(label.to_string())
        .size(size::BODY)
        .font(UI_BOLD)
        .color(p.text)]
    .spacing(3);
    if !hint.is_empty() {
        col = col.push(text(hint.to_string()).size(size::SMALL).color(p.muted));
    }
    row![
        col.width(Length::Fill),
        toggler(value)
            .on_toggle(on)
            .size(20)
            .style(theme::toggle(p)),
    ]
    .spacing(16)
    .align_y(Alignment::Center)
    .into()
}

/// Cellule de tableau à largeur fixe ou extensible, contenu tronqué.
pub fn cell<'a>(content: impl Into<El<'a>>, width: Length) -> El<'a> {
    container(content).width(width).clip(true).into()
}

/// Texte de données sur une seule ligne (cellules, valeurs).
pub fn mono<'a>(s: impl ToString, size: u16, color: Color) -> iced::widget::Text<'a> {
    text(s.to_string())
        .size(size)
        .font(MONO)
        .color(color)
        .wrapping(iced::widget::text::Wrapping::None)
}

/// Texte de données pouvant passer à la ligne (chemins).
pub fn mono_wrap<'a>(s: impl ToString, size: u16, color: Color) -> iced::widget::Text<'a> {
    text(s.to_string())
        .size(size)
        .font(MONO)
        .color(color)
        .wrapping(iced::widget::text::Wrapping::WordOrGlyph)
}

pub fn empty_state<'a>(p: Pal, ico: Ico, title: &str, hint: &str) -> El<'a> {
    container(
        column![
            icon(ico, 24.0, p.faint),
            text(title.to_string())
                .size(size::HEADING)
                .font(UI_BOLD)
                .color(p.text),
            text(hint.to_string()).size(size::SMALL).color(p.muted),
        ]
        .spacing(8)
        .align_x(Alignment::Center),
    )
    .width(Length::Fill)
    .padding(32)
    .center_x(Length::Fill)
    .into()
}

pub fn hint<'a>(p: Pal, s: &str) -> El<'a> {
    text(s.to_string()).size(size::SMALL).color(p.muted).into()
}

/// Zone défilante sans barre visible.
pub fn vscroll<'a>(p: Pal, content: impl Into<El<'a>>) -> El<'a> {
    scrollable(content)
        .direction(theme::hidden_bar())
        .style(theme::scroll(p))
        .height(Length::Fill)
        .into()
}

/// Séparateur horizontal fin.
pub fn divider<'a>(p: Pal) -> El<'a> {
    container(Space::new(Length::Fill, 1))
        .style(theme::fill(p.line))
        .into()
}
