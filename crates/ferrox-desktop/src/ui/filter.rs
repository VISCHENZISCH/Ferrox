//! Page Filtrage : listes, catégories UT1, blocage manuel, exceptions, types de fichiers.

use super::overview::category_color;
use super::widgets::{
    btn, card, chip, hint, input_add, mono, mono_wrap, tag, toggle_row, El, Kind,
};
use crate::app::{App, ListKind, Message, Toggle};
use crate::fmt;
use crate::icons::{icon, Ico};
use crate::theme::{self, Pal, UI_BOLD};
use iced::widget::{column, container, horizontal_space, row, text, toggler, Space};
use iced::{Alignment, Length, Padding};

fn tags<'a>(p: Pal, items: &[String], kind: ListKind, empty: &str) -> El<'a> {
    if items.is_empty() {
        return text(empty.to_string()).size(12).color(p.faint).into();
    }
    let mut r = row![].spacing(6);
    for (i, it) in items.iter().enumerate() {
        r = r.push(tag(p, it, Message::RemoveItem(kind, i)));
    }
    r.wrap().into()
}

pub fn view(app: &App, p: Pal) -> El<'_> {
    let f = &app.draft.filter;

    // Listes de blocage.
    let mut lists = column![].spacing(12);
    for (i, l) in f.lists.iter().enumerate() {
        let status = app.list_status.iter().find(|r| r.name == l.name);
        let status_el: El = match status {
            Some(r) if r.ok => mono(&r.message, 11, p.ok).into(),
            Some(r) => mono(fmt::truncate(&r.message, 40), 11, p.danger).into(),
            None => Space::new(0, 0).into(),
        };
        lists = lists.push(
            row![
                toggler(l.enabled)
                    .on_toggle(move |v| Message::ToggleList(i, v))
                    .size(18)
                    .style(theme::toggle(p)),
                column![
                    row![
                        text(l.name.clone()).size(14).font(UI_BOLD).color(p.text),
                        chip(p, &l.category, category_color(p, &l.category)),
                    ]
                    .spacing(8)
                    .align_y(Alignment::Center),
                    mono(fmt::truncate(&l.url, 64), 11, p.faint),
                ]
                .spacing(3)
                .width(Length::Fill),
                status_el,
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        );
    }
    let mut lists_footer = column![row![
        icon(Ico::Globe, 14.0, p.steel),
        mono(
            format!(
                "{} domaines actifs dans le moteur",
                fmt::count(app.filter_domains as u64)
            ),
            12,
            p.text
        ),
    ]
    .spacing(8)
    .align_y(Alignment::Center)]
    .spacing(4);
    for e in &app.filter_errors {
        lists_footer = lists_footer.push(text(e.clone()).size(12).color(p.warn));
    }
    let update_btn = if app.updating {
        btn(p, "Téléchargement…", Some(Ico::Refresh), Kind::Ghost, None)
    } else {
        btn(
            p,
            "Mettre à jour",
            Some(Ico::Refresh),
            Kind::Ghost,
            Some(Message::UpdateLists),
        )
    };
    let lists_card = card(
        p,
        "Listes de blocage",
        Some(Ico::List),
        Some(update_btn),
        column![
            lists,
            container(Space::new(Length::Fill, 1)).style(theme::fill(p.line)),
            lists_footer
        ]
        .spacing(20)
        .into(),
    );

    // Catégories UT1.
    let cat_dir = app.paths.categories_dir(f);
    let categories_card = card(
        p,
        "Catégories (base UT1)",
        Some(Ico::Filter),
        Some(btn(p, "Ouvrir le dossier", Some(Ico::Export), Kind::Ghost, Some(Message::OpenFolder(cat_dir.clone())))),
        column![
            hint(p, "Base de l'Université Toulouse Capitole : extrayez l'archive dans le dossier, chaque catégorie y a son sous-dossier avec un fichier « domains »."),
            mono_wrap(cat_dir.display().to_string(), 11, p.muted),
            input_add(
                p,
                "catégorie (adult, gambling, malware, phishing…)",
                &app.inputs[ListKind::Category as usize],
                |v| Message::Input(ListKind::Category, v),
                Message::AddItem(ListKind::Category),
            ),
            tags(p, &f.blocked_categories, ListKind::Category, "Aucune catégorie bloquée."),
        ]
        .spacing(10)
        .into(),
    );

    let block_card = card(
        p,
        "Blocage manuel",
        Some(Ico::Close),
        Some(mono(f.custom_block.len(), 12, p.muted).into()),
        column![
            input_add(
                p,
                "domaine.exemple (sous-domaines inclus)",
                &app.inputs[ListKind::Block as usize],
                |v| Message::Input(ListKind::Block, v),
                Message::AddItem(ListKind::Block),
            ),
            tags(
                p,
                &f.custom_block,
                ListKind::Block,
                "Aucun domaine bloqué manuellement."
            ),
        ]
        .spacing(10)
        .into(),
    );

    let allow_card = card(
        p,
        "Toujours autorisés",
        Some(Ico::Check),
        Some(mono(f.allow.len(), 12, p.muted).into()),
        column![
            hint(p, "Prioritaires sur toutes les listes (faux positifs)."),
            input_add(
                p,
                "domaine.exemple",
                &app.inputs[ListKind::Allow as usize],
                |v| Message::Input(ListKind::Allow, v),
                Message::AddItem(ListKind::Allow),
            ),
            tags(p, &f.allow, ListKind::Allow, "Aucune exception."),
        ]
        .spacing(10)
        .into(),
    );

    let files_card = card(
        p,
        "Types de fichiers",
        Some(Ico::Export),
        None,
        column![
            input_add(
                p,
                "extension (exe, msi, ps1, iso…)",
                &app.inputs[ListKind::Ext as usize],
                |v| Message::Input(ListKind::Ext, v),
                Message::AddItem(ListKind::Ext),
            ),
            tags(
                p,
                &f.blocked_extensions,
                ListKind::Ext,
                "Aucune extension bloquée."
            ),
            toggle_row(
                p,
                "Inspecter les signatures",
                "Reconnaît un exécutable même renommé (premiers octets du fichier).",
                f.sniff_magic,
                |v| Message::Flag(Toggle::Sniff, v),
            ),
            hint(
                p,
                "Sans interception TLS, seuls les téléchargements HTTP en clair sont inspectés."
            ),
        ]
        .spacing(12)
        .into(),
    );

    let dirty = app.filter_dirty();
    let footer = container(
        row![
            if dirty {
                row![
                    icon(Ico::Alert, 14.0, p.warn),
                    text("Modifications non appliquées").size(13).color(p.warn)
                ]
                .spacing(8)
                .align_y(Alignment::Center)
            } else {
                row![
                    icon(Ico::Check, 14.0, p.ok),
                    text("Filtrage à jour").size(13).color(p.muted)
                ]
                .spacing(8)
                .align_y(Alignment::Center)
            },
            horizontal_space(),
            btn(
                p,
                "Appliquer à chaud",
                Some(Ico::Check),
                Kind::Primary,
                dirty.then_some(Message::ApplyFilter),
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
                column![lists_card, categories_card]
                    .spacing(20)
                    .width(Length::FillPortion(1)),
                column![block_card, allow_card, files_card]
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
