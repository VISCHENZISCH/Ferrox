//! Page des alertes : une colonne par gravité, cartes détaillées, blocage en un clic.

use super::overview::{kcard, kcolumn, CardSpec};
use super::widgets::{empty_state, vscroll, El, GAP};
use crate::app::{App, Message};
use crate::fmt;
use crate::icons::Ico;
use crate::theme::Pal;
use ferrox_core::event::{AlertKind, Severity};
use iced::widget::row;

const PER_COLUMN: usize = 40;

pub fn view(app: &App, p: Pal) -> El<'_> {
    let s = &app.snap;
    let newest_unseen = s
        .alerts
        .iter()
        .rev()
        .find(|a| a.id > app.alerts_cleared_at && a.severity >= Severity::High)
        .map(|a| a.id);

    let column_for = |sev: &[Severity], title: &str, empty_hint: &str| {
        let list: Vec<_> = s
            .alerts
            .iter()
            .rev()
            .filter(|a| sev.contains(&a.severity))
            .collect();
        let n = list.len();
        let cards: Vec<El> = list
            .into_iter()
            .take(PER_COLUMN)
            .map(|a| {
                let blockable = a.target != "*" && a.kind != AlertKind::SuspiciousUserAgent;
                kcard(
                    p,
                    CardSpec {
                        title: a.kind.label().into(),
                        desc: format!(
                            "{} → {}\n{}",
                            a.client,
                            fmt::truncate(&a.target, 48),
                            a.detail
                        ),
                        time: format!("{} · {}", fmt::clock(a.ts), fmt::ago(a.ts, app.now)),
                        meta: vec![(Ico::Pulse, format!("{:.0} %", a.score * 100.0))],
                        action: blockable
                            .then(|| (Ico::Filter, Message::QuickBlock(a.target.clone()))),
                        inverted: Some(a.id) == newest_unseen,
                        soft: a.id <= app.alerts_cleared_at,
                        accent: (a.severity >= Severity::High).then_some(p.danger),
                        extra: None,
                    },
                )
            })
            .collect();
        kcolumn(
            p,
            title,
            n,
            cards,
            empty_state(p, Ico::Check, "Rien à signaler", empty_hint),
        )
    };

    vscroll(
        p,
        row![
            column_for(
                &[Severity::Critical],
                "Critiques",
                "Aucune alerte critique."
            ),
            column_for(
                &[Severity::High],
                "Hautes",
                "Balises C2, exfiltration, tunnels."
            ),
            column_for(&[Severity::Medium], "Moyennes", "DGA, User-Agent d'outils."),
            column_for(&[Severity::Low], "Faibles", "Signaux faibles."),
        ]
        .spacing(GAP + 4),
    )
}
