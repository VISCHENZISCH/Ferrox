//! Identité visuelle Ferrox, palette « Nocturne » : surfaces neutres (blanc, ou noirs et gris
//! sans teinte en sombre), violet #7C3AED pour les actions et l'élément actif. Les couleurs
//! d'état ne se confondent jamais avec la marque : vert autorisé, rouge bloqué, cyan inspecté
//! (interception TLS), gris tunnel ; gravité gris, orange, rouge, magenta.
//! Une seule famille (IBM Plex Sans) et une échelle fixe (`size`).

use ferrox_core::event::Severity;
use iced::font::Weight;
use iced::widget::{button, container, scrollable, text_input, toggler};
use iced::{Background, Border, Color, Font, Shadow, Theme, Vector};

const FAMILY: &str = "IBM Plex Sans";
pub const UI: Font = Font::with_name(FAMILY);
pub const UI_BOLD: Font = Font {
    weight: Weight::Medium,
    ..Font::with_name(FAMILY)
};
pub const UI_HEAVY: Font = Font {
    weight: Weight::Semibold,
    ..Font::with_name(FAMILY)
};
/// Chiffres clés.
pub const UI_STRONG: Font = Font {
    weight: Weight::Bold,
    ..Font::with_name(FAMILY)
};
/// Données (domaines, adresses, chiffres) : même famille, pour une interface homogène.
pub const MONO: Font = UI;
/// Extraits de commandes uniquement.
pub const CODE: Font = Font::with_name("JetBrains Mono");

/// Échelle typographique : toute taille de texte de l'interface vient d'ici.
pub mod size {
    /// Chiffres clés et titre de page.
    pub const DISPLAY: u16 = 28;
    /// Titres de section.
    pub const TITLE: u16 = 20;
    /// Titres de cartes, marque.
    pub const HEADING: u16 = 16;
    /// Navigation, boutons, champs, valeurs.
    pub const BODY: u16 = 14;
    /// Descriptions, aides, sous-titres.
    pub const SMALL: u16 = 13;
    /// Libellés, puces, en-têtes de colonnes.
    pub const CAPTION: u16 = 12;
    /// Axes des graphiques.
    pub const MICRO: f32 = 11.0;
}

/// Rayon des cartes et panneaux.
pub const RADIUS: f32 = 16.0;
/// Rayon des contrôles (boutons, champs, puces).
pub const RADIUS_SM: f32 = 10.0;

const fn hex(v: u32) -> Color {
    Color {
        r: ((v >> 16) & 0xff) as f32 / 255.0,
        g: ((v >> 8) & 0xff) as f32 / 255.0,
        b: (v & 0xff) as f32 / 255.0,
        a: 1.0,
    }
}

pub fn alpha(c: Color, a: f32) -> Color {
    Color { a, ..c }
}

/// Mélange opaque de deux couleurs (`t` = part de `a`). Préférable à la transparence pour du
/// texte posé sur une couleur vive : le rendu reste net et le contraste prévisible.
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    Color {
        r: a.r * t + b.r * (1.0 - t),
        g: a.g * t + b.g * (1.0 - t),
        b: a.b * t + b.b * (1.0 - t),
        a: 1.0,
    }
}

pub fn hex_str(c: Color) -> String {
    format!(
        "#{:02X}{:02X}{:02X}",
        (c.r * 255.0).round() as u8,
        (c.g * 255.0).round() as u8,
        (c.b * 255.0).round() as u8
    )
}

#[derive(Clone, Copy, Debug)]
pub struct Pal {
    pub dark: bool,
    /// Fond général.
    pub bg: Color,
    pub sidebar: Color,
    /// Bandeau supérieur (teinté de jaune).
    pub hero: Color,
    /// Cartes.
    pub surface: Color,
    /// Survol, élément actif, puces.
    pub raised: Color,
    pub line: Color,
    pub line_strong: Color,
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    /// Couleur principale : violet (boutons, élément actif).
    pub accent: Color,
    /// Survol et appui des boutons principaux.
    pub accent_hover: Color,
    /// Texte posé sur la couleur principale.
    pub on_accent: Color,
    /// Violet lisible en texte ou en icône sur le fond du thème.
    pub accent_ink: Color,
    /// Fond teinté (élément actif, puces).
    pub accent_soft: Color,
    /// Série principale des graphiques.
    pub series: Color,
    /// Trafic déchiffré par l'interception TLS.
    pub inspect: Color,
    /// Gravité moyenne (orange).
    pub medium: Color,
    /// Neutre fort (notifications, infobulles).
    pub ink: Color,
    pub on_ink: Color,
    /// Séries de données secondaires (gris).
    pub steel: Color,
    pub ok: Color,
    pub warn: Color,
    pub danger: Color,
    pub crit: Color,
}

impl Pal {
    pub const LIGHT: Pal = Pal {
        dark: false,
        bg: hex(0xFAFAFA),
        sidebar: hex(0xFFFFFF),
        hero: hex(0xFFFFFF),
        surface: hex(0xFFFFFF),
        raised: hex(0xF4F4F5),
        line: hex(0xEBEBEB),
        line_strong: hex(0xD9D9D9),
        text: hex(0x1A1A1A),
        muted: hex(0x6E6E6E),
        faint: hex(0xA3A3A3),
        accent: hex(0x7C3AED),
        accent_hover: hex(0x6D28D9),
        on_accent: hex(0xFFFFFF),
        accent_ink: hex(0x6D3FD9),
        accent_soft: hex(0xF1EBFE),
        series: hex(0x7C3AED),
        inspect: hex(0x0E7490),
        medium: hex(0xB45309),
        ink: hex(0x1A1A1A),
        on_ink: hex(0xFFFFFF),
        steel: hex(0xBDBDBD),
        ok: hex(0x0A8754),
        warn: hex(0xB45309),
        danger: hex(0xCF304A),
        crit: hex(0xB0247A),
    };

    pub const DARK: Pal = Pal {
        dark: true,
        bg: hex(0x0D0D0D),
        sidebar: hex(0x121212),
        hero: hex(0x121212),
        surface: hex(0x181818),
        raised: hex(0x222222),
        line: hex(0x262626),
        line_strong: hex(0x363636),
        text: hex(0xEAEAEA),
        muted: hex(0x8F8F8F),
        faint: hex(0x5E5E5E),
        accent: hex(0x7C3AED),
        accent_hover: hex(0x6D28D9),
        on_accent: hex(0xFFFFFF),
        accent_ink: hex(0xA78BFA),
        accent_soft: hex(0x241A38),
        series: hex(0xA78BFA),
        inspect: hex(0x22D3EE),
        medium: hex(0xFF8A3D),
        ink: hex(0xEAEAEA),
        on_ink: hex(0x121212),
        steel: hex(0x4A4A4A),
        ok: hex(0x2EBD85),
        warn: hex(0xFF8A3D),
        danger: hex(0xF6465D),
        crit: hex(0xFF4FB8),
    };

    pub fn get(dark: bool) -> Pal {
        if dark {
            Pal::DARK
        } else {
            Pal::LIGHT
        }
    }

    /// Couleur par gravité : gris, orange, rouge, magenta.
    pub fn severity(&self, s: Severity) -> Color {
        match s {
            Severity::Low => self.faint,
            Severity::Medium => self.medium,
            Severity::High => self.danger,
            Severity::Critical => self.crit,
        }
    }

    pub fn theme(&self) -> Theme {
        Theme::custom(
            if self.dark {
                "Ferrox sombre"
            } else {
                "Ferrox clair"
            }
            .into(),
            iced::theme::Palette {
                background: self.bg,
                text: self.text,
                primary: self.accent,
                success: self.ok,
                danger: self.danger,
            },
        )
    }
}

fn border(color: Color, width: f32, radius: f32) -> Border {
    Border {
        color,
        width,
        radius: radius.into(),
    }
}

// ------------------------------------------------------------------ conteneurs

pub fn page_bg(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.bg.into()),
        text_color: Some(p.text),
        ..Default::default()
    }
}

pub fn sidebar(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.sidebar.into()),
        text_color: Some(p.text),
        ..Default::default()
    }
}

pub fn hero(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.hero.into()),
        text_color: Some(p.text),
        ..Default::default()
    }
}

/// Filet de séparation sous le bandeau et à droite de la barre latérale.
pub fn rule(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.line.into()),
        ..Default::default()
    }
}

pub fn card(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.surface.into()),
        border: border(p.line, 1.0, RADIUS),
        text_color: Some(p.text),
        ..Default::default()
    }
}

/// Carte mise en avant, en couleur principale.
pub fn card_inverted(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.accent.into()),
        border: border(p.accent, 1.0, RADIUS),
        text_color: Some(p.on_accent),
        ..Default::default()
    }
}

/// Carte grisée (éléments lus, colonnes secondaires).
pub fn card_soft(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.raised.into()),
        border: border(p.raised, 1.0, RADIUS),
        text_color: Some(p.text),
        ..Default::default()
    }
}

pub fn raised(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.raised.into()),
        border: border(p.line, 1.0, RADIUS_SM),
        text_color: Some(p.text),
        ..Default::default()
    }
}

pub fn fill(color: Color) -> impl Fn(&Theme) -> container::Style {
    fill_round(color, 0.0)
}

pub fn fill_round(color: Color, radius: f32) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(color.into()),
        border: border(Color::TRANSPARENT, 0.0, radius),
        ..Default::default()
    }
}

pub fn chip(color: Color, p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.raised.into()),
        border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
        text_color: Some(color),
        ..Default::default()
    }
}

pub fn toast(p: Pal, _color: Color) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.ink.into()),
        border: border(p.ink, 1.0, RADIUS),
        text_color: Some(p.on_ink),
        shadow: Shadow {
            color: alpha(Color::BLACK, if p.dark { 0.5 } else { 0.18 }),
            offset: Vector::new(0.0, 8.0),
            blur_radius: 24.0,
        },
    }
}

// ------------------------------------------------------------------ boutons

pub fn btn_primary(p: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| {
        let bg = match s {
            button::Status::Hovered => p.accent_hover,
            button::Status::Pressed => mix(p.accent_hover, Color::BLACK, 0.88),
            button::Status::Disabled => alpha(p.accent, 0.35),
            _ => p.accent,
        };
        button::Style {
            background: Some(bg.into()),
            text_color: p.on_accent,
            border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
            shadow: Shadow::default(),
        }
    }
}

pub fn btn_ghost(p: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| {
        // Bouton secondaire : fond gris plein, sans contour.
        let bg = match s {
            button::Status::Hovered => p.line_strong,
            button::Status::Pressed => p.line,
            _ => p.raised,
        };
        button::Style {
            background: Some(Background::Color(bg)),
            text_color: if matches!(s, button::Status::Disabled) {
                p.faint
            } else {
                p.text
            },
            border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
            shadow: Shadow::default(),
        }
    }
}

/// Bouton texte sans cadre (barre supérieure).
pub fn btn_text(p: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| button::Style {
        background: match s {
            button::Status::Hovered | button::Status::Pressed => {
                Some(alpha(p.text, if p.dark { 0.08 } else { 0.05 }).into())
            }
            _ => None,
        },
        text_color: p.text,
        border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
        shadow: Shadow::default(),
    }
}

pub fn btn_danger(p: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| {
        let hovered = matches!(s, button::Status::Hovered | button::Status::Pressed);
        button::Style {
            background: if hovered {
                Some(alpha(p.danger, 0.1).into())
            } else {
                None
            },
            text_color: p.danger,
            border: border(alpha(p.danger, 0.45), 1.0, RADIUS_SM),
            shadow: Shadow::default(),
        }
    }
}

/// Bouton icône discret.
pub fn btn_icon(p: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| button::Style {
        background: match s {
            button::Status::Hovered | button::Status::Pressed => Some(p.raised.into()),
            _ => None,
        },
        text_color: p.muted,
        border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
        shadow: Shadow::default(),
    }
}

pub fn btn_nav(p: Pal, active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| {
        let hovered = matches!(s, button::Status::Hovered | button::Status::Pressed);
        button::Style {
            background: if active {
                Some(p.raised.into())
            } else if hovered {
                Some(alpha(p.raised, 0.5).into())
            } else {
                None
            },
            text_color: p.text,
            border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
            shadow: Shadow::default(),
        }
    }
}

pub fn btn_seg(p: Pal, active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| {
        let hovered = matches!(s, button::Status::Hovered);
        button::Style {
            background: if active {
                Some(p.surface.into())
            } else if hovered {
                Some(alpha(p.surface, 0.5).into())
            } else {
                None
            },
            text_color: if active { p.text } else { p.muted },
            border: border(
                if active { p.line } else { Color::TRANSPARENT },
                1.0,
                RADIUS_SM - 1.0,
            ),
            shadow: Shadow::default(),
        }
    }
}

/// Tuile d'icône de la navigation : violet plein pour la page active, invisible sinon.
pub fn icon_tile(p: Pal, active: bool) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: active.then(|| p.accent.into()),
        border: border(Color::TRANSPARENT, 0.0, 8.0),
        ..Default::default()
    }
}

/// Puce teintée de la couleur principale (compteurs, badges).
pub fn accent_chip(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.accent_soft.into()),
        border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
        text_color: Some(p.text),
        ..Default::default()
    }
}

/// Fond des contrôles segmentés.
pub fn seg_track(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.raised.into()),
        border: border(Color::TRANSPARENT, 0.0, RADIUS_SM),
        ..Default::default()
    }
}

// ------------------------------------------------------------------ champs

pub fn input(p: Pal) -> impl Fn(&Theme, text_input::Status) -> text_input::Style {
    move |_, s| {
        // Champ épuré : fond plein discret, filet neutre au survol, violet au focus.
        let (bd, bg) = match s {
            text_input::Status::Focused => (p.accent, p.surface),
            text_input::Status::Hovered => (p.line_strong, p.raised),
            text_input::Status::Disabled => (Color::TRANSPARENT, alpha(p.raised, 0.5)),
            _ => (Color::TRANSPARENT, p.raised),
        };
        text_input::Style {
            background: Background::Color(bg),
            border: border(bd, 1.0, RADIUS_SM),
            icon: p.muted,
            placeholder: p.faint,
            value: p.text,
            selection: alpha(p.accent, 0.35),
        }
    }
}

/// Champ sans cadre (recherche intégrée à la barre supérieure).
pub fn input_bare(p: Pal) -> impl Fn(&Theme, text_input::Status) -> text_input::Style {
    move |_, _| text_input::Style {
        background: Background::Color(Color::TRANSPARENT),
        border: border(Color::TRANSPARENT, 0.0, 0.0),
        icon: p.muted,
        placeholder: p.muted,
        value: p.text,
        selection: alpha(p.accent, 0.35),
    }
}

pub fn toggle(p: Pal) -> impl Fn(&Theme, toggler::Status) -> toggler::Style {
    move |_, s| {
        let on = matches!(
            s,
            toggler::Status::Active { is_toggled: true }
                | toggler::Status::Hovered { is_toggled: true }
        );
        toggler::Style {
            background: if on { p.accent } else { p.line_strong },
            background_border_width: 0.0,
            background_border_color: Color::TRANSPARENT,
            foreground: hex(0xFFFFFF),
            foreground_border_width: 0.0,
            foreground_border_color: Color::TRANSPARENT,
        }
    }
}

/// Barres de défilement masquées : le défilement reste actif (molette, pavé).
pub fn hidden_bar() -> scrollable::Direction {
    scrollable::Direction::Vertical(
        scrollable::Scrollbar::new()
            .width(0)
            .scroller_width(0)
            .margin(0),
    )
}

pub fn scroll(_p: Pal) -> impl Fn(&Theme, scrollable::Status) -> scrollable::Style {
    move |_, _| {
        let rail = scrollable::Rail {
            background: None,
            border: Border::default(),
            scroller: scrollable::Scroller {
                color: Color::TRANSPARENT,
                border: Border::default(),
            },
        };
        scrollable::Style {
            container: container::Style::default(),
            vertical_rail: rail,
            horizontal_rail: rail,
            gap: None,
        }
    }
}
