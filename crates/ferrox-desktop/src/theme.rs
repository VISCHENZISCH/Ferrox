//! Identité visuelle Ferrox : sobre et monochrome.
//! Noir, blanc, gris chauds et un bandeau beige ; une seule couleur d'alerte (rouge),
//! réservée aux menaces et aux blocages.

use ferrox_core::event::Severity;
use iced::font::Weight;
use iced::widget::{button, container, scrollable, text_input, toggler};
use iced::{Background, Border, Color, Font, Shadow, Theme, Vector};

pub const UI: Font = Font::with_name("Manrope");
pub const UI_BOLD: Font = Font {
    weight: Weight::Medium,
    ..Font::with_name("Manrope")
};
pub const UI_HEAVY: Font = Font {
    weight: Weight::Semibold,
    ..Font::with_name("Manrope")
};
/// Données (domaines, adresses, chiffres) : même famille, pour une interface homogène.
pub const MONO: Font = UI;
/// Extraits de commandes uniquement.
pub const CODE: Font = Font::with_name("JetBrains Mono");

/// Rayon des cartes et panneaux.
pub const RADIUS: f32 = 12.0;
/// Rayon des contrôles (boutons, champs, puces).
pub const RADIUS_SM: f32 = 8.0;

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
    /// Bandeau supérieur (beige).
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
    /// Action principale : noir en clair, blanc en sombre.
    pub accent: Color,
    pub on_accent: Color,
    /// Séries de données secondaires (gris).
    pub steel: Color,
    pub ok: Color,
    pub warn: Color,
    pub danger: Color,
    #[allow(dead_code)]
    pub crit: Color,
}

impl Pal {
    pub const LIGHT: Pal = Pal {
        dark: false,
        bg: hex(0xFFFFFF),
        sidebar: hex(0xFFFFFF),
        hero: hex(0xEFEFE7),
        surface: hex(0xFFFFFF),
        raised: hex(0xF3F3F0),
        line: hex(0xE6E6E1),
        line_strong: hex(0xD2D2CB),
        text: hex(0x141414),
        muted: hex(0x6E6E6A),
        faint: hex(0xA9A9A3),
        accent: hex(0x161616),
        on_accent: hex(0xFFFFFF),
        steel: hex(0x8C8C86),
        ok: hex(0x3C8A55),
        warn: hex(0x6E6E6A),
        danger: hex(0xD2412C),
        crit: hex(0xB0281A),
    };

    pub const DARK: Pal = Pal {
        dark: true,
        bg: hex(0x111111),
        sidebar: hex(0x111111),
        hero: hex(0x1B1B19),
        surface: hex(0x161616),
        raised: hex(0x222220),
        line: hex(0x272725),
        line_strong: hex(0x3A3A37),
        text: hex(0xF1F1EC),
        muted: hex(0x9B9B95),
        faint: hex(0x5F5F5A),
        accent: hex(0xF1F1EC),
        on_accent: hex(0x111111),
        steel: hex(0x77776F),
        ok: hex(0x5FB27A),
        warn: hex(0x9B9B95),
        danger: hex(0xF0624C),
        crit: hex(0xFF7A66),
    };

    pub fn get(dark: bool) -> Pal {
        if dark {
            Pal::DARK
        } else {
            Pal::LIGHT
        }
    }

    /// Couleur par gravité, réservée aux vues d'alertes à venir.
    #[allow(dead_code)]
    pub fn severity(&self, s: Severity) -> Color {
        match s {
            Severity::Low => self.faint,
            Severity::Medium => self.muted,
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

pub fn card(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.surface.into()),
        border: border(p.line, 1.0, RADIUS),
        text_color: Some(p.text),
        ..Default::default()
    }
}

/// Carte mise en avant (inversée : noire en clair, claire en sombre).
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

/// Cadre fin sans fond (puces de date, compteurs).
pub fn outline(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: None,
        border: border(p.line_strong, 1.0, RADIUS_SM),
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
        background: Some(p.accent.into()),
        border: border(p.accent, 1.0, RADIUS),
        text_color: Some(p.on_accent),
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
            button::Status::Hovered => alpha(p.accent, 0.86),
            button::Status::Pressed => alpha(p.accent, 0.76),
            button::Status::Disabled => alpha(p.accent, 0.25),
            _ => p.accent,
        };
        button::Style {
            background: Some(bg.into()),
            text_color: p.on_accent,
            border: border(Color::TRANSPARENT, 0.0, RADIUS_SM + 2.0),
            shadow: Shadow::default(),
        }
    }
}

pub fn btn_ghost(p: Pal) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_, s| {
        let bg = match s {
            button::Status::Hovered => Some(p.raised),
            button::Status::Pressed => Some(p.line),
            _ => None,
        };
        button::Style {
            background: bg.map(Background::Color),
            text_color: if matches!(s, button::Status::Disabled) {
                p.faint
            } else {
                p.text
            },
            border: border(p.line_strong, 1.0, RADIUS_SM + 2.0),
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
            border: border(alpha(p.danger, 0.45), 1.0, RADIUS_SM + 2.0),
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
                Some(alpha(p.raised, 0.6).into())
            } else {
                None
            },
            text_color: p.text,
            border: border(Color::TRANSPARENT, 0.0, RADIUS_SM + 2.0),
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

/// Fond des contrôles segmentés.
pub fn seg_track(p: Pal) -> impl Fn(&Theme) -> container::Style {
    move |_| container::Style {
        background: Some(p.raised.into()),
        border: border(Color::TRANSPARENT, 0.0, RADIUS_SM + 2.0),
        ..Default::default()
    }
}

// ------------------------------------------------------------------ champs

pub fn input(p: Pal) -> impl Fn(&Theme, text_input::Status) -> text_input::Style {
    move |_, s| {
        let bd = match s {
            text_input::Status::Focused => p.text,
            text_input::Status::Hovered => p.line_strong,
            _ => p.line,
        };
        text_input::Style {
            background: Background::Color(p.surface),
            border: border(bd, 1.0, RADIUS_SM + 2.0),
            icon: p.muted,
            placeholder: p.faint,
            value: p.text,
            selection: alpha(p.text, 0.18),
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
        selection: alpha(p.text, 0.18),
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
            foreground: if on { p.on_accent } else { p.surface },
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
