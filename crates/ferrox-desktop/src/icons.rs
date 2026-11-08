//! Jeu d'icônes Ferrox (SVG dessinés pour le projet) et monogramme.

use crate::theme::{hex_str, Pal};
use iced::widget::svg::{self, Handle};
use iced::{Color, Element, Length};
use std::sync::LazyLock;

macro_rules! icons {
    ($($v:ident => $f:literal),* $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[allow(dead_code)]
        pub enum Ico { $( $v, )* }

        static HANDLES: LazyLock<Vec<Handle>> = LazyLock::new(|| vec![
            $( Handle::from_memory(include_bytes!(concat!("../assets/icons/", $f, ".svg")).as_slice()), )*
        ]);
    };
}

icons! {
    Overview => "overview", Traffic => "traffic", Dns => "dns", Alert => "alert",
    Filter => "filter", Settings => "settings", Play => "play", Stop => "stop",
    Pause => "pause", Sun => "sun", Moon => "moon", Refresh => "refresh", Plus => "plus",
    Close => "close", Export => "export", Search => "search", Up => "up", Down => "down",
    Lock => "lock", Check => "check", Host => "host", Pulse => "pulse", Globe => "globe",
    List => "list", Arrow => "arrow", Sort => "sort", Clock => "clock", Dots => "dots",
}

/// Icône teintée à la couleur demandée.
pub fn icon<'a, M: 'a>(i: Ico, size: f32, color: Color) -> Element<'a, M> {
    iced::widget::svg(HANDLES[i as usize].clone())
        .width(Length::Fixed(size))
        .height(Length::Fixed(size))
        .style(move |_, _| svg::Style { color: Some(color) })
        .into()
}

/// Monogramme aux couleurs du thème.
pub struct Brand {
    pub mark: Handle,
}

impl Brand {
    pub fn new(p: Pal) -> Self {
        let mark = include_str!("../assets/logo-mark.svg.tpl")
            .replace("{BASE}", &hex_str(p.on_accent))
            .replace("{INK}", &hex_str(p.accent));
        Self {
            mark: Handle::from_memory(mark.into_bytes()),
        }
    }
}
