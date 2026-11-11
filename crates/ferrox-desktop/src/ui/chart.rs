//! Graphiques sur canvas : barres groupées (pleines / hachurées) et jauge à graduations.

use crate::theme::{alpha, size, Pal, UI, UI_BOLD, UI_STRONG};
use iced::alignment::{Horizontal, Vertical};
use iced::mouse;
use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke, Text};
use iced::{Point, Rectangle, Renderer, Size, Theme};

fn nice_max(v: f32) -> f32 {
    if v <= 0.0 {
        return 10.0;
    }
    // Au moins 4 : les graduations 0 / moitié / max restent des entiers distincts.
    let v = v.max(4.0);
    let mag = 10f32.powf(v.log10().floor());
    let n = v / mag;
    let step = if n <= 1.0 {
        1.0
    } else if n <= 2.0 {
        2.0
    } else if n <= 5.0 {
        5.0
    } else {
        10.0
    };
    step * mag
}

fn label(
    content: String,
    at: Point,
    size: f32,
    color: iced::Color,
    h: Horizontal,
    v: Vertical,
) -> Text {
    Text {
        content,
        position: at,
        color,
        size: size.into(),
        font: UI,
        horizontal_alignment: h,
        vertical_alignment: v,
        ..Text::default()
    }
}

/// Hachures diagonales limitées à un rectangle.
fn hatch(f: &mut Frame, x0: f32, y0: f32, w: f32, h: f32, color: iced::Color) {
    let (x1, y1) = (x0 + w, y0 + h);
    let stroke = Stroke::default().with_color(color).with_width(1.0);
    let mut c = x0 + y0;
    while c < x1 + y1 {
        // Droite x + y = c.
        let xa = x0.max(c - y1);
        let xb = x1.min(c - y0);
        if xa < xb {
            f.stroke(
                &Path::line(Point::new(xa, c - xa), Point::new(xb, c - xb)),
                stroke,
            );
        }
        c += 4.5;
    }
}

/// Barres groupées : une barre hachurée (DNS) et une barre pleine (web) par intervalle.
pub struct Bars {
    pub solid: Vec<f32>,
    pub hatched: Vec<f32>,
    pub labels: Vec<String>,
    pub pal: Pal,
}

impl<M> canvas::Program<M> for Bars {
    type State = ();

    fn draw(
        &self,
        _: &(),
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let p = self.pal;
        let mut f = Frame::new(renderer, bounds.size());
        let n = self.solid.len().max(1);
        let (left, bottom, top) = (26.0, 24.0, 6.0);
        let w = bounds.width - left;
        let h = bounds.height - bottom - top;
        let max = nice_max(
            self.solid
                .iter()
                .chain(self.hatched.iter())
                .cloned()
                .fold(0.0, f32::max),
        );
        let y = |v: f32| top + h - h * (v / max).min(1.0);

        for v in [0.0, max / 2.0, max] {
            let txt = if v >= 1000.0 {
                format!("{:.0}k", v / 1000.0)
            } else {
                format!("{v:.0}")
            };
            f.fill_text(label(
                txt,
                Point::new(0.0, y(v)),
                size::MICRO,
                p.muted,
                Horizontal::Left,
                Vertical::Center,
            ));
        }

        let slot = w / n as f32;
        let bw = (slot * 0.28).clamp(4.0, 16.0);
        let gap = (bw * 0.3).max(3.0);
        let hover = cursor
            .position_in(bounds)
            .filter(|c| c.x >= left)
            .map(|c| (((c.x - left) / slot) as usize).min(n - 1));

        for i in 0..n {
            let cx = left + slot * (i as f32 + 0.5);
            let (s, hv) = (
                self.solid.get(i).copied().unwrap_or(0.0),
                self.hatched.get(i).copied().unwrap_or(0.0),
            );
            let dim = hover.is_some_and(|k| k != i);
            let ink = if dim { alpha(p.muted, 0.45) } else { p.muted };
            let fill = if dim { alpha(p.series, 0.4) } else { p.series };
            // Barre hachurée.
            let hx = cx - gap / 2.0 - bw;
            let hy = y(hv);
            if hv > 0.0 {
                hatch(
                    &mut f,
                    hx,
                    hy,
                    bw,
                    top + h - hy,
                    alpha(ink, if dim { 0.4 } else { 0.55 }),
                );
            }
            // Barre pleine.
            let sx = cx + gap / 2.0;
            let sy = y(s);
            if s > 0.0 {
                f.fill(
                    &Path::rounded_rectangle(
                        Point::new(sx, sy),
                        Size::new(bw, top + h - sy),
                        3.0.into(),
                    ),
                    fill,
                );
            }
            if let Some(l) = self.labels.get(i).filter(|l| !l.is_empty()) {
                f.fill_text(label(
                    l.clone(),
                    Point::new(cx, top + h + 9.0),
                    size::MICRO,
                    p.muted,
                    Horizontal::Center,
                    Vertical::Top,
                ));
            }
        }

        if let Some(i) = hover {
            let cx = left + slot * (i as f32 + 0.5);
            let lines = [
                format!(
                    "{:.0} requêtes web",
                    self.solid.get(i).copied().unwrap_or(0.0)
                ),
                format!(
                    "{:.0} requêtes DNS",
                    self.hatched.get(i).copied().unwrap_or(0.0)
                ),
            ];
            let (tw, th) = (150.0, 46.0);
            let tx = (cx - tw / 2.0).clamp(left, bounds.width - tw);
            let tip = Path::rounded_rectangle(Point::new(tx, top), Size::new(tw, th), 8.0.into());
            f.fill(&tip, p.ink);
            for (k, l) in lines.into_iter().enumerate() {
                f.fill_text(Text {
                    font: UI_BOLD,
                    ..label(
                        l,
                        Point::new(tx + 12.0, top + 9.0 + 15.0 * k as f32),
                        f32::from(size::CAPTION),
                        p.on_ink,
                        Horizontal::Left,
                        Vertical::Top,
                    )
                });
            }
        }
        vec![f.into_geometry()]
    }
}

/// Jauge en arc composée de graduations : valeur au centre, légende dessous,
/// bornes de l'échelle aux deux extrémités de l'arc.
pub struct Gauge {
    pub ratio: f32,
    pub value: String,
    pub caption: String,
    pub min_label: String,
    pub max_label: String,
    pub pal: Pal,
}

impl<M> canvas::Program<M> for Gauge {
    type State = ();

    fn draw(
        &self,
        _: &(),
        renderer: &Renderer,
        _: &Theme,
        bounds: Rectangle,
        _: mouse::Cursor,
    ) -> Vec<Geometry> {
        let p = self.pal;
        let mut f = Frame::new(renderer, bounds.size());
        let cx = bounds.width / 2.0;
        // Place réservée sous l'arc pour les bornes de l'échelle.
        let r = (bounds.width / 2.0 - 4.0).min((bounds.height - 30.0) * 0.72);
        let cy = r + 6.0;
        let ticks = 46;
        let (start, span) = (200f32.to_radians(), 220f32.to_radians());
        let active = (self.ratio.clamp(0.0, 1.0) * ticks as f32).round() as usize;
        for i in 0..ticks {
            let a = start - span * i as f32 / (ticks - 1) as f32;
            let (c, s) = (a.cos(), a.sin());
            let len = if i % 5 == 0 { 20.0 } else { 15.0 };
            let p0 = Point::new(cx + (r - len) * c, cy - (r - len) * s);
            let p1 = Point::new(cx + r * c, cy - r * s);
            f.stroke(
                &Path::line(p0, p1),
                Stroke::default()
                    .with_color(if i < active { p.series } else { p.line_strong })
                    .with_width(if i % 5 == 0 { 2.2 } else { 1.6 })
                    .with_line_cap(canvas::LineCap::Round),
            );
        }
        f.fill_text(Text {
            font: UI_STRONG,
            ..label(
                self.value.clone(),
                Point::new(cx, cy - 4.0),
                // Taille réduite si le texte est long (« 578.0 Ko/s ») pour rester dans l'arc.
                if self.value.chars().count() > 7 {
                    f32::from(size::TITLE) + 2.0
                } else {
                    f32::from(size::DISPLAY)
                },
                p.text,
                Horizontal::Center,
                Vertical::Bottom,
            )
        });
        f.fill_text(label(
            self.caption.clone(),
            Point::new(cx, cy + 6.0),
            f32::from(size::SMALL),
            p.muted,
            Horizontal::Center,
            Vertical::Top,
        ));
        // Bornes sous les extrémités de l'arc (200° et -20°).
        let end = 20f32.to_radians();
        let (ex, ey) = (r * end.cos(), cy + r * end.sin() + 8.0);
        // Bornes alignées sur l'extérieur de l'arc : jamais coupées par le bord.
        for (txt, x, h) in [
            (&self.min_label, cx - ex - 6.0, Horizontal::Left),
            (&self.max_label, cx + ex + 6.0, Horizontal::Right),
        ] {
            f.fill_text(label(
                txt.clone(),
                Point::new(x, ey),
                size::MICRO,
                p.faint,
                h,
                Vertical::Top,
            ));
        }
        vec![f.into_geometry()]
    }
}
