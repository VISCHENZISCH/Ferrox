//! Ferrox : application de bureau.

#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod fmt;
mod icons;
mod theme;
mod ui;

use app::App;

fn main() -> iced::Result {
    // Lit le fuseau horaire avant tout fil d'exécution (exigence de `time` sous Unix).
    let _ = fmt::clock(0);
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let icon =
        iced::window::icon::from_rgba(include_bytes!("../assets/icon-64.rgba").to_vec(), 64, 64)
            .ok();

    iced::application("Ferrox", App::update, ui::view)
        .subscription(App::subscription)
        .theme(App::theme)
        .font(include_bytes!("../assets/fonts/IBMPlexSans-Regular.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/IBMPlexSans-Medium.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/IBMPlexSans-SemiBold.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/IBMPlexSans-Bold.ttf").as_slice())
        .font(include_bytes!("../assets/fonts/JetBrainsMono-Regular.ttf").as_slice())
        .default_font(theme::UI)
        .antialiasing(true)
        .window(iced::window::Settings {
            size: iced::Size::new(1440.0, 900.0),
            min_size: Some(iced::Size::new(1120.0, 700.0)),
            icon,
            ..Default::default()
        })
        .run_with(App::new)
}
