//! Formatage des valeurs affichées.

use time::{OffsetDateTime, UtcOffset};

pub fn bytes(b: u64) -> String {
    let f = b as f64;
    if b < 1024 {
        format!("{b} o")
    } else if f < 1024.0 * 1024.0 {
        format!("{:.1} Ko", f / 1024.0)
    } else if f < 1024.0 * 1024.0 * 1024.0 {
        format!("{:.1} Mo", f / 1_048_576.0)
    } else {
        format!("{:.2} Go", f / 1_073_741_824.0)
    }
}

pub fn count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

pub fn duration_ms(ms: u32) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{} min", ms / 60_000)
    }
}

pub fn uptime(s: u64) -> String {
    let (h, m, sec) = (s / 3600, (s % 3600) / 60, s % 60);
    if h > 0 {
        format!("{h} h {m:02} min")
    } else if m > 0 {
        format!("{m} min {sec:02} s")
    } else {
        format!("{sec} s")
    }
}

static OFFSET: std::sync::LazyLock<UtcOffset> =
    std::sync::LazyLock::new(|| UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC));

fn local(ms: i64) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp_nanos(ms as i128 * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .to_offset(*OFFSET)
}

/// Heure locale HH:MM:SS.
pub fn clock(ms: i64) -> String {
    let t = local(ms);
    format!("{:02}:{:02}:{:02}", t.hour(), t.minute(), t.second())
}

/// Temps relatif court (« il y a 12 s »).
pub fn ago(ms: i64, now_ms: i64) -> String {
    let d = ((now_ms - ms) / 1000).max(0);
    if d < 60 {
        format!("il y a {d} s")
    } else if d < 3600 {
        format!("il y a {} min", d / 60)
    } else if d < 86_400 {
        format!("il y a {} h", d / 3600)
    } else {
        format!("il y a {} j", d / 86_400)
    }
}

pub fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(n.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}
