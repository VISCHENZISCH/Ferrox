//! Reconnaissance de types de fichiers par signature (premiers octets).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    WindowsExe,
    Elf,
    MachO,
    Zip,
    Rar,
    SevenZip,
    Pdf,
    OleDoc,
    Script,
    Iso,
}

impl Kind {
    pub fn name(&self) -> &'static str {
        match self {
            Kind::WindowsExe => "exe-pe",
            Kind::Elf => "elf",
            Kind::MachO => "mach-o",
            Kind::Zip => "zip",
            Kind::Rar => "rar",
            Kind::SevenZip => "7z",
            Kind::Pdf => "pdf",
            Kind::OleDoc => "ole",
            Kind::Script => "script",
            Kind::Iso => "iso",
        }
    }
}

/// Associe une extension bloquée à la signature correspondante.
pub fn kind_for_extension(ext: &str) -> Option<Kind> {
    Some(match ext {
        "exe" | "dll" | "scr" | "sys" | "com" | "cpl" => Kind::WindowsExe,
        "elf" | "so" | "bin" => Kind::Elf,
        "dylib" | "macho" => Kind::MachO,
        "zip" | "jar" | "apk" | "docm" | "xlsm" | "appx" | "msix" => Kind::Zip,
        "rar" => Kind::Rar,
        "7z" => Kind::SevenZip,
        "pdf" => Kind::Pdf,
        "doc" | "xls" | "ppt" | "msi" => Kind::OleDoc,
        "sh" | "ps1" | "py" | "pl" => Kind::Script,
        "iso" | "img" => Kind::Iso,
        _ => return None,
    })
}

pub fn detect(h: &[u8]) -> Option<Kind> {
    let starts = |sig: &[u8]| h.len() >= sig.len() && &h[..sig.len()] == sig;
    if starts(b"MZ") {
        return Some(Kind::WindowsExe);
    }
    if starts(b"\x7fELF") {
        return Some(Kind::Elf);
    }
    if starts(&[0xCF, 0xFA, 0xED, 0xFE])
        || starts(&[0xFE, 0xED, 0xFA, 0xCF])
        || starts(&[0xCA, 0xFE, 0xBA, 0xBE])
    {
        return Some(Kind::MachO);
    }
    if starts(b"PK\x03\x04") {
        return Some(Kind::Zip);
    }
    if starts(b"Rar!\x1a\x07") {
        return Some(Kind::Rar);
    }
    if starts(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        return Some(Kind::SevenZip);
    }
    if starts(b"%PDF-") {
        return Some(Kind::Pdf);
    }
    if starts(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return Some(Kind::OleDoc);
    }
    if starts(b"#!") {
        return Some(Kind::Script);
    }
    if h.len() >= 0x8006 && &h[0x8001..0x8006] == b"CD001" {
        return Some(Kind::Iso);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects() {
        assert_eq!(detect(b"MZ\x90\x00"), Some(Kind::WindowsExe));
        assert_eq!(detect(b"%PDF-1.7"), Some(Kind::Pdf));
        assert_eq!(detect(b"<html>"), None);
    }
}
