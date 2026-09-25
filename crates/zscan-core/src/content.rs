//! Guessing what a stream's decompressed contents are (image, text, executable...),
//! from magic numbers and a look at the first bytes. For display only.

use serde::Serialize;

/// A broad class of content, for choosing how to preview it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ContentClass {
    Image,
    Text,
    Archive,
    Executable,
    Media,
    Document,
    Binary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ContentType {
    /// Short name, e.g. "PNG" or "UTF-8 text".
    pub name: &'static str,
    pub class: ContentClass,
}

impl ContentType {
    const fn new(name: &'static str, class: ContentClass) -> Self {
        Self { name, class }
    }
}

const MAGIC: &[(&[u8], ContentType)] = {
    use ContentClass::*;
    &[
        (b"\x89PNG\r\n\x1a\n", ContentType::new("PNG", Image)),
        (b"\xff\xd8\xff", ContentType::new("JPEG", Image)),
        (b"GIF87a", ContentType::new("GIF", Image)),
        (b"GIF89a", ContentType::new("GIF", Image)),
        (b"BM", ContentType::new("BMP", Image)),
        (b"DDS ", ContentType::new("DDS", Image)),
        (b"II*\0", ContentType::new("TIFF", Image)),
        (b"MM\0*", ContentType::new("TIFF", Image)),
        (b"\0\0\x01\0", ContentType::new("ICO", Image)),
        (b"%PDF", ContentType::new("PDF", Document)),
        (b"PK\x03\x04", ContentType::new("ZIP", Archive)),
        (b"\x1f\x8b", ContentType::new("gzip", Archive)),
        (b"\x28\xb5\x2f\xfd", ContentType::new("zstd", Archive)),
        (b"\xfd7zXZ\0", ContentType::new("xz", Archive)),
        (b"BZh", ContentType::new("bzip2", Archive)),
        (b"7z\xbc\xaf\x27\x1c", ContentType::new("7z", Archive)),
        (b"Rar!\x1a\x07", ContentType::new("RAR", Archive)),
        (b"\x7fELF", ContentType::new("ELF", Executable)),
        (b"MZ", ContentType::new("PE/DOS executable", Executable)),
        (b"\xca\xfe\xba\xbe", ContentType::new("Java class / Mach-O", Executable)),
        (b"\xcf\xfa\xed\xfe", ContentType::new("Mach-O", Executable)),
        (b"\0asm", ContentType::new("WebAssembly", Executable)),
        (b"OggS", ContentType::new("Ogg", Media)),
        (b"fLaC", ContentType::new("FLAC", Media)),
        (b"ID3", ContentType::new("MP3", Media)),
        (b"\x1a\x45\xdf\xa3", ContentType::new("Matroska/WebM", Media)),
        (b"SQLite format 3\0", ContentType::new("SQLite", Document)),
    ]
};

/// Guess the type of `data` from its first bytes.
pub fn sniff(data: &[u8]) -> ContentType {
    use ContentClass::*;
    if data.len() >= 12 && &data[..4] == b"RIFF" {
        return match &data[8..12] {
            b"WEBP" => ContentType::new("WebP", Image),
            b"WAVE" => ContentType::new("WAV", Media),
            b"AVI " => ContentType::new("AVI", Media),
            _ => ContentType::new("RIFF", Media),
        };
    }
    if data.len() >= 12 && &data[4..8] == b"ftyp" {
        return ContentType::new("MP4/QuickTime", Media);
    }
    // Two-byte magics (BM, MZ) are too weak on their own; ask for a plausible header too.
    let plausible = |m: &[u8]| match m {
        b"BM" => data.len() >= 26 && data[6..10] == [0; 4],
        b"MZ" => data.len() >= 64,
        _ => true,
    };
    if let Some((_, t)) = MAGIC.iter().find(|(m, _)| data.starts_with(m) && plausible(m)) {
        return *t;
    }
    if data.is_empty() {
        return ContentType::new("empty", Binary);
    }
    if let Some(text) = text_type(data) {
        return text;
    }
    ContentType::new("binary", Binary)
}

/// Text, if the start of `data` looks like it: UTF-8 (a character cut off at the end of
/// the sample is fine) with few control characters.
fn text_type(data: &[u8]) -> Option<ContentType> {
    const SAMPLE: usize = 4096;
    let sample = match data {
        [0xff, 0xfe, ..] | [0xfe, 0xff, ..] => return Some(ContentType::new("UTF-16 text", ContentClass::Text)),
        [0xef, 0xbb, 0xbf, rest @ ..] => &rest[..rest.len().min(SAMPLE)],
        _ => &data[..data.len().min(SAMPLE)],
    };
    let valid = match std::str::from_utf8(sample) {
        Ok(s) => s,
        // A multi-byte character split by the sample cut is not a sign of binary data.
        Err(e) if e.error_len().is_none() && sample.len() - e.valid_up_to() < 4 => {
            std::str::from_utf8(&sample[..e.valid_up_to()]).ok()?
        }
        Err(_) => return None,
    };
    let control = valid.chars().filter(|&c| c.is_control() && !matches!(c, '\t' | '\n' | '\r' | '\x0c')).count();
    if control * 50 > valid.chars().count().max(1) {
        return None;
    }
    let start = valid.trim_start();
    let name = if start.starts_with("<?xml") || start.starts_with("<svg") {
        "XML"
    } else if start.as_bytes().get(..5).is_some_and(|b| b.eq_ignore_ascii_case(b"<!doc")) || start.starts_with("<html") {
        "HTML"
    } else if start.starts_with('{') || start.starts_with('[') {
        "JSON"
    } else if valid.is_ascii() {
        "ASCII text"
    } else {
        "UTF-8 text"
    };
    Some(ContentType::new(name, ContentClass::Text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_numbers() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR").name, "PNG");
        assert_eq!(sniff(b"\xff\xd8\xff\xe0\0\x10JFIF").class, ContentClass::Image);
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 ").name, "WebP");
        assert_eq!(sniff(b"\x7fELF\x02\x01\x01").class, ContentClass::Executable);
        assert_eq!(sniff(b"PK\x03\x04\x14\0").name, "ZIP");
    }

    #[test]
    fn weak_magic_needs_a_plausible_header() {
        assert_eq!(sniff(b"BMW is a car, not a bitmap"), ContentType::new("ASCII text", ContentClass::Text));
        assert_eq!(sniff(b"MZ\x90\x00").name, "binary");
    }

    #[test]
    fn text() {
        assert_eq!(sniff(b"hello world\n").name, "ASCII text");
        assert_eq!(sniff("h\u{e9}llo".as_bytes()).name, "UTF-8 text");
        assert_eq!(sniff(b"  {\"a\": 1}").name, "JSON");
        assert_eq!(sniff(b"<?xml version=\"1.0\"?><a/>").name, "XML");
        assert_eq!(sniff(b"<!DOCTYPE html><html>").name, "HTML");
        // A character cut in half by the sample limit is still text.
        let mut long = "\u{e9}".repeat(3000).into_bytes();
        long.truncate(4096 + 1);
        assert_eq!(sniff(&long).name, "UTF-8 text");
    }

    #[test]
    fn binary() {
        assert_eq!(sniff(&[0u8, 1, 2, 3, 4, 5, 200, 201]).name, "binary");
        assert_eq!(sniff(&[]).name, "empty");
    }
}
