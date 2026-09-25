//! Custom widgets: the entropy map with stream lane, and the hex and text views.

use egui::{Color32, Pos2, Rect, RichText, Sense, Stroke, StrokeKind, Ui, Vec2};
use zscan_core::entropy::EntropyBlock;
use zscan_core::{Format, StreamEntry};

/// Colour for an entropy value (0..=8 bits/byte): dark blue for zeros and padding,
/// green for text and code, yellow to red for compressed or encrypted data.
pub fn entropy_color(entropy: f64) -> Color32 {
    const STOPS: [(f64, [u8; 3]); 5] =
        [(0.0, [16, 24, 64]), (3.0, [40, 110, 170]), (5.0, [60, 170, 90]), (7.0, [230, 200, 60]), (8.0, [220, 60, 40])];
    let e = entropy.clamp(0.0, 8.0);
    let i = STOPS.iter().rposition(|&(x, _)| x <= e).unwrap_or(0).min(STOPS.len() - 2);
    let ((x0, c0), (x1, c1)) = (STOPS[i], STOPS[i + 1]);
    let t = ((e - x0) / (x1 - x0)) as f32;
    let mix = |a: u8, b: u8| (f32::from(a) + (f32::from(b) - f32::from(a)) * t).round() as u8;
    Color32::from_rgb(mix(c0[0], c1[0]), mix(c0[1], c1[1]), mix(c0[2], c1[2]))
}

pub fn format_color(format: Format) -> Color32 {
    match format {
        Format::Gzip => Color32::from_rgb(90, 160, 255),
        Format::Zlib => Color32::from_rgb(80, 200, 200),
        Format::Deflate => Color32::from_rgb(150, 130, 255),
        Format::Zstd => Color32::from_rgb(255, 150, 60),
        Format::Xz => Color32::from_rgb(230, 90, 160),
        Format::Bzip2 => Color32::from_rgb(170, 200, 80),
        Format::Lz4 => Color32::from_rgb(240, 220, 90),
        Format::Brotli => Color32::from_rgb(200, 120, 90),
        Format::Lzo => Color32::from_rgb(120, 210, 120),
        Format::Oodle => Color32::from_rgb(210, 170, 255),
    }
}

/// The file at a glance: entropy along the top, streams (coloured by format) below.
/// Returns the stream clicked, if any.
pub fn entropy_strip(
    ui: &mut Ui,
    blocks: &[EntropyBlock],
    file_len: u64,
    streams: &[StreamEntry],
    selected: Option<u32>,
    is_edited: impl Fn(u32) -> bool,
) -> Option<u32> {
    const MAP_H: f32 = 34.0;
    const LANE_H: f32 = 16.0;
    let (rect, response) = ui.allocate_exact_size(Vec2::new(ui.available_width(), MAP_H + 2.0 + LANE_H), Sense::click());
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 2.0, ui.visuals().extreme_bg_color);
    if file_len == 0 {
        return None;
    }
    let width = rect.width();
    let x_of = |offset: u64| rect.left() + (offset as f64 / file_len as f64 * f64::from(width)) as f32;
    let offset_at = |x: f32| (((x - rect.left()) / width).clamp(0.0, 1.0) as f64 * file_len as f64) as u64;

    // Entropy: one column per pixel, showing the highest entropy in its range so thin
    // compressed regions don't vanish when there are more blocks than pixels.
    let map_rect = Rect::from_min_size(rect.min, Vec2::new(width, MAP_H));
    let columns = width.max(1.0) as usize;
    if !blocks.is_empty() {
        for col in 0..columns {
            let (from, to) = (col * blocks.len() / columns, ((col + 1) * blocks.len() / columns).max(col * blocks.len() / columns + 1));
            let e = blocks[from.min(blocks.len() - 1)..to.min(blocks.len())].iter().map(|b| b.entropy).fold(0.0, f64::max);
            let x = map_rect.left() + col as f32;
            let h = (e / 8.0) as f32 * (MAP_H - 4.0) + 4.0;
            painter.rect_filled(
                Rect::from_min_max(Pos2::new(x, map_rect.bottom() - h), Pos2::new(x + 1.0, map_rect.bottom())),
                0.0,
                entropy_color(e),
            );
        }
    }

    // Stream lane.
    let lane = Rect::from_min_size(Pos2::new(rect.left(), map_rect.bottom() + 2.0), Vec2::new(width, LANE_H));
    for s in streams {
        let (x0, x1) = (x_of(s.offset), x_of(s.end()));
        let r = Rect::from_min_max(Pos2::new(x0, lane.top()), Pos2::new(x1.max(x0 + 1.0), lane.bottom()));
        painter.rect_filled(r, 0.0, format_color(s.format));
        if is_edited(s.id) {
            painter.rect_filled(Rect::from_min_max(Pos2::new(r.left(), lane.bottom() - 4.0), r.max), 0.0, Color32::WHITE);
        }
    }
    if let Some(s) = selected.and_then(|id| streams.iter().find(|s| s.id == id)) {
        let (x0, x1) = (x_of(s.offset), x_of(s.end()));
        let r = Rect::from_min_max(Pos2::new(x0 - 2.0, rect.top()), Pos2::new(x1.max(x0 + 1.0) + 2.0, rect.bottom()));
        painter.rect_stroke(r, 1.0, Stroke::new(2.0, ui.visuals().strong_text_color()), StrokeKind::Inside);
    }

    // The stream under the pointer: the one containing it, else the nearest within 4 px.
    let stream_at = |x: f32| -> Option<&StreamEntry> {
        let offset = offset_at(x);
        let i = streams.partition_point(|s| s.end() <= offset);
        let candidates = streams.get(i.saturating_sub(1)..(i + 1).min(streams.len())).unwrap_or(&[]);
        candidates
            .iter()
            .map(|s| (s, if s.offset <= offset && offset < s.end() { 0.0 } else { (x_of(s.offset) - x).abs().min((x_of(s.end()) - x).abs()) }))
            .filter(|&(_, d)| d <= 4.0)
            .min_by(|a, b| a.1.total_cmp(&b.1))
            .map(|(s, _)| s)
    };

    let mut clicked = None;
    if let Some(pos) = response.interact_pointer_pos().filter(|_| response.clicked()) {
        clicked = stream_at(pos.x).map(|s| s.id);
    }
    if let Some(pos) = response.hover_pos() {
        let offset = offset_at(pos.x);
        let block = blocks.iter().rfind(|b| b.offset <= offset);
        let stream = stream_at(pos.x).cloned();
        response.on_hover_ui_at_pointer(|ui| {
            ui.label(RichText::new(format!("offset {offset:#x}")).monospace());
            if let Some(b) = block {
                ui.label(format!("entropy {:.2} bits/byte", b.entropy));
            }
            if let Some(s) = stream {
                ui.label(format!(
                    "stream {}: {} at {:#x}, {} bytes, {} decompressed",
                    s.id, s.format, s.offset, s.compressed_size, s.decompressed_size
                ));
            }
        });
    }
    clicked
}

/// Offset column width in hex digits for data ending at `end`.
fn offset_digits(end: u64) -> usize {
    if end > u64::from(u32::MAX) { 12 } else { 8 }
}

/// One hex-dump line: offset, 16 bytes in hex, and their printable characters.
pub fn hex_line(base: u64, row: &[u8], digits: usize) -> String {
    use std::fmt::Write;
    let mut line = format!("{base:0digits$x}  ");
    for i in 0..16 {
        match row.get(i) {
            Some(b) => write!(line, "{b:02x} ").unwrap(),
            None => line.push_str("   "),
        }
        if i == 7 {
            line.push(' ');
        }
    }
    line.push(' ');
    line.extend(row.iter().map(|&b| if b.is_ascii_graphic() || b == b' ' { char::from(b) } else { '.' }));
    line
}

/// A scrollable hex dump of `bytes`, labelled with offsets starting at `base`. Only
/// the visible rows are formatted, so any size works.
pub fn hex_view(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, bytes: &[u8], base: u64) {
    let rows = bytes.len().div_ceil(16);
    let digits = offset_digits(base + bytes.len() as u64);
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
    egui::ScrollArea::both().id_salt(id).auto_shrink(false).show_rows(ui, row_height, rows, |ui, range| {
        for row in range {
            let start = row * 16;
            let line = hex_line(base + start as u64, &bytes[start..(start + 16).min(bytes.len())], digits);
            ui.add(egui::Label::new(RichText::new(line).monospace()).extend());
        }
    });
}

/// Text split into lines for [`text_view`]. Only the first `limit` bytes are kept.
pub struct TextLines {
    text: String,
    /// Start and end of each line in `text`.
    lines: Vec<(usize, usize)>,
    pub truncated: bool,
}

impl TextLines {
    pub fn new(bytes: &[u8], limit: usize) -> Self {
        let text = String::from_utf8_lossy(&bytes[..bytes.len().min(limit)]).into_owned();
        let mut lines = Vec::new();
        let mut start = 0;
        for (i, _) in text.match_indices('\n') {
            lines.push((start, i));
            start = i + 1;
        }
        if start < text.len() {
            lines.push((start, text.len()));
        }
        Self { text, lines, truncated: bytes.len() > limit }
    }
}

pub fn text_view(ui: &mut Ui, id: impl std::hash::Hash + std::fmt::Debug, text: &TextLines) {
    const MAX_LINE: usize = 2000;
    let row_height = ui.text_style_height(&egui::TextStyle::Monospace);
    egui::ScrollArea::both().id_salt(id).auto_shrink(false).show_rows(ui, row_height, text.lines.len(), |ui, range| {
        for &(a, b) in &text.lines[range] {
            let line = text.text[a..b].trim_end_matches('\r');
            let line = match line.char_indices().nth(MAX_LINE) {
                Some((cut, _)) => &line[..cut],
                None => line,
            };
            ui.add(egui::Label::new(RichText::new(line.replace('\t', "    ")).monospace()).extend());
        }
    });
}

/// `1234567` -> `1.18 MiB`
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} bytes") } else { format!("{v:.2} {}", UNITS[unit]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_lines() {
        assert_eq!(
            hex_line(0x10, b"Hello, world!\x00\x01\xff", 8),
            "00000010  48 65 6c 6c 6f 2c 20 77  6f 72 6c 64 21 00 01 ff  Hello, world!..."
        );
        assert_eq!(hex_line(0, b"ab", 8), format!("00000000  61 62 {}  ab", " ".repeat(3 * 14)));
    }

    #[test]
    fn text_lines() {
        let t = TextLines::new(b"one\r\ntwo\nthree", 100);
        assert_eq!(t.lines.len(), 3);
        assert_eq!(&t.text[t.lines[2].0..t.lines[2].1], "three");
        assert!(TextLines::new(b"abcdef", 3).truncated);
    }

    #[test]
    fn colors_and_sizes() {
        assert_eq!(entropy_color(0.0), Color32::from_rgb(16, 24, 64));
        assert_eq!(entropy_color(8.0), Color32::from_rgb(220, 60, 40));
        assert_eq!(entropy_color(9.0), entropy_color(8.0));
        assert_eq!(human_size(512), "512 bytes");
        assert_eq!(human_size(3 << 20), "3.00 MiB");
    }
}
