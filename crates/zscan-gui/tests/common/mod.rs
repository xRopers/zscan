//! A small input file for the GUI tests: text, a PNG and binary records, each compressed.

#![allow(dead_code)]

use std::path::PathBuf;

use zscan_fixtures::{Builder, Kind, gzip, zlib};

pub struct Input {
    pub dir: tempfile::TempDir,
    pub path: PathBuf,
    pub data: Vec<u8>,
    /// Decompressed contents of each stream, in file order.
    pub payloads: Vec<Vec<u8>>,
}

/// A 6×4 RGB PNG.
pub fn tiny_png() -> Vec<u8> {
    let img = image::RgbImage::from_fn(6, 4, |x, y| image::Rgb([(x * 40) as u8, (y * 60) as u8, 200]));
    let mut out = std::io::Cursor::new(Vec::new());
    img.write_to(&mut out, image::ImageFormat::Png).unwrap();
    out.into_inner()
}

pub fn input() -> Input {
    let mut b = Builder::new(42);
    b.random(600);
    let text = b.text(20_000);
    b.stream(Kind::Zlib, zlib(&text, 6), text, None);
    b.random(300);
    let png = tiny_png();
    b.stream(Kind::Zlib, zlib(&png, 9), png, None);
    b.random(300);
    let records = b.records(8000);
    b.stream(Kind::Gzip, gzip(&records, Some("records.bin")), records, Some("records.bin"));
    b.random(400);
    let fixture = b.finish("gui", "text, image and records");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("input.bin");
    std::fs::write(&path, &fixture.data).unwrap();
    Input { dir, path, data: fixture.data, payloads: fixture.expected.into_iter().map(|e| e.payload).collect() }
}
