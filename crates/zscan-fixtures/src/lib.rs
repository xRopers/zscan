//! Deterministic fixtures for zscan tests: binary blobs with compressed streams at known
//! offsets. Everything is generated from fixed seeds, so every run produces the same bytes.
//!
//! `cargo run -p zscan-fixtures --bin gen-fixtures` writes them to `tests/fixtures/`.
//!
//! Streams are made with stock zlib (flate2's zlib backend), so the scanner's parameter
//! matching should reproduce them exactly, except ones marked `zlib_made: false`.

use std::io::Write;

use flate2::Compression;
use flate2::GzBuilder;
use flate2::write::{DeflateEncoder, ZlibEncoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gzip,
    Zlib,
    Deflate,
}

impl Kind {
    /// Same spelling as `zscan_core::Format`'s Display/serde form.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Gzip => "gzip",
            Kind::Zlib => "zlib",
            Kind::Deflate => "deflate",
        }
    }
}

/// A stream the scanner is expected to report.
#[derive(Debug, Clone)]
pub struct Expected {
    pub offset: usize,
    pub kind: Kind,
    pub compressed_size: usize,
    pub payload: Vec<u8>,
    pub name: Option<String>,
    /// Made by stock zlib, so some zlib setting reproduces it byte for byte.
    pub zlib_made: bool,
}

#[derive(Debug, Clone)]
pub struct Fixture {
    pub name: &'static str,
    pub description: &'static str,
    pub data: Vec<u8>,
    pub expected: Vec<Expected>,
}

/// xorshift64*: small, fast, and stable across platforms and releases.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next_u64() >> 56) as u8).collect()
    }
}

const WORDS: &[&str] = &[
    "stream", "offset", "deflate", "window", "block", "huffman", "literal", "length", "distance",
    "header", "checksum", "archive", "texture", "model", "level", "packet", "buffer", "table",
    "index", "record", "the", "a", "of", "and", "to", "in",
];

/// Compressible English-like text.
pub fn text(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    while out.len() < len {
        out.extend_from_slice(WORDS[rng.below(WORDS.len() as u64) as usize].as_bytes());
        out.push(if rng.below(12) == 0 { b'\n' } else { b' ' });
    }
    out.truncate(len);
    out
}

/// Compressible fixed-size binary records, like a game data table.
pub fn records(rng: &mut Rng, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 16);
    let mut id = 0u32;
    while out.len() < len {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(rng.below(100) as u16).to_le_bytes());
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&(rng.below(4) as u32).to_le_bytes());
        id += 1;
    }
    out.truncate(len);
    out
}

pub fn deflate(payload: &[u8], level: u32) -> Vec<u8> {
    let mut e = DeflateEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// zlib stream made by miniz_oxide instead of zlib: valid, but no zlib setting reproduces it.
pub fn zlib_miniz(payload: &[u8], level: u8) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(payload, level)
}

pub fn zlib(payload: &[u8], level: u32) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::new(level));
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// zlib stream whose header declares a smaller window. `payload` must be shorter than
/// the window so the deflate data can't reference anything further back.
pub fn zlib_with_window(payload: &[u8], level: u32, window_bits: u8) -> Vec<u8> {
    assert!((8..=15).contains(&window_bits) && payload.len() < 1 << window_bits);
    let cmf = ((window_bits - 8) << 4) | 8;
    let check = ((u16::from(cmf) << 8) % 31) as u8;
    let flg = (31 - check) % 31;
    let mut out = vec![cmf, flg];
    out.extend(deflate(payload, level));
    out.extend(adler32(payload).to_be_bytes());
    out
}

pub fn gzip(payload: &[u8], name: Option<&str>) -> Vec<u8> {
    let mut builder = GzBuilder::new().mtime(0);
    if let Some(name) = name {
        builder = builder.filename(name);
    }
    let mut e = builder.write(Vec::new(), Compression::default());
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// gzip member with every optional header field: FEXTRA, FNAME, FCOMMENT and FHCRC.
pub fn gzip_all_fields(payload: &[u8], name: &str) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0x02 | 0x04 | 0x08 | 0x10, 0, 0, 0, 0, 0, 255];
    let extra = b"ZS\x04\x00test";
    out.extend((extra.len() as u16).to_le_bytes());
    out.extend(extra);
    out.extend(name.as_bytes());
    out.push(0);
    out.extend(b"made by zscan-fixtures");
    out.push(0);
    let hcrc = crc32fast::hash(&out) as u16;
    out.extend(hcrc.to_le_bytes());
    out.extend(deflate(payload, 6));
    out.extend(crc32fast::hash(payload).to_le_bytes());
    out.extend((payload.len() as u32).to_le_bytes());
    out
}

pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &x in data {
        a = (a + u32::from(x)) % 65521;
        b = (b + a) % 65521;
    }
    (b << 16) | a
}

/// Appends pieces to a blob while recording where the expected streams land.
pub struct Builder {
    pub data: Vec<u8>,
    pub expected: Vec<Expected>,
    pub rng: Rng,
}

impl Builder {
    pub fn new(seed: u64) -> Self {
        Self { data: Vec::new(), expected: Vec::new(), rng: Rng::new(seed) }
    }

    pub fn random(&mut self, len: usize) {
        let bytes = self.rng.bytes(len);
        self.data.extend(bytes);
    }

    pub fn zeros(&mut self, len: usize) {
        self.data.resize(self.data.len() + len, 0);
    }

    /// Bytes that should not be reported as a stream.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }

    pub fn text(&mut self, len: usize) -> Vec<u8> {
        text(&mut self.rng, len)
    }

    pub fn records(&mut self, len: usize) -> Vec<u8> {
        records(&mut self.rng, len)
    }

    /// Append an encoded stream that the scanner should report at this position.
    pub fn stream(&mut self, kind: Kind, encoded: Vec<u8>, payload: Vec<u8>, name: Option<&str>) {
        self.expect(self.data.len(), kind, encoded.len(), payload, name);
        self.data.extend(encoded);
    }

    /// Like [`Builder::stream`], for a stream not made by zlib.
    pub fn foreign_stream(&mut self, kind: Kind, encoded: Vec<u8>, payload: Vec<u8>) {
        self.stream(kind, encoded, payload, None);
        self.expected.last_mut().unwrap().zlib_made = false;
    }

    /// Record an expected stream at an arbitrary offset (for streams nested in other bytes).
    pub fn expect(&mut self, offset: usize, kind: Kind, compressed_size: usize, payload: Vec<u8>, name: Option<&str>) {
        self.expected.push(Expected { offset, kind, compressed_size, payload, name: name.map(String::from), zlib_made: true });
    }

    pub fn finish(mut self, name: &'static str, description: &'static str) -> Fixture {
        self.expected.sort_by_key(|e| e.offset);
        Fixture { name, description, data: self.data, expected: self.expected }
    }
}

pub fn all() -> Vec<Fixture> {
    vec![zlib_basic(), gzip_basic(), deflate_raw(), mixed(), noise()]
}

pub fn zlib_basic() -> Fixture {
    let mut b = Builder::new(1);
    b.random(1000);
    let p = b.text(5000);
    b.stream(Kind::Zlib, zlib(&p, 6), p, None);
    b.random(777);
    let p = b.text(20_000);
    b.stream(Kind::Zlib, zlib(&p, 9), p, None);
    b.zeros(100);
    let p = b.records(3000);
    b.stream(Kind::Zlib, zlib(&p, 1), p, None);
    // Back to back, no gap.
    let p = b.text(100);
    b.stream(Kind::Zlib, zlib(&p, 0), p, None);
    let p = b.text(2000);
    b.stream(Kind::Zlib, zlib_with_window(&p, 6, 12), p, None);
    b.random(500);
    let p = b.text(4000);
    b.foreign_stream(Kind::Zlib, zlib_miniz(&p, 6), p);
    b.random(300);
    b.finish(
        "zlib_basic",
        "zlib streams at several levels, a stored stream, a 4 KiB-window header, back-to-back streams, one made by miniz",
    )
}

pub fn gzip_basic() -> Fixture {
    let mut b = Builder::new(2);
    b.random(300);
    let p = b.text(6000);
    b.stream(Kind::Gzip, gzip(&p, Some("hello.txt")), p, Some("hello.txt"));
    b.random(1234);
    let p = b.records(4000);
    b.stream(Kind::Gzip, gzip(&p, None), p, None);
    b.random(64);
    let p = b.text(3000);
    b.stream(Kind::Gzip, gzip_all_fields(&p, "all_fields.bin"), p, Some("all_fields.bin"));
    // Second member of a multi-member gzip file.
    let p = b.text(1500);
    b.stream(Kind::Gzip, gzip(&p, None), p, None);
    b.random(200);
    b.finish("gzip_basic", "gzip members with and without FNAME, one with every optional header field, multi-member")
}

pub fn deflate_raw() -> Fixture {
    let mut b = Builder::new(3);
    b.random(2048);
    let p = b.text(8000);
    b.stream(Kind::Deflate, deflate(&p, 6), p, None);
    b.random(3000);
    let p = b.records(4000);
    b.stream(Kind::Deflate, deflate(&p, 9), p, None);
    b.zeros(64);
    let p = b.text(1000);
    b.stream(Kind::Deflate, deflate(&p, 0), p, None);
    b.random(1000);
    b.finish("deflate_raw", "raw deflate streams (fixed/dynamic and stored) between random filler")
}

pub fn mixed() -> Fixture {
    let mut b = Builder::new(4);
    b.random(512);
    let p = b.text(4000);
    b.stream(Kind::Zlib, zlib(&p, 6), p, None);
    b.random(100);
    let p = b.text(4000);
    b.stream(Kind::Gzip, gzip(&p, Some("inner.txt")), p, Some("inner.txt"));
    b.random(100);
    let p = b.records(5000);
    b.stream(Kind::Deflate, deflate(&p, 6), p, None);

    // Trap: zlib header followed by junk.
    b.random(100);
    b.raw(&[0x78, 0x9c]);
    b.random(200);
    // Trap: gzip header followed by junk.
    b.raw(&[0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0xff]);
    b.random(300);
    // Trap: zlib stream with a corrupt Adler-32. Not zlib, but its deflate body is
    // intact, so it should come back as raw deflate two bytes in.
    let p = b.text(3000);
    let mut bad = zlib(&p, 6);
    let last = bad.len() - 1;
    bad[last] ^= 0xff;
    let body_offset = b.data.len() + 2;
    let body_len = bad.len() - 6;
    b.raw(&bad);
    b.expect(body_offset, Kind::Deflate, body_len, p, None);
    // Trap: truncated gzip member.
    b.random(100);
    let p = b.text(5000);
    let gz = gzip(&p, None);
    b.raw(&gz[..gz.len() / 2]);
    // Trap: a real zlib stream, but below the default minimum size.
    b.random(100);
    let p = b.text(10);
    b.raw(&zlib(&p, 6));
    // Trap: a long run of zeros.
    b.zeros(4096);
    b.random(256);
    b.finish("mixed", "all three formats plus false-positive traps: bare headers, bad checksum, truncation, tiny stream, zeros")
}

pub fn noise() -> Fixture {
    let mut b = Builder::new(99);
    b.random(1 << 20);
    b.finish("noise", "1 MiB of random bytes; nothing should be found")
}
