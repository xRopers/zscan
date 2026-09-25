//! Deterministic fixtures for zscan tests: binary blobs with compressed streams at known
//! offsets. Everything is generated from fixed seeds, so every run produces the same bytes.
//!
//! `cargo run -p zscan-fixtures --bin gen-fixtures` writes them to `tests/fixtures/`.
//!
//! Streams are made with the same encoder libraries zscan uses (zlib via flate2, libzstd,
//! liblzma, libbzip2's Rust port, lz4_flex, brotli), so the scanner's parameter matching
//! should reproduce them exactly, except ones marked `reproducible: false`.

use std::io::Write;

use flate2::Compression;
use flate2::GzBuilder;
use flate2::write::{DeflateEncoder, ZlibEncoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Gzip,
    Zlib,
    Zstd,
    Xz,
    Bzip2,
    Lz4,
    Deflate,
    Brotli,
}

impl Kind {
    /// Same spelling as `zscan_core::Format`'s Display/serde form.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Gzip => "gzip",
            Kind::Zlib => "zlib",
            Kind::Zstd => "zstd",
            Kind::Xz => "xz",
            Kind::Bzip2 => "bzip2",
            Kind::Lz4 => "lz4",
            Kind::Deflate => "deflate",
            Kind::Brotli => "brotli",
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
    /// Made by the encoder library zscan uses for this format, so some setting
    /// reproduces it byte for byte.
    pub reproducible: bool,
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
        self.expected.last_mut().unwrap().reproducible = false;
    }

    /// Record an expected stream at an arbitrary offset (for streams nested in other bytes).
    pub fn expect(&mut self, offset: usize, kind: Kind, compressed_size: usize, payload: Vec<u8>, name: Option<&str>) {
        self.expected.push(Expected { offset, kind, compressed_size, payload, name: name.map(String::from), reproducible: true });
    }

    pub fn finish(mut self, name: &'static str, description: &'static str) -> Fixture {
        self.expected.sort_by_key(|e| e.offset);
        Fixture { name, description, data: self.data, expected: self.expected }
    }
}

/// Every fixture found with the default formats. [`brotli_streams`] needs brotli enabled.
pub fn all() -> Vec<Fixture> {
    vec![zlib_basic(), gzip_basic(), deflate_raw(), mixed(), codecs(), noise()]
}

pub fn zstd_frame(payload: &[u8], level: i32, checksum: bool) -> Vec<u8> {
    let mut c = zstd::bulk::Compressor::new(level).unwrap();
    c.set_parameter(zstd::zstd_safe::CParameter::ChecksumFlag(checksum)).unwrap();
    c.compress(payload).unwrap()
}

/// zstd's streaming encoder with no size given up front: no content size in the header.
pub fn zstd_streamed(payload: &[u8], level: i32) -> Vec<u8> {
    let mut e = zstd::stream::Encoder::new(Vec::new(), level).unwrap();
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// liblzma's easy encoder (what xz2 and Python's lzma use), CRC-64.
pub fn xz_easy(payload: &[u8], preset: u32) -> Vec<u8> {
    let mut e = xz2::write::XzEncoder::new(Vec::new(), preset);
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// Like the `xz` tool: dictionary shrunk to fit the input, CRC-32 check, optionally the
/// multithreaded encoder (which records block sizes in the block header).
pub fn xz_tool_like(payload: &[u8], preset: u32, threaded: bool) -> Vec<u8> {
    use xz2::stream::{Check, Filters, LzmaOptions, MtStreamBuilder, Stream};
    let mut opts = LzmaOptions::new_preset(preset).unwrap();
    opts.dict_size((payload.len() as u32).next_power_of_two().max(4096));
    let mut filters = Filters::new();
    filters.lzma2(&opts);
    let stream = if threaded {
        MtStreamBuilder::new().threads(2).filters(filters).check(Check::Crc32).encoder().unwrap()
    } else {
        Stream::new_stream_encoder(&filters, Check::Crc32).unwrap()
    };
    let mut e = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

pub fn bzip2(payload: &[u8], level: u32) -> Vec<u8> {
    let mut e = ::bzip2::write::BzEncoder::new(Vec::new(), ::bzip2::Compression::new(level));
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// lz4_flex frame. With `linked`, blocks may reference earlier blocks and every
/// checksum is on.
pub fn lz4_frame(payload: &[u8], linked: bool) -> Vec<u8> {
    use lz4_flex::frame::{BlockMode, BlockSize, FrameEncoder, FrameInfo};
    let info = if linked {
        FrameInfo::new()
            .block_size(BlockSize::Max64KB)
            .block_mode(BlockMode::Linked)
            .block_checksums(true)
            .content_checksum(true)
            .content_size(Some(payload.len() as u64))
    } else {
        FrameInfo::new()
    };
    let mut e = FrameEncoder::with_frame_info(info, Vec::new());
    e.write_all(payload).unwrap();
    e.finish().unwrap()
}

/// An LZ4 frame of stored (uncompressed) blocks with a content checksum, built by hand.
/// Valid, but no lz4_flex setting produces it.
pub fn lz4_stored_frame(payload: &[u8]) -> Vec<u8> {
    use xxhash_rust::xxh32::xxh32;
    let mut out = vec![0x04, 0x22, 0x4d, 0x18];
    let descriptor = [0x64, 0x40]; // version 01, independent blocks, content checksum; 64 KiB blocks
    out.extend(descriptor);
    out.push((xxh32(&descriptor, 0) >> 8) as u8);
    for block in payload.chunks(64 * 1024) {
        out.extend((block.len() as u32 | 0x8000_0000).to_le_bytes());
        out.extend(block);
    }
    out.extend(0u32.to_le_bytes());
    out.extend(xxh32(payload, 0).to_le_bytes());
    out
}

pub fn brotli(payload: &[u8], quality: u32, lgwin: u32) -> Vec<u8> {
    let params = ::brotli::enc::backward_references::BrotliEncoderParams {
        quality: quality as i32,
        lgwin: lgwin as i32,
        size_hint: payload.len(),
        ..Default::default()
    };
    let mut out = Vec::new();
    ::brotli::BrotliCompress(&mut &payload[..], &mut out, &params).unwrap();
    out
}

pub fn codecs() -> Fixture {
    let mut b = Builder::new(5);
    b.random(700);
    let p = b.text(9000);
    b.stream(Kind::Zstd, zstd_frame(&p, 3, false), p, None);
    b.random(300);
    let p = b.records(20_000);
    b.stream(Kind::Zstd, zstd_frame(&p, 19, true), p, None);
    b.random(300);
    let p = b.text(5000);
    b.stream(Kind::Zstd, zstd_streamed(&p, 5), p, None);
    b.random(300);
    let p = b.text(7000);
    b.stream(Kind::Xz, xz_easy(&p, 6), p, None);
    b.random(300);
    let p = b.records(6000);
    b.stream(Kind::Xz, xz_tool_like(&p, 3, false), p, None);
    b.random(300);
    let p = b.text(8000);
    b.stream(Kind::Xz, xz_tool_like(&p, 6, true), p, None);
    b.random(300);
    let p = b.text(12_000);
    b.stream(Kind::Bzip2, bzip2(&p, 9), p, None);
    b.random(300);
    let p = b.records(3000);
    b.stream(Kind::Bzip2, bzip2(&p, 1), p, None);
    b.random(300);
    let p = b.text(10_000);
    b.stream(Kind::Lz4, lz4_frame(&p, false), p, None);
    b.random(300);
    let p = b.text(150_000);
    b.stream(Kind::Lz4, lz4_frame(&p, true), p, None);
    b.random(300);
    let p = b.text(2000);
    b.foreign_stream(Kind::Lz4, lz4_stored_frame(&p), p);
    b.random(300);

    // Traps: real magic numbers followed by garbage.
    b.raw(&[0x28, 0xb5, 0x2f, 0xfd, 0x24, 0x10]);
    b.random(200);
    b.raw(b"BZh91AY&SY");
    b.random(200);
    b.raw(&[0xfd, b'7', b'z', b'X', b'Z', 0, 0, 0x04, 0xe6, 0xd6, 0xb4, 0x46]); // valid xz stream header
    b.random(200);
    b.raw(&lz4_frame(b"x", false)[..7]); // valid lz4 frame header
    b.random(200);
    // Trap: a truncated zstd frame.
    let p = b.text(4000);
    let z = zstd_frame(&p, 3, true);
    b.raw(&z[..z.len() - 10]);
    b.random(200);
    // Trap: a zstd frame whose content checksum is wrong.
    let p = b.text(4000);
    let mut z = zstd_frame(&p, 3, true);
    let last = z.len() - 1;
    z[last] ^= 0x55;
    b.raw(&z);
    b.random(500);
    b.finish("codecs", "zstd, xz, bzip2 and lz4 streams in several configurations, plus traps for each format")
}

/// Brotli streams, which have no magic number and are only scanned when asked for.
pub fn brotli_streams() -> Fixture {
    let mut b = Builder::new(6);
    b.random(1000);
    let p = b.text(20_000);
    b.stream(Kind::Brotli, brotli(&p, 11, 22), p, None);
    b.random(1000);
    let p = b.records(8000);
    b.stream(Kind::Brotli, brotli(&p, 5, 18), p, None);
    b.random(1000);
    b.finish("brotli", "brotli streams (quality 11 and 5) in random filler; scan with brotli enabled")
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
    // Stored (level 0) raw deflate: only found with the raw ratio filter off.
    let p = b.text(1000);
    b.raw(&deflate(&p, 0));
    b.random(1000);
    b.finish("deflate_raw", "raw deflate streams between random filler, plus a stored one the default filters skip")
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
