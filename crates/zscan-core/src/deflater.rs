//! Raw deflate compression through stock zlib (bundled by `libz-sys`), with full control
//! over level, window bits, memLevel and strategy, plus the search that finds which
//! settings reproduce an existing stream byte for byte.

use std::alloc::{Layout, alloc, dealloc};
use std::ffi::{c_int, c_void};
use std::fmt;
use std::ptr;

use libz_sys as z;
use serde::{Deserialize, Serialize};


/// zlib compression strategies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Default,
    Filtered,
    HuffmanOnly,
    Rle,
    Fixed,
}

/// Complete zlib deflate settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeflateParams {
    pub level: u8,
    pub window_bits: u8,
    pub mem_level: u8,
    pub strategy: Strategy,
}

impl DeflateParams {
    /// zlib's defaults (`compress2` at level 6) with the given window.
    pub fn zlib_default(window_bits: u8) -> Self {
        Self { level: 6, window_bits, mem_level: 8, strategy: Strategy::Default }
    }

    /// True if zlib accepts these settings. zlib silently turns window bits 8 into 9 for raw
    /// deflate, so 8 is rejected here to keep recorded params honest.
    pub fn is_valid(&self) -> bool {
        self.level <= 9 && (9..=15).contains(&self.window_bits) && (1..=9).contains(&self.mem_level)
    }
}

impl fmt::Display for DeflateParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let strategy = match self.strategy {
            Strategy::Default => "default",
            Strategy::Filtered => "filtered",
            Strategy::HuffmanOnly => "huffman",
            Strategy::Rle => "rle",
            Strategy::Fixed => "fixed",
        };
        write!(f, "L{} W{} M{} {strategy}", self.level, self.window_bits, self.mem_level)
    }
}

fn strategy_code(s: Strategy) -> c_int {
    match s {
        Strategy::Default => z::Z_DEFAULT_STRATEGY,
        Strategy::Filtered => z::Z_FILTERED,
        Strategy::HuffmanOnly => z::Z_HUFFMAN_ONLY,
        Strategy::Rle => z::Z_RLE,
        Strategy::Fixed => z::Z_FIXED,
    }
}

/// Compress `data` to a raw deflate stream.
///
/// Panics if `params` is not valid; check [`DeflateParams::is_valid`] for untrusted input.
pub fn compress_raw(data: &[u8], params: &DeflateParams) -> Vec<u8> {
    let mut out = Vec::new();
    Deflater::new(params).run(data, output_chunk(params, data, 256 * 1024), |chunk| {
        out.extend_from_slice(chunk);
        true
    });
    out
}

/// True if compressing `data` with `params` produces exactly `expected`.
/// Stops at the first differing output chunk.
pub fn reproduces(data: &[u8], params: &DeflateParams, expected: &[u8]) -> bool {
    let mut pos = 0;
    let finished = Deflater::new(params).run(data, output_chunk(params, data, 4096), |chunk| {
        if expected.get(pos..pos + chunk.len()) == Some(chunk) {
            pos += chunk.len();
            true
        } else {
            false
        }
    });
    finished && pos == expected.len()
}

/// Level 0 (stored) block sizes depend on how much output space each `deflate()` call
/// has, so stored streams are produced in one call, the way `compress2()` does it.
/// Other levels are independent of output buffering.
fn output_chunk(params: &DeflateParams, data: &[u8], chunk: usize) -> usize {
    if params.level == 0 {
        // Stored overhead is 5 bytes per block of at most 65535 bytes (deflateBound is
        // exact for level 0 but needs an initialised stream).
        data.len() + 5 * (data.len() / 65535 + 1) + 16
    } else {
        chunk
    }
}

/// Find settings that reproduce the raw deflate stream `body` from `data`, trying the
/// most common ones first. `window_hint` (from a zlib header) limits the window search.
pub fn find_params(data: &[u8], body: &[u8], window_hint: Option<u8>) -> Option<DeflateParams> {
    const MEM_LEVELS: [u8; 9] = [8, 9, 7, 6, 5, 4, 3, 2, 1];
    const LEVELS: [u8; 9] = [6, 9, 1, 5, 4, 7, 8, 2, 3];
    const ALL_WINDOWS: [u8; 7] = [15, 14, 13, 12, 11, 10, 9];

    let mem_levels: Vec<u8> = match mem_level_hint(body) {
        MemLevelHint::Exactly(m) => vec![m],
        MemLevelHint::AtLeast(min) => MEM_LEVELS.into_iter().filter(|&m| m >= min).collect(),
        MemLevelHint::NotZlib => return None,
        MemLevelHint::Unknown => MEM_LEVELS.to_vec(),
    };
    let windows: Vec<u8> = match window_hint.filter(|w| (9..=15).contains(w)) {
        Some(w) => vec![w],
        // A window at least as big as the input (plus zlib's lookahead margin) never
        // limits a match, so it gives the same output as 15, which is tried first.
        None => ALL_WINDOWS.into_iter().filter(|&w| w == 15 || (1usize << w) - 262 < data.len()).collect(),
    };

    for &mem_level in &mem_levels {
        for &window_bits in &windows {
            let mut candidates = Vec::with_capacity(27);
            for &level in &LEVELS {
                candidates.push((level, Strategy::Default));
                // Z_FILTERED only changes the lazy matcher, used by levels 4-9.
                if level >= 4 {
                    candidates.push((level, Strategy::Filtered));
                }
                candidates.push((level, Strategy::Fixed));
            }
            // Huffman-only and RLE ignore the level; record them as 6 like zlib's default.
            candidates.push((6, Strategy::Rle));
            candidates.push((6, Strategy::HuffmanOnly));
            candidates.push((0, Strategy::Default));

            for (level, strategy) in candidates {
                let params = DeflateParams { level, window_bits, mem_level, strategy };
                if reproduces(data, &params, body) {
                    return Some(params);
                }
            }
        }
    }
    None
}

/// What the first block of a raw deflate stream says about zlib's memLevel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MemLevelHint {
    Exactly(u8),
    AtLeast(u8),
    /// No zlib setting produces this block structure.
    NotZlib,
    /// Stored first block, or unparsable: no information.
    Unknown,
}

/// zlib ends a block when its symbol buffer fills, after exactly 2^(memLevel+6) - 1
/// literals and matches (all strategies except stored). A first block that isn't the
/// last therefore pins memLevel, and one of any other length proves the stream wasn't
/// made by zlib, which saves a stream like that the whole parameter search. A final
/// first block only shows the buffer was bigger than its length.
fn mem_level_hint(body: &[u8]) -> MemLevelHint {
    let Some(block) = first_block(body) else { return MemLevelHint::Unknown };
    if block.stored {
        return MemLevelHint::Unknown;
    }
    let capacity = |m: u8| (1u32 << (m + 6)) - 1;
    if block.last {
        (1..=9).find(|&m| capacity(m) > block.symbols).map_or(MemLevelHint::NotZlib, MemLevelHint::AtLeast)
    } else {
        (1..=9).find(|&m| capacity(m) == block.symbols).map_or(MemLevelHint::NotZlib, MemLevelHint::Exactly)
    }
}

struct FirstBlock {
    last: bool,
    stored: bool,
    /// Literals plus matches, not counting end-of-block.
    symbols: u32,
}

/// Parse the first deflate block just far enough to count its symbols.
fn first_block(body: &[u8]) -> Option<FirstBlock> {
    let mut bits = BitReader { data: body, pos: 0 };
    let last = bits.read(1)? == 1;
    let (litlen, dist) = match bits.read(2)? {
        0 => return Some(FirstBlock { last, stored: true, symbols: 0 }),
        1 => {
            let mut lengths = [8u8; 288];
            lengths[144..256].fill(9);
            lengths[256..280].fill(7);
            (Huffman::new(&lengths)?, Huffman::new(&[5; 30])?)
        }
        2 => {
            const ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
            let hlit = bits.read(5)? as usize + 257;
            let hdist = bits.read(5)? as usize + 1;
            let hclen = bits.read(4)? as usize + 4;
            let mut cl_lengths = [0u8; 19];
            for &i in &ORDER[..hclen] {
                cl_lengths[i] = bits.read(3)? as u8;
            }
            let cl = Huffman::new(&cl_lengths)?;
            let mut lengths = vec![0u8; hlit + hdist];
            let mut i = 0;
            while i < lengths.len() {
                let (value, repeat) = match cl.decode(&mut bits)? {
                    sym @ 0..=15 => (sym as u8, 1),
                    16 => (*lengths.get(i.checked_sub(1)?)?, 3 + bits.read(2)? as usize),
                    17 => (0, 3 + bits.read(3)? as usize),
                    _ => (0, 11 + bits.read(7)? as usize),
                };
                lengths.get_mut(i..i + repeat)?.fill(value);
                i += repeat;
            }
            (Huffman::new(&lengths[..hlit])?, Huffman::new(&lengths[hlit..])?)
        }
        _ => return None,
    };
    const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
    const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
    let mut symbols = 0u32;
    loop {
        match litlen.decode(&mut bits)? {
            0..=255 => {}
            256 => return Some(FirstBlock { last, stored: false, symbols }),
            sym => {
                bits.read(*LEN_EXTRA.get(usize::from(sym) - 257)?)?;
                let dist_sym = usize::from(dist.decode(&mut bits)?);
                bits.read(*DIST_EXTRA.get(dist_sym)?)?;
            }
        }
        symbols += 1;
    }
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BitReader<'_> {
    /// Read `n` bits (at most 16), least significant first.
    fn read(&mut self, n: u8) -> Option<u32> {
        let mut v = 0;
        for i in 0..n {
            let byte = *self.data.get(self.pos >> 3)?;
            v |= u32::from((byte >> (self.pos & 7)) & 1) << i;
            self.pos += 1;
        }
        Some(v)
    }
}

/// Canonical Huffman decoding, one bit at a time (as in zlib's puff.c).
struct Huffman {
    count: [u16; 16],
    symbols: Vec<u16>,
}

impl Huffman {
    fn new(lengths: &[u8]) -> Option<Self> {
        let mut count = [0u16; 16];
        for &l in lengths {
            count[usize::from(l)] += 1;
        }
        count[0] = 0;
        let mut offsets = [0u16; 16];
        for len in 1..15 {
            offsets[len + 1] = offsets[len] + count[len];
        }
        let mut symbols = vec![0u16; lengths.len()];
        for (sym, &l) in lengths.iter().enumerate() {
            if l != 0 {
                symbols[usize::from(offsets[usize::from(l)])] = sym as u16;
                offsets[usize::from(l)] += 1;
            }
        }
        Some(Self { count, symbols })
    }

    fn decode(&self, bits: &mut BitReader) -> Option<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0i32);
        for len in 1..16 {
            code |= bits.read(1)? as i32;
            let count = i32::from(self.count[len]);
            if code - count < first {
                return self.symbols.get((index + code - first) as usize).copied();
            }
            index += count;
            first = (first + count) << 1;
            code <<= 1;
        }
        None
    }
}

struct Deflater {
    // Boxed because zlib keeps a pointer back to the stream struct.
    strm: Box<z::z_stream>,
}

impl Deflater {
    fn new(params: &DeflateParams) -> Self {
        assert!(params.is_valid(), "invalid deflate params {params:?}");
        let mut strm = Box::new(z::z_stream {
            next_in: ptr::null_mut(),
            avail_in: 0,
            total_in: 0,
            next_out: ptr::null_mut(),
            avail_out: 0,
            total_out: 0,
            msg: ptr::null_mut(),
            state: ptr::null_mut(),
            zalloc,
            zfree,
            opaque: ptr::null_mut(),
            data_type: 0,
            adler: 0,
            reserved: 0,
        });
        // SAFETY: `strm` is a fully initialised z_stream with valid allocator callbacks,
        // and it is boxed so its address stays fixed for zlib's internal back-pointer.
        let ret = unsafe {
            z::deflateInit2_(
                &mut *strm,
                c_int::from(params.level),
                z::Z_DEFLATED,
                -c_int::from(params.window_bits),
                c_int::from(params.mem_level),
                strategy_code(params.strategy),
                z::zlibVersion(),
                size_of::<z::z_stream>() as c_int,
            )
        };
        assert_eq!(ret, z::Z_OK, "deflateInit2 failed for {params:?}");
        Self { strm }
    }

    /// Compress all of `input`, handing each piece of output to `sink` as it is produced.
    /// Returns false if `sink` asked to stop early.
    fn run(&mut self, input: &[u8], out_chunk: usize, mut sink: impl FnMut(&[u8]) -> bool) -> bool {
        let mut buf = vec![0u8; out_chunk.clamp(1, u32::MAX as usize)];
        let mut remaining = input;
        loop {
            let take = remaining.len().min(u32::MAX as usize);
            let flush = if take == remaining.len() { z::Z_FINISH } else { z::Z_NO_FLUSH };
            self.strm.next_in = remaining.as_ptr().cast_mut();
            self.strm.avail_in = take as u32;
            loop {
                self.strm.next_out = buf.as_mut_ptr();
                self.strm.avail_out = buf.len() as u32;
                // SAFETY: next_in/avail_in describe `remaining[..take]` and next_out/avail_out
                // describe `buf`; both outlive the call. zlib only reads the input.
                let ret = unsafe { z::deflate(&mut *self.strm, flush) };
                let produced = buf.len() - self.strm.avail_out as usize;
                if produced > 0 && !sink(&buf[..produced]) {
                    return false;
                }
                match ret {
                    z::Z_STREAM_END => return true,
                    z::Z_OK | z::Z_BUF_ERROR => {}
                    other => panic!("zlib deflate failed with code {other}"),
                }
                if flush == z::Z_NO_FLUSH && self.strm.avail_in == 0 && self.strm.avail_out > 0 {
                    break;
                }
            }
            remaining = &remaining[take..];
        }
    }
}

impl Drop for Deflater {
    fn drop(&mut self) {
        // SAFETY: the stream was initialised by deflateInit2_ in `new`.
        unsafe { z::deflateEnd(&mut *self.strm) };
    }
}

// zlib allocator callbacks backed by the Rust global allocator. Each block stores its
// size in a header so `zfree` can rebuild the layout.
const ALLOC_ALIGN: usize = 16;

unsafe extern "C" fn zalloc(_opaque: *mut c_void, items: z::uInt, size: z::uInt) -> *mut c_void {
    let Some(total) = (items as usize).checked_mul(size as usize).and_then(|n| n.checked_add(ALLOC_ALIGN)) else {
        return ptr::null_mut();
    };
    let Ok(layout) = Layout::from_size_align(total, ALLOC_ALIGN) else { return ptr::null_mut() };
    // SAFETY: layout has non-zero size (at least ALLOC_ALIGN bytes).
    unsafe {
        let base = alloc(layout);
        if base.is_null() {
            return ptr::null_mut();
        }
        base.cast::<usize>().write(total);
        base.add(ALLOC_ALIGN).cast()
    }
}

unsafe extern "C" fn zfree(_opaque: *mut c_void, address: *mut c_void) {
    if address.is_null() {
        return;
    }
    // SAFETY: `address` came from `zalloc`, so the size header sits ALLOC_ALIGN bytes before it.
    unsafe {
        let base = address.cast::<u8>().sub(ALLOC_ALIGN);
        let total = base.cast::<usize>().read();
        dealloc(base, Layout::from_size_align_unchecked(total, ALLOC_ALIGN));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{Codec, DecodeCtx};
    use crate::codecs::DeflateCodec;

    fn sample() -> Vec<u8> {
        (0..50_000u32).flat_map(|i| format!("record {} value {}\n", i % 977, i % 13).into_bytes()).collect()
    }

    #[test]
    fn compress_round_trips() {
        let data = sample();
        let mut ctx = DecodeCtx::new(1 << 24);
        for level in [0, 1, 6, 9] {
            for strategy in [Strategy::Default, Strategy::Filtered, Strategy::HuffmanOnly, Strategy::Rle, Strategy::Fixed] {
                let p = DeflateParams { level, window_bits: 15, mem_level: 8, strategy };
                let body = compress_raw(&data, &p);
                let d = DeflateCodec.decode(&body, &mut ctx).unwrap();
                assert_eq!(d.data, data, "{p}");
                assert_eq!(d.compressed_size, body.len());
            }
        }
    }

    #[test]
    fn first_block_reveals_mem_level() {
        let data = sample(); // 1 MB: many blocks at every memLevel
        for mem_level in [1, 5, 8, 9] {
            for strategy in [Strategy::Default, Strategy::Fixed, Strategy::HuffmanOnly] {
                let p = DeflateParams { level: 6, window_bits: 15, mem_level, strategy };
                let hint = mem_level_hint(&compress_raw(&data, &p));
                assert_eq!(hint, MemLevelHint::Exactly(mem_level), "{p}");
            }
        }
        // One block: only a lower bound.
        let small = &data[..2000];
        let hint = mem_level_hint(&compress_raw(small, &DeflateParams::zlib_default(15)));
        assert!(matches!(hint, MemLevelHint::AtLeast(m) if m <= 8), "{hint:?}");
        // Level 0 is all stored blocks: no information.
        let stored = DeflateParams { level: 0, ..DeflateParams::zlib_default(15) };
        assert_eq!(mem_level_hint(&compress_raw(&data, &stored)), MemLevelHint::Unknown);
        // miniz ends blocks at other lengths.
        assert_eq!(mem_level_hint(&miniz_oxide::deflate::compress_to_vec(&data, 6)), MemLevelHint::NotZlib);
    }

    #[test]
    fn empty_input() {
        let body = compress_raw(&[], &DeflateParams::zlib_default(15));
        assert_eq!(body, [0x03, 0x00]);
    }

    #[test]
    fn finds_the_params_that_made_a_stream() {
        let data = sample();
        for p in [
            DeflateParams::zlib_default(15),
            DeflateParams { level: 9, window_bits: 15, mem_level: 9, strategy: Strategy::Default },
            DeflateParams { level: 1, window_bits: 12, mem_level: 8, strategy: Strategy::Default },
            DeflateParams { level: 7, window_bits: 15, mem_level: 5, strategy: Strategy::Filtered },
            DeflateParams { level: 6, window_bits: 15, mem_level: 8, strategy: Strategy::Rle },
            DeflateParams { level: 0, window_bits: 15, mem_level: 8, strategy: Strategy::Default },
        ] {
            let body = compress_raw(&data, &p);
            let found = find_params(&data, &body, None).unwrap_or_else(|| panic!("no match for {p}"));
            // Several settings can give identical output; any of them is a correct answer.
            assert_eq!(compress_raw(&data, &found), body, "{p} -> {found}");
        }
    }

    #[test]
    fn foreign_stream_does_not_match() {
        let data = sample();
        let body = miniz_oxide::deflate::compress_to_vec(&data, 6);
        assert_eq!(find_params(&data, &body, Some(15)), None);
    }

    #[test]
    fn reproduces_rejects_prefix_and_extension() {
        let data = sample();
        let p = DeflateParams::zlib_default(15);
        let body = compress_raw(&data, &p);
        assert!(reproduces(&data, &p, &body));
        assert!(!reproduces(&data, &p, &body[..body.len() - 1]));
        let mut longer = body.clone();
        longer.push(0);
        assert!(!reproduces(&data, &p, &longer));
    }
}
