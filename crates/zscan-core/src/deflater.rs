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

    let hinted = window_hint.filter(|w| (9..=15).contains(w)).map(|w| [w]);
    let windows: &[u8] = hinted.as_ref().map_or(&ALL_WINDOWS, |w| w);

    for &mem_level in &MEM_LEVELS {
        for &window_bits in windows {
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
