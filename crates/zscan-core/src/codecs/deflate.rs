//! Raw deflate (RFC 1951).

use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::deflater::{DeflateParams, Strategy, compress_raw, find_params};
use crate::params::EncoderParams;

pub struct DeflateCodec;

/// Cheap check that `data` starts with a plausible deflate block header.
///
/// - BTYPE 11 is reserved, so it is rejected.
/// - Stored blocks need LEN == !NLEN. The header's 5 padding bits must also be zero;
///   the spec does not require that, but every real encoder writes zeros.
/// - Dynamic blocks need HLIT <= 29, HDIST <= 29, and a code-length code that is a
///   complete prefix code. zlib's inflate rejects incomplete ones and its deflate never
///   writes one. This check alone rejects most random offsets before any table building.
pub fn probe_block_header(data: &[u8]) -> bool {
    let Some(&b0) = data.first() else { return false };
    match (b0 >> 1) & 3 {
        0 => {
            b0 >> 3 == 0
                && data.len() >= 5
                && u16::from_le_bytes([data[1], data[2]]) == !u16::from_le_bytes([data[3], data[4]])
        }
        1 => probe_fixed_block(data),
        2 => probe_dynamic_header(data),
        _ => false,
    }
}

/// Fixed-Huffman literal/length decode table indexed by the next 9 input bits (LSB-first):
/// (symbol, code length). Built at compile time.
static FIXED_LITLEN: [(u16, u8); 512] = build_fixed_litlen();

const fn build_fixed_litlen() -> [(u16, u8); 512] {
    let mut table = [(0u16, 0u8); 512];
    let mut sym = 0u16;
    while sym < 288 {
        // RFC 1951 3.2.6: code lengths and first codes for each symbol range.
        let (len, code) = match sym {
            0..=143 => (8, 0x30 + sym),
            144..=255 => (9, 0x190 + sym - 144),
            256..=279 => (7, sym - 256),
            _ => (8, 0xc0 + sym - 280),
        };
        // Huffman codes are packed MSB-first, so reverse them for LSB-first lookup.
        let mut rev = 0u16;
        let mut i = 0;
        while i < len {
            rev |= ((code >> i) & 1) << (len - 1 - i);
            i += 1;
        }
        let mut fill = 0u16;
        while fill < 1 << (9 - len) {
            table[(rev | (fill << len)) as usize] = (sym, len as u8);
            fill += 1;
        }
        sym += 1;
    }
    table
}

const LEN_BASE: [u16; 29] =
    [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
const LEN_EXTRA: [u8; 29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145,
    8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];

/// How many symbols of a fixed block to check before handing over to the real decoder.
const FIXED_PROBE_SYMBOLS: usize = 64;

/// Decode the first symbols of a fixed-Huffman block with static tables, rejecting only
/// what every inflater rejects: literal/length codes 286-287, distance codes 30-31, and
/// distances reaching back before the start of the stream. About a quarter of random
/// offsets look like fixed blocks. Rejecting their garbage here saves the real decoder's
/// per-block table setup, which was the dominant cost of the raw deflate pass.
fn probe_fixed_block(data: &[u8]) -> bool {
    let mut bit = 3usize; // past BFINAL + BTYPE
    let mut out = 0usize;
    // Up to 25 bits from `bit` (9 code + 5 extra + 5 distance + 13 extra fit in two reads).
    let peek = |bit: usize| -> Option<u32> {
        let byte = bit >> 3;
        let mut word = [0u8; 4];
        let avail = data.len().checked_sub(byte)?.min(4);
        if avail < 4 {
            return None;
        }
        word.copy_from_slice(&data[byte..byte + 4]);
        Some(u32::from_le_bytes(word) >> (bit & 7))
    };
    for _ in 0..FIXED_PROBE_SYMBOLS {
        // Running out of input is for the real decoder to judge.
        let Some(bits) = peek(bit) else { return true };
        let (sym, len) = FIXED_LITLEN[(bits & 0x1ff) as usize];
        bit += usize::from(len);
        match sym {
            0..=255 => out += 1,
            256 => return true, // end of block; later blocks are not checked
            286.. => return false,
            _ => {
                let i = usize::from(sym - 257);
                let Some(bits) = peek(bit) else { return true };
                let extra = LEN_EXTRA[i];
                let length = usize::from(LEN_BASE[i]) + (bits & ((1 << extra) - 1)) as usize;
                bit += usize::from(extra);

                let Some(bits) = peek(bit) else { return true };
                let code = bits & 0x1f;
                let dist_sym = ((code.reverse_bits()) >> 27) as usize; // 5-bit code, MSB-first
                if dist_sym >= 30 {
                    return false;
                }
                bit += 5;
                let Some(bits) = peek(bit) else { return true };
                let extra = DIST_EXTRA[dist_sym];
                let distance = usize::from(DIST_BASE[dist_sym]) + (bits & ((1 << extra) - 1)) as usize;
                bit += usize::from(extra);
                if distance > out {
                    return false;
                }
                out += length;
            }
        }
    }
    true
}

fn probe_dynamic_header(data: &[u8]) -> bool {
    // The header fits in 3 + 5 + 5 + 4 + 19 * 3 = 74 bits.
    let mut bytes = [0u8; 16];
    let n = data.len().min(10);
    bytes[..n].copy_from_slice(&data[..n]);
    let bits = u128::from_le_bytes(bytes);
    let field = |pos: u32, width: u32| ((bits >> pos) & ((1 << width) - 1)) as u32;

    let (hlit, hdist, hclen) = (field(3, 5), field(8, 5), field(13, 4) + 4);
    if hlit > 29 || hdist > 29 {
        return false;
    }
    if data.len() < (17 + 3 * hclen as usize).div_ceil(8) {
        return true; // Too short to judge; decode will report truncation.
    }
    // Kraft sum in units of 2^-7 (code lengths are at most 7): complete means exactly 128.
    let kraft: u32 = (0..hclen).map(|i| field(17 + 3 * i, 3)).filter(|&len| len > 0).map(|len| 1 << (7 - len)).sum();
    kraft == 128
}

impl Codec for DeflateCodec {
    fn format(&self) -> Format {
        Format::Deflate
    }

    fn self_verifying(&self) -> bool {
        false
    }

    fn probe(&self, data: &[u8]) -> bool {
        probe_block_header(data)
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let (consumed, len) = ctx.inflate(data)?;
        Ok(Decoded { compressed_size: consumed, body: 0..consumed, data: ctx.take_output(len), original_name: None })
    }

    /// Stored blocks are copied verbatim, so their contents prove nothing: only what
    /// follows the leading stored blocks counts. A chance stored header (LEN == !NLEN)
    /// in random data followed by a short garbage block that happens to end was the one
    /// false positive in 1 GiB of mixed test data (stage 4).
    fn evidence(&self, stream: &[u8]) -> usize {
        stream.len() - stored_prefix_len(stream).min(stream.len())
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        find_family_params(stream, decoded, None)
    }

    fn default_params(&self, _stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        EncoderParams::Deflate(DeflateParams::zlib_default(15))
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, params: &EncoderParams) -> Result<EncoderParams, String> {
        adapt_family_params(params, 15)
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        stronger_family_params(base)
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], params: &EncoderParams) -> Vec<u8> {
        compress_raw(data, family_params(params))
    }
}

/// Bytes taken up by the stored blocks at the start of a raw deflate stream. Stored
/// blocks end byte-aligned, so consecutive ones can be walked without decoding.
pub(crate) fn stored_prefix_len(stream: &[u8]) -> usize {
    let mut pos = 0;
    while let Some(&header) = stream.get(pos) {
        if (header >> 1) & 3 != 0 {
            break;
        }
        let Some(len) = stream.get(pos + 1..pos + 3) else { break };
        pos += 5 + usize::from(u16::from_le_bytes([len[0], len[1]]));
        if header & 1 != 0 {
            break; // final block
        }
    }
    pos
}

// Shared by the deflate family (gzip, zlib, raw deflate), which all encode with zlib.

/// Exact settings for a deflate-family stream: search on its raw deflate body.
pub(crate) fn find_family_params(stream: &[u8], decoded: &Decoded, window_hint: Option<u8>) -> Option<EncoderParams> {
    find_params(&decoded.data, &stream[decoded.body.clone()], window_hint).map(EncoderParams::Deflate)
}

/// Check that `params` are valid zlib settings, capping the window at `max_window`
/// (what the original header allows a decoder to assume).
pub(crate) fn adapt_family_params(params: &EncoderParams, max_window: u8) -> Result<EncoderParams, String> {
    let p = params.as_deflate().ok_or_else(|| format!("{params} are not deflate settings"))?;
    if !p.is_valid() {
        return Err(format!("invalid deflate settings {p}"));
    }
    Ok(EncoderParams::Deflate(DeflateParams { window_bits: p.window_bits.min(max_window), ..*p }))
}

/// Level 9 with each memLevel/strategy combination that tends to help, keeping the window.
pub(crate) fn stronger_family_params(base: &EncoderParams) -> Vec<EncoderParams> {
    let window_bits = family_params(base).window_bits;
    let mut out = Vec::new();
    for mem_level in [9, 8] {
        for strategy in [Strategy::Default, Strategy::Filtered] {
            let p = EncoderParams::Deflate(DeflateParams { level: 9, window_bits, mem_level, strategy });
            if p != *base {
                out.push(p);
            }
        }
    }
    out
}

pub(crate) fn family_params(params: &EncoderParams) -> &DeflateParams {
    params.as_deflate().expect("deflate-family codec given non-deflate params")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_reserved_and_bad_stored() {
        assert!(!probe_block_header(&[0b110])); // BTYPE 11
        assert!(!probe_block_header(&[0x01, 0x05, 0x00, 0x00, 0x00])); // LEN != !NLEN
        assert!(probe_block_header(&[0x01, 0x05, 0x00, 0xfa, 0xff])); // stored, LEN 5
        assert!(!probe_block_header(&[0x09, 0x05, 0x00, 0xfa, 0xff])); // non-zero padding
        assert!(!probe_block_header(&[]));
    }

    /// The fixed-block probe must never reject a stream the decoder accepts.
    #[test]
    fn fixed_probe_accepts_real_fixed_streams() {
        let mut ctx = DecodeCtx::new(1 << 24);
        let mut checked = 0;
        for n in 1..400usize {
            let data: Vec<u8> = (0..n).map(|i| (i * i % 7 + (i / 5) % 3) as u8 + b'a').collect();
            for level in [1, 6, 9] {
                let body = miniz_oxide::deflate::compress_to_vec(&data, level);
                if (body[0] >> 1) & 3 != 1 {
                    continue; // not a fixed block
                }
                checked += 1;
                assert!(probe_fixed_block(&body), "n={n} level={level}");
                assert_eq!(DeflateCodec.decode(&body, &mut ctx).unwrap().data, data);
            }
        }
        assert!(checked > 100, "only {checked} fixed-block streams generated");
    }

    #[test]
    fn fixed_probe_agrees_with_decoder_on_random_input() {
        // Anything the probe rejects, the decoder must reject too.
        let mut ctx = DecodeCtx::new(1 << 20);
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let data: Vec<u8> = (0..200_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 32) as u8
            })
            .collect();
        let (mut rejected, mut agreed) = (0, 0);
        for pos in 0..data.len() - 8 {
            let w = &data[pos..];
            if (w[0] >> 1) & 3 == 1 && !probe_fixed_block(w) {
                rejected += 1;
                if ctx.inflate(w).is_err() {
                    agreed += 1;
                }
            }
        }
        assert_eq!(rejected, agreed);
        assert!(rejected > 40_000, "probe should reject most random fixed-block starts, got {rejected}");
    }

    #[test]
    fn stored_prefix() {
        let stored = [0x00, 0x02, 0x00, 0xfd, 0xff, b'a', b'b', 0x01, 0x01, 0x00, 0xfe, 0xff, b'c'];
        assert_eq!(stored_prefix_len(&stored), stored.len());
        assert_eq!(DeflateCodec.evidence(&stored), 0);
        let mut mixed = stored[..7].to_vec();
        mixed.extend([0x4b, 0x04, 0x00]); // fixed block after the first stored one
        assert_eq!(stored_prefix_len(&mixed), 7);
        assert_eq!(DeflateCodec.evidence(&mixed), 3);
    }

    #[test]
    fn decode_stored_block() {
        let stream = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c', 0xee];
        let mut ctx = DecodeCtx::new(1 << 20);
        let d = DeflateCodec.decode(&stream, &mut ctx).unwrap();
        assert_eq!(d.data, b"abc");
        assert_eq!(d.compressed_size, 8, "trailing byte must not be counted");
    }

    #[test]
    fn truncated_and_too_large() {
        let mut ctx = DecodeCtx::new(1 << 20);
        let stream = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a'];
        assert_eq!(DeflateCodec.decode(&stream, &mut ctx).unwrap_err(), DecodeError::Truncated);

        let mut small = DecodeCtx::new(2);
        let stream = [0x01, 0x03, 0x00, 0xfc, 0xff, b'a', b'b', b'c'];
        assert_eq!(DeflateCodec.decode(&stream, &mut small).unwrap_err(), DecodeError::TooLarge(2));
    }
}
