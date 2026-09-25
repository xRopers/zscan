//! Brotli (RFC 7932). It has no magic number and no checksum, so it is never scanned
//! for ([`Format::scannable`]); streams are added at known offsets with
//! [`decode_at`](crate::scan::decode_at) (`zscan try`), then extract and pack normally.
//!
//! Why not scan: measured in stage 4, even with the start-of-stream checks below, random
//! bytes decode as brotli for kilobytes on average (the static dictionary and permissive
//! prefix codes accept almost anything), so scanning ran at about 1 MiB/s on 24 threads,
//! and on 16 MiB of mixed data with no brotli in it, 4 garbage "streams" of up to 686 KB
//! passed every raw filter.
//!
//! Encoding uses the `brotli` crate, a port of the reference encoder.

use std::io::{self, Write};

use brotli::enc::StandardAlloc;
use brotli::enc::backward_references::{BrotliEncoderMode, BrotliEncoderParams};
use brotli::{BrotliDecompressStream, BrotliResult, BrotliState};

use super::util::{grow, wrong_encoder};
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::params::{BrotliMode, BrotliParams, EncoderParams};

pub struct BrotliCodec;

/// The window size (lgwin, 10-24) encoded in the stream's first bits (RFC 7932 9.1),
/// or `None` for the invalid pattern and large-window streams.
fn stream_lgwin(data: &[u8]) -> Option<u32> {
    let b = u32::from(*data.first()?);
    if b & 1 == 0 {
        return Some(16);
    }
    let n = (b >> 1) & 0x7;
    if n != 0 {
        return Some(17 + n);
    }
    match (b >> 4) & 0x7 {
        0 => Some(17),
        1 => None, // large-window streams (not standard brotli)
        m => Some(8 + m),
    }
}

/// Parse the stream header and the first meta-block header (RFC 7932 9.1-9.2). Returns
/// false for patterns no real encoder starts a compressible stream with: an invalid
/// window, a non-minimal length, a leading metadata block, or a leading uncompressed
/// meta-block. That last is a verbatim copy, so like a stored deflate block it proves
/// nothing, and random bytes read as one often enough that without this check the
/// decoder read ~8.5 KB of garbage per offset before failing.
fn plausible_start(data: &[u8]) -> bool {
    let mut word = [0u8; 8];
    let n = data.len().min(8);
    word[..n].copy_from_slice(&data[..n]);
    let bits = u64::from_le_bytes(word);
    let mut pos = 0u32;
    let mut take = |width: u32| {
        let v = (bits >> pos) & ((1 << width) - 1);
        pos += width;
        v
    };
    // WBITS: 1, 4 or 7 bits.
    if take(1) == 1 && take(3) == 0 && take(3) == 1 {
        return false; // large-window marker
    }
    let is_last = take(1) == 1;
    if is_last && take(1) == 1 {
        return true; // ISLASTEMPTY: a valid, empty stream
    }
    let nibbles = match take(2) {
        3 => return false, // metadata block
        m => m as u32 + 4,
    };
    let mlen_minus_1 = take(4 * nibbles);
    if nibbles > 4 && mlen_minus_1 >> (4 * (nibbles - 1)) == 0 {
        return false; // non-minimal length encoding is invalid
    }
    is_last || take(1) == 0 // ISUNCOMPRESSED
}

fn params(p: &EncoderParams) -> &BrotliParams {
    match p {
        EncoderParams::Brotli(p) => p,
        other => panic!("{}", wrong_encoder("brotli", other)),
    }
}

/// A `Write` that compares what it is given with `expected`, failing at the first
/// difference so the encoder stops early.
struct Compare<'a> {
    expected: &'a [u8],
    pos: usize,
}

impl Write for Compare<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.expected.get(self.pos..self.pos + buf.len()) != Some(buf) {
            return Err(io::Error::other("differs"));
        }
        self.pos += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn compress(data: &[u8], p: &BrotliParams, out: &mut impl Write) -> io::Result<usize> {
    let mut settings = BrotliEncoderParams {
        quality: p.quality as i32,
        lgwin: p.lgwin as i32,
        mode: match p.mode {
            BrotliMode::Generic => BrotliEncoderMode::BROTLI_MODE_GENERIC,
            BrotliMode::Text => BrotliEncoderMode::BROTLI_MODE_TEXT,
            BrotliMode::Font => BrotliEncoderMode::BROTLI_MODE_FONT,
        },
        ..Default::default()
    };
    settings.size_hint = data.len();
    brotli::BrotliCompress(&mut &data[..], out, &settings)
}

impl Codec for BrotliCodec {
    fn format(&self) -> Format {
        Format::Brotli
    }

    fn self_verifying(&self) -> bool {
        false
    }

    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= 2 && stream_lgwin(data).is_some() && plausible_start(data)
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let max = ctx.max_output();
        let mut state = BrotliState::new(StandardAlloc::default(), StandardAlloc::default(), StandardAlloc::default());
        // Small to start with: this runs at nearly every offset, and grows on demand.
        let mut out = Vec::with_capacity(4096.min(max));
        let (mut in_offset, mut total_out) = (0usize, 0usize);
        loop {
            if out.len() == out.capacity() {
                grow(&mut out, max)?;
            }
            let mut available_in = data.len() - in_offset;
            let mut out_offset = out.len();
            out.resize(out.capacity(), 0);
            let mut available_out = out.len() - out_offset;
            let result = BrotliDecompressStream(
                &mut available_in,
                &mut in_offset,
                data,
                &mut available_out,
                &mut out_offset,
                &mut out,
                &mut total_out,
                &mut state,
            );
            out.truncate(out_offset);
            match result {
                BrotliResult::ResultSuccess => break,
                BrotliResult::NeedsMoreOutput => {}
                BrotliResult::NeedsMoreInput => return Err(DecodeError::Truncated),
                BrotliResult::ResultFailure => return Err(DecodeError::InvalidData),
            }
        }
        Ok(Decoded { compressed_size: in_offset, body: 0..in_offset, data: out, original_name: None })
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        let lgwin = stream_lgwin(stream)?;
        for mode in [BrotliMode::Generic, BrotliMode::Text, BrotliMode::Font] {
            for quality in [11, 9, 5, 6, 4, 7, 8, 10, 3, 2, 1, 0] {
                let p = BrotliParams { quality, lgwin, mode };
                let mut cmp = Compare { expected: stream, pos: 0 };
                if compress(&decoded.data, &p, &mut cmp).is_ok() && cmp.pos == stream.len() {
                    return Some(EncoderParams::Brotli(p));
                }
            }
        }
        None
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        let lgwin = stream_lgwin(stream).unwrap_or(22);
        EncoderParams::Brotli(BrotliParams { quality: 11, lgwin, mode: BrotliMode::Generic })
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Brotli(b) if b.quality <= 11 && (10..=24).contains(&b.lgwin) => Ok(p.clone()),
            EncoderParams::Brotli(b) => Err(format!("invalid brotli settings {b:?}")),
            other => Err(wrong_encoder("brotli", other)),
        }
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let base = *params(base);
        [BrotliMode::Generic, BrotliMode::Text]
            .into_iter()
            .map(|mode| EncoderParams::Brotli(BrotliParams { quality: 11, mode, ..base }))
            .filter(|p| *p != EncoderParams::Brotli(base))
            .collect()
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], p: &EncoderParams) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        compress(data, params(p), &mut out).expect("writing to a Vec cannot fail");
        Ok(out)
    }
}
