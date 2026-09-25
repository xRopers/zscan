//! Raw LZO1X, as written by liblzo's LZO1X-1 and LZO1X-999 compressors (and minilzo,
//! which is LZO1X-1). There is no header, size or checksum; a stream ends with the
//! marker `11 00 00`. Cargo feature `lzo`.
//!
//! The end of a stream is reliable, but its start is not: a stream opens with a run of
//! literals, and a byte before it can often be read as a longer run that ends in the same
//! place (or a byte inside the run as a shorter one), giving a stream with junk in front
//! or bytes missing that decodes just as well. In the `lzo` test fixture, 3 of 5 streams
//! were first found up to 200 bytes early. So a scan only accepts LZO where a field just
//! before the stream holds its compressed size ([`Codec::scan_needs_size_field`]), the
//! usual archive layout; other streams are added at known offsets. That also keeps
//! scanning fast: garbage decodes as LZO for kilobytes (a match only has to point inside
//! the output so far), so decoding at every offset ran at 0.3 MiB/s, while checking for
//! the end marker where a size field says the stream ends rejects almost every offset.
//!
//! Decoding is done here rather than by a crate, because the scanner must find the end
//! of a stream of unknown size inside a larger buffer, which the crates' decoders don't
//! report. Encoding uses the `lzo1x` crate, a port of liblzo's compressors, so streams
//! made by liblzo can be matched exactly. That crate, like liblzo, is GPL-2.0.
//!
//! Checked against liblzo 2.10 built from source, the crate's output is identical for
//! LZO1X-1 (minilzo's `lzo1x_1`), `lzo1x_1_11`, `lzo1x_1_12` and LZO1X-999 levels 3 and
//! 5-9 (including the default, 8), and differs on some inputs for `lzo1x_1_15` and 999
//! levels 1, 2 and 4. Streams that went through `lzo1x_optimize` (lzop -7 to -9) don't
//! match: the crate's port of it panics or corrupts streams, so it isn't used. Pack still
//! re-encodes such streams; only the bit-exact match is lost.
//!
//! Instruction set (liblzo's `lzo1x_d.ch`; the Linux kernel's `lzo.rst` describes it too).
//! The state is how many literals the previous instruction copied:
//! - `0..=15` with state 0: a run of 4+ literals (0 extends the length).
//! - `0..=15` with state 1-3: a 2-byte match up to 1 KiB back.
//! - `0..=15` with state 4 (after a literal run): a 3-byte match 2-3 KiB back.
//! - `16..=31`: a match 16-48 KiB back, or with distance 0 the end marker.
//! - `32..=63`: a match up to 16 KiB back.
//! - `64..=255`: a 3-8 byte match up to 2 KiB back.
//!
//! Every match's last two bits give 0-3 literals that follow it.

use super::util::wrong_encoder;
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format, SizeHint};
use crate::params::{EncoderParams, LzoParams};

pub struct LzoCodec;

/// A decoded stream.
struct Lzo {
    data: Vec<u8>,
    /// Bytes of input up to and including the end marker.
    consumed: usize,
    /// Of those, bytes copied verbatim as literals.
    literals: usize,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    max: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> Result<usize, DecodeError> {
        let b = *self.data.get(self.pos).ok_or(DecodeError::Truncated)?;
        self.pos += 1;
        Ok(usize::from(b))
    }

    fn le16(&mut self) -> Result<usize, DecodeError> {
        Ok(self.byte()? | self.byte()? << 8)
    }

    /// A length that didn't fit its instruction: each zero byte adds 255, then the first
    /// non-zero byte ends it.
    fn extended(&mut self, base: usize) -> Result<usize, DecodeError> {
        let mut n = base;
        loop {
            match self.byte()? {
                0 if n > self.max => return Err(DecodeError::TooLarge(self.max)),
                0 => n += 255,
                b => return Ok(n + b),
            }
        }
    }
}

fn decompress(data: &[u8], max: usize) -> Result<Lzo, DecodeError> {
    let mut r = Reader { data, pos: 0, max };
    // Small to start with: a scan tries this at nearly every offset. It grows on demand.
    let mut out: Vec<u8> = Vec::with_capacity(4096.min(max));
    let mut literals = 0;
    let mut copy_literals = |r: &mut Reader, out: &mut Vec<u8>, n: usize| {
        let bytes = r.data.get(r.pos..r.pos + n).ok_or(DecodeError::Truncated)?;
        if out.len() + n > max {
            return Err(DecodeError::TooLarge(max));
        }
        out.extend_from_slice(bytes);
        r.pos += n;
        literals += n;
        Ok(())
    };

    let mut state = 0;
    if let Some(&first) = data.first()
        && first > 17
    {
        r.pos = 1;
        let n = usize::from(first) - 17;
        copy_literals(&mut r, &mut out, n)?;
        state = n.min(4);
    }
    loop {
        let t = r.byte()?;
        let (distance, len, trailing);
        if t >= 64 {
            distance = 1 + ((t >> 2) & 7) + (r.byte()? << 3);
            len = (t >> 5) + 1;
            trailing = t & 3;
        } else if t >= 32 {
            len = match t & 31 {
                0 => r.extended(31)?,
                n => n,
            } + 2;
            let d = r.le16()?;
            distance = 1 + (d >> 2);
            trailing = d & 3;
        } else if t >= 16 {
            let n = match t & 7 {
                0 => r.extended(7)?,
                n => n,
            };
            let d = r.le16()?;
            let far = ((t & 8) << 11) + (d >> 2);
            if far == 0 {
                // Distance 0 is the end marker, which encoders always write as 11 00 00.
                if t != 0x11 || d != 0 {
                    return Err(DecodeError::InvalidData);
                }
                break;
            }
            distance = far + 0x4000;
            len = n + 2;
            trailing = d & 3;
        } else if state == 0 {
            let n = match t {
                0 => r.extended(15)?,
                n => n,
            } + 3;
            copy_literals(&mut r, &mut out, n)?;
            state = 4;
            continue;
        } else {
            let b = r.byte()?;
            (distance, len) = if state == 4 { (1 + 0x800 + (t >> 2) + (b << 2), 3) } else { (1 + (t >> 2) + (b << 2), 2) };
            trailing = t & 3;
        }

        if distance > out.len() {
            return Err(DecodeError::InvalidData);
        }
        if out.len() + len > max {
            return Err(DecodeError::TooLarge(max));
        }
        let start = out.len() - distance;
        if distance >= len {
            out.extend_from_within(start..start + len);
        } else {
            for i in 0..len {
                out.push(out[start + i]);
            }
        }
        copy_literals(&mut r, &mut out, trailing)?;
        state = trailing;
    }
    Ok(Lzo { data: out, consumed: r.pos, literals })
}

fn params(p: &EncoderParams) -> &LzoParams {
    match p {
        EncoderParams::Lzo(p) => p,
        other => panic!("{}", wrong_encoder("lzo", other)),
    }
}

fn compress(data: &[u8], p: &LzoParams) -> Vec<u8> {
    lzo1x::compress(data, lzo1x::CompressLevel::new(p.level))
}

/// Levels to try when matching, most common first: minilzo's LZO1X-1, then
/// `lzo1x_999_compress` (level 8), then the rest.
const MATCH_ORDER: [u8; 13] = [3, 12, 1, 2, 13, 11, 10, 9, 7, 4, 8, 6, 5];

impl Codec for LzoCodec {
    fn format(&self) -> Format {
        Format::Lzo
    }

    fn self_verifying(&self) -> bool {
        false
    }

    fn scan_needs_size_field(&self) -> bool {
        true
    }

    /// Any first byte can start a stream, and the shortest one is the bare end marker.
    fn probe(&self, data: &[u8]) -> bool {
        data.len() >= 3
    }

    /// With the compressed size known, the stream must end with the end marker right there,
    /// which is checked before decoding anything.
    fn decode_with_hint(&self, data: &[u8], hint: SizeHint, ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        match hint.compressed {
            Some(n) if n > data.len() => Err(DecodeError::Truncated),
            Some(n) if n < 3 || data[n - 3..n] != [0x11, 0, 0] => Err(DecodeError::InvalidData),
            Some(n) => self.decode(&data[..n], ctx),
            None => self.decode(data, ctx),
        }
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        let lzo = decompress(data, ctx.max_output())?;
        Ok(Decoded { compressed_size: lzo.consumed, body: 0..lzo.consumed, data: lzo.data, original_name: None })
    }

    /// Literals are copied verbatim, so like stored deflate blocks they prove nothing.
    fn evidence(&self, stream: &[u8]) -> usize {
        decompress(stream, usize::MAX).map_or(0, |lzo| lzo.consumed - lzo.literals)
    }

    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        MATCH_ORDER
            .into_iter()
            .map(|level| LzoParams { level })
            .find(|p| compress(&decoded.data, p) == stream)
            .map(EncoderParams::Lzo)
    }

    fn default_params(&self, _stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        EncoderParams::Lzo(LzoParams { level: 3 })
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Lzo(l) if (1..=13).contains(&l.level) => Ok(p.clone()),
            EncoderParams::Lzo(l) => Err(format!("lzo level {} is not 1-13", l.level)),
            other => Err(wrong_encoder("lzo", other)),
        }
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let strongest = EncoderParams::Lzo(LzoParams { level: 13 });
        if params(base).level == 13 { vec![] } else { vec![strongest] }
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], p: &EncoderParams) -> Result<Vec<u8>, String> {
        Ok(compress(data, params(p)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Vec<u8>> {
        let mut rng = zscan_fixtures::Rng::new(9);
        let mut v = vec![Vec::new(), b"a".to_vec(), b"abc".to_vec(), vec![0; 5], vec![7; 100_000]];
        for len in [1, 2, 3, 4, 5, 17, 18, 238, 239, 300, 5000, 70_000] {
            v.push(zscan_fixtures::text(&mut rng, len));
            v.push(rng.bytes(len));
        }
        v.push(zscan_fixtures::records(&mut rng, 200_000));
        // Long runs and far matches: exercises extended lengths and 16-48 KiB distances.
        let block = zscan_fixtures::text(&mut rng, 20_000);
        v.push([block.as_slice(), &rng.bytes(30_000), &block, &vec![b'x'; 1000], &block].concat());
        v
    }

    #[test]
    fn decodes_every_level_and_finds_the_end() {
        let mut ctx = DecodeCtx::new(1 << 24);
        for data in samples() {
            for level in 1..=13 {
                let p = LzoParams { level };
                let stream = compress(&data, &p);
                let mut padded = stream.clone();
                padded.extend_from_slice(&[0x11, 0, 0, 0xff, 1, 2, 3]);
                let d = LzoCodec.decode(&padded, &mut ctx).unwrap_or_else(|e| panic!("{p:?} len {}: {e}", data.len()));
                assert_eq!(d.compressed_size, stream.len(), "{p:?} len {}", data.len());
                assert!(d.data == data, "{p:?} len {}", data.len());
                // The crate's own decoder agrees.
                let mut check = vec![0; data.len()];
                lzo1x::decompress(&stream, &mut check).unwrap();
                assert!(check == data);
            }
        }
    }

    #[test]
    fn finds_params_that_reproduce_the_stream() {
        let mut ctx = DecodeCtx::new(1 << 24);
        let mut rng = zscan_fixtures::Rng::new(3);
        let data = zscan_fixtures::text(&mut rng, 30_000);
        for p in [LzoParams { level: 3 }, LzoParams { level: 12 }, LzoParams { level: 1 }] {
            let stream = compress(&data, &p);
            let d = LzoCodec.decode(&stream, &mut ctx).unwrap();
            let found = LzoCodec.find_params(&stream, &d).expect("a match");
            assert_eq!(LzoCodec.encode(&stream, &d, &data, &found).unwrap(), stream, "{p:?} matched as {found}");
        }
    }

    #[test]
    fn rejects_bad_streams() {
        let mut ctx = DecodeCtx::new(1 << 20);
        let stream = compress(b"hello hello hello hello hello", &LzoParams { level: 3 });
        assert_eq!(LzoCodec.decode(&stream[..stream.len() - 1], &mut ctx).unwrap_err(), DecodeError::Truncated);
        // One literal, then a match reaching 8 bytes back.
        assert_eq!(LzoCodec.decode(&[0x12, b'a', 0x5c, 0x00, 0x11, 0, 0], &mut ctx).unwrap_err(), DecodeError::InvalidData);
        // A distance-0 far match that isn't exactly 11 00 00.
        assert_eq!(LzoCodec.decode(&[0x11, 0x01, 0x00], &mut ctx).unwrap_err(), DecodeError::InvalidData);
        assert_eq!(LzoCodec.decode(&[0x11, 0, 0], &mut ctx).unwrap().data, b"");
        let mut small = DecodeCtx::new(10);
        assert_eq!(LzoCodec.decode(&stream, &mut small).unwrap_err(), DecodeError::TooLarge(10));
    }

    #[test]
    fn evidence_leaves_out_literals() {
        let mut rng = zscan_fixtures::Rng::new(4);
        let noise = rng.bytes(2000);
        let stream = compress(&noise, &LzoParams { level: 3 });
        assert!(LzoCodec.evidence(&stream) < 16, "incompressible data is all literals");
        let text = zscan_fixtures::text(&mut rng, 20_000);
        let stream = compress(&text, &LzoParams { level: 3 });
        assert!(LzoCodec.evidence(&stream) > stream.len() / 3);
    }
}
