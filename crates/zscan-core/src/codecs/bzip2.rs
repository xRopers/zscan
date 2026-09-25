//! bzip2: `BZh` + a block-size digit, then blocks that each start with the 48-bit magic
//! 0x314159265359 and carry a CRC-32 of their data, ending with 0x177245385090 and a
//! combined CRC. The end is bit-aligned and padded to a byte.

use bzip2::{Action, Compress, Compression, Decompress, Status};

use super::util::{grow, output_buffer, wrong_encoder};
use crate::codec::{Codec, DecodeCtx, DecodeError, Decoded, Format};
use crate::params::{Bzip2Params, EncoderParams};

pub struct Bzip2Codec;

const BLOCK_MAGIC: [u8; 6] = [0x31, 0x41, 0x59, 0x26, 0x53, 0x59];
const END_MAGIC: [u8; 6] = [0x17, 0x72, 0x45, 0x38, 0x50, 0x90];

/// The block-size level (1-9) if `data` starts with a bzip2 header followed by a block
/// or end-of-stream magic.
fn header_level(data: &[u8]) -> Option<u32> {
    let level = *data.get(3)?;
    let magic = data.get(4..10)?;
    (data.starts_with(b"BZh") && (b'1'..=b'9').contains(&level) && (magic == BLOCK_MAGIC || magic == END_MAGIC))
        .then(|| u32::from(level - b'0'))
}

fn params(p: &EncoderParams) -> &Bzip2Params {
    match p {
        EncoderParams::Bzip2(p) => p,
        other => panic!("{}", wrong_encoder("bzip2", other)),
    }
}

impl Codec for Bzip2Codec {
    fn format(&self) -> Format {
        Format::Bzip2
    }

    fn self_verifying(&self) -> bool {
        true
    }

    fn probe(&self, data: &[u8]) -> bool {
        header_level(data).is_some()
    }

    fn decode(&self, data: &[u8], ctx: &mut DecodeCtx) -> Result<Decoded, DecodeError> {
        header_level(data).ok_or(DecodeError::BadHeader)?;
        let max = ctx.max_output();
        let mut d = Decompress::new(false);
        let mut out = output_buffer(None, max);
        loop {
            if out.len() == out.capacity() {
                grow(&mut out, max)?;
            }
            let (in_before, out_before) = (d.total_in(), out.len());
            let status = d.decompress_vec(&data[d.total_in() as usize..], &mut out).map_err(|_| DecodeError::InvalidData)?;
            if status == Status::StreamEnd {
                break;
            }
            let stalled = d.total_in() == in_before && out.len() == out_before;
            if stalled || (d.total_in() as usize == data.len() && out.len() < out.capacity()) {
                return Err(DecodeError::Truncated);
            }
        }
        let size = d.total_in() as usize;
        Ok(Decoded { compressed_size: size, body: 0..size, data: out, original_name: None })
    }

    /// libbzip2's output depends only on the block size, which the header states.
    fn find_params(&self, stream: &[u8], decoded: &Decoded) -> Option<EncoderParams> {
        let p = self.default_params(stream, decoded);
        (self.encode(stream, decoded, &decoded.data, &p) == stream).then_some(p)
    }

    fn default_params(&self, stream: &[u8], _decoded: &Decoded) -> EncoderParams {
        EncoderParams::Bzip2(Bzip2Params { level: header_level(stream).unwrap_or(9) })
    }

    fn adapt_params(&self, _stream: &[u8], _decoded: &Decoded, p: &EncoderParams) -> Result<EncoderParams, String> {
        match p {
            EncoderParams::Bzip2(b) if (1..=9).contains(&b.level) => Ok(p.clone()),
            EncoderParams::Bzip2(b) => Err(format!("bzip2 level {} is not 1-9", b.level)),
            other => Err(wrong_encoder("bzip2", other)),
        }
    }

    fn stronger_params(&self, base: &EncoderParams) -> Vec<EncoderParams> {
        let strongest = EncoderParams::Bzip2(Bzip2Params { level: 9 });
        if *base == strongest { vec![] } else { vec![strongest] }
    }

    fn encode(&self, _stream: &[u8], _decoded: &Decoded, data: &[u8], p: &EncoderParams) -> Vec<u8> {
        let mut c = Compress::new(Compression::new(params(p).level), 30);
        let mut out = Vec::with_capacity(data.len() / 2 + 64);
        loop {
            if out.len() == out.capacity() {
                out.reserve(out.capacity().max(4096));
            }
            let status = c.compress_vec(&data[c.total_in() as usize..], &mut out, Action::Finish).expect("bzip2 compress");
            if status == Status::StreamEnd {
                return out;
            }
        }
    }
}
