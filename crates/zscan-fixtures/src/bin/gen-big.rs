//! Writes a large benchmark input: `gen-big <out.bin> <size MiB> [seed]`.
//!
//! Each 1 MiB segment is one of: random bytes, zeros, uncompressed records,
//! uncompressed text, or random filler around one compressed stream (gzip, zlib, raw
//! deflate, zstd, xz, bzip2 or lz4; 1 KiB to 2 MiB payload). Streams can run past their
//! segment.
//! Also writes `<out.bin>.expected.json` listing every stream.

use std::fs::File;
use std::io::{BufWriter, Write};

use serde_json::json;
use zscan_fixtures::{
    Rng, bzip2, deflate, gzip, lz4_frame, records, text, xz_easy, xz_tool_like, zlib, zstd_frame,
};

const SEGMENT: usize = 1 << 20;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: gen-big <out.bin> <size MiB> [seed]");
        std::process::exit(2);
    }
    let path = &args[1];
    let target = args[2].parse::<usize>().expect("size in MiB") * SEGMENT;
    let seed = args.get(3).map_or(1, |s| s.parse().expect("seed"));

    let mut rng = Rng::new(seed);
    let mut out = BufWriter::with_capacity(1 << 22, File::create(path)?);
    let mut written = 0usize;
    let mut streams = Vec::new();

    while written < target {
        let segment = match rng.below(100) {
            0..40 => rng.bytes(SEGMENT),
            40..50 => vec![0; SEGMENT],
            50..60 => records(&mut rng, SEGMENT),
            60..70 => text(&mut rng, SEGMENT),
            _ => {
                let payload_len = 1024 << rng.below(12); // 1 KiB .. 2 MiB
                let payload = if rng.below(2) == 0 { text(&mut rng, payload_len) } else { records(&mut rng, payload_len) };
                let pick = rng.below(3) as usize;
                let (format, encoded) = match rng.below(7) {
                    0 => ("zlib", zlib(&payload, [1, 6, 9][pick])),
                    1 => ("gzip", gzip(&payload, None)),
                    2 => ("deflate", deflate(&payload, [1, 6, 9][pick])),
                    3 => ("zstd", zstd_frame(&payload, [1, 3, 19][pick], pick == 2)),
                    4 => ("xz", if pick == 0 { xz_easy(&payload, 6) } else { xz_tool_like(&payload, 6, pick == 2) }),
                    5 => ("bzip2", bzip2(&payload, [1, 9, 9][pick])),
                    _ => ("lz4", lz4_frame(&payload, pick == 2)),
                };
                let before = rng.below(SEGMENT as u64 / 2) as usize;
                let mut seg = rng.bytes(before);
                streams.push(json!({
                    "offset": written + before,
                    "format": format,
                    "compressed_size": encoded.len(),
                    "decompressed_size": payload.len(),
                    "crc32": format!("{:08x}", crc32fast::hash(&payload)),
                }));
                seg.extend(encoded);
                let after = SEGMENT.saturating_sub(seg.len());
                seg.extend(rng.bytes(after));
                seg
            }
        };
        out.write_all(&segment)?;
        written += segment.len();
    }
    out.flush()?;
    let expected = json!({ "size": written, "streams": streams });
    std::fs::write(format!("{path}.expected.json"), serde_json::to_string_pretty(&expected).unwrap())?;
    eprintln!("{path}: {written} bytes, {} streams", streams.len());
    Ok(())
}
