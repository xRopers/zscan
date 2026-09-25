# zscan — offzip/packzip redesign

## Goal
A ground-up Rust replacement for Luigi Auriemma's offzip + packzip: find compressed streams inside arbitrary binary files, extract them, and reinject edited versions. One tool, manifest-driven, with round-trip verification. A GUI comes later, built on the same core library.

## Language and key crates
- Rust (workspace)
- `flate2` with `zlib-ng` or `zlib` backend; `libz-sys` for full strategy/memLevel control
- `memmap2` (large inputs), `rayon` (parallel scanning), `clap` (CLI), `serde` + `serde_json`/`toml` (manifest)
- Later codecs: `zstd`, `lz4_flex`, `xz2`, `brotli`, `bzip2`

## Layout
```
zscan/
  crates/
    zscan-core/   # library: scanning, codecs, manifest, pack logic
    zscan-cli/    # clap CLI
    zscan-gui/    # later: egui or Tauri, depends on zscan-core only
  zscan-core/src/codecs/   # deflate.rs, zlib.rs, gzip.rs, zstd.rs ...
  tests/fixtures/          # files with known streams at known offsets
```
The core must never depend on the CLI or GUI. The GUI calls the library directly, never shells out.

## CLI
```
zscan scan    <file> [-o manifest.json]   # find streams, write manifest
zscan extract <file> -m manifest.json -d out/
zscan pack    <file> -m manifest.json [-o patched.bin] [--dry-run]
zscan info    <file>                      # summary + entropy map
```
All commands support `--json` output for scripting.

## Manifest (per stream)
- id, offset, compressed_size, decompressed_size
- format: raw deflate | zlib | gzip | (later) zstd, lz4, xz, brotli, bzip2
- detected params: level, window bits, memLevel, strategy, `exact_match: bool`
- checksum of original decompressed data (CRC32/Adler-32)
- extracted filename
- optional length-field rules: location, width, endianness, what it measures

## Requirements / improvements over offzip+packzip
1. **Codec trait** so each format is one file.
2. **False-positive filtering:** minimum decompressed size and ratio, require a valid stream end, verify zlib header check + Adler-32 / gzip CRC, optional output entropy check.
3. **Fast scanning:** cheap candidate prefilter (zlib headers `78 01/5E/9C/DA`, gzip magic, valid deflate block bits for raw), inflate only candidates, mmap input, parallel chunks with overlap, skip past found streams.
4. **Parameter matching at scan time:** recompress original data across level × strategy × memLevel; if a combo reproduces the original bytes exactly, record it so unedited streams round-trip bit-identically.
5. **Pack fitting:** reuse matched params; if the new stream is too big, try stronger settings, then use slack or relocate if length-field rules allow, else fail with a clear "N bytes over" message. Pad remaining space with zeros.
6. **Safety:** never modify input in place by default, `--dry-run` shows per-stream size deltas, post-pack verify re-scans and confirms every stream decompresses to the intended data.
7. **Later / advanced:** preflate/precomp-style reconstruction data for bit-exact recreation of streams from unknown compressors.

## Build order
1. Workspace skeleton, Codec trait, deflate/zlib/gzip scan + manifest + extract (replaces offzip). Fixture tests.
2. Pack with parameter matching, fitting, verify (replaces packzip).
3. Performance: prefilter, mmap, rayon, benchmarks on multi-GB files.
4. Extra codecs.
5. Length-field rules, then preflate-style exact reconstruction.
6. GUI (egui for speed of building, or Tauri for a richer hex/preview UI): entropy map, stream table (offset, format, sizes, ratio, detected type, exact-match flag), preview pane (hex/text/image), mark edited streams, pack view with dry-run + verify, save/load manifest as a project.

## Status
- Stages 1–4 done: `zscan scan | extract | pack | try | fields | unpack | rebuild | info`. Formats: gzip, zlib, raw deflate, zstd, xz, bzip2, lz4 frame, and brotli (not scannable; add with `zscan try`).
- Codec trait (stage 4): each format file owns probe/decode plus `find_params` (exact match), `default_params` (derived from the original header), `adapt_params`, `stronger_params` and `encode`. Params are the tagged `EncoderParams` enum (`params.rs`). Manifest v2 stores `exact_params`, and v1 manifests are migrated on load.
- Exact matching per format:
  - zstd: level search with header flags. Frames without a content size need the streaming (`e_continue` then `e_end`) path.
  - xz: the dictionary size and threaded mode are read from the block header. Big-dictionary encoders are serialised by a mutex, since they need ~10× the dictionary in RAM.
  - bzip2: determined by the header level.
  - lz4: lz4_flex only; reference-lz4 frames decode and repack but don't match.
  - brotli: quality × mode.
- Brotli is never scanned for (`Format::scannable`): blind scanning measured ~1 MiB/s and ~1 FP per 4 MiB. Streams are added at known offsets with `decode_at` / `zscan try --at <off> --format brotli -m m.json`, then extract and pack normally.
- Length fields (stage 5A, `fields.rs`): per-stream fields recording compressed size, decompressed size or offset, each as `value + adjust` at offset/width/endian.
  - Pack refuses to start unless every field holds its current value, then rewrites the fields that change.
  - `zscan fields --apply` detects candidates: integers just before a stream (any value), or anywhere for values ≥ `--min-value`. It keeps only locations claimed once; a quantity may legitimately have several fields.
  - `--relocate` moves a stream that doesn't fit to the end of the file. It requires offset + compressed-size fields and no field in the 16 bytes in front (a local header would be left behind).
  - The tests read packed archives with an independent reader (`zscan_fixtures::read_archive`).
- Stage 5B (`unpack.rs`): `zscan unpack FILE -d DIR` / `zscan rebuild DIR -o FILE`, a precomp-style bit-exact round trip.
  - The directory holds `unpack.json`, `gaps.bin`, `streams/` (contents) and `recon/`.
  - Each stream uses the first method that reproduces it, checked at unpack time: encode (exact params + original header), then preflate (`preflate-rs` 0.7.6, which needs Rust 1.89: this is why the MSRV is 1.89), then stored verbatim.
  - Rebuild checks whole-file size and CRC, and refuses edited contents (edits go through pack).
  - Results: 512 MiB dense archive → unpacked form compresses 33% smaller with zstd -19. 4 GiB unpack 4 s, rebuild 6.5 s. preflate fails on some miniz streams (prediction failure at any chain length); those fall back to stored.
- Overlap rule for unverified formats (`later_match_wins`): a later match replaces the current one only if it runs further *and* no match starting at or after the current end ends where it does. That second condition keeps back-to-back raw streams, where a misaligned decode from the first one's tail resyncs into the second.
- `find_params` prunes memLevel from the first block's symbol count (zlib flushes after exactly 2^(memLevel+6) − 1 symbols), which rejects non-zlib streams without searching. It also skips windows larger than the input. Dense-archive scans are still dominated by param matching (~35 MiB/s, mostly xz/zstd level searches); `--no-match` skips it.
- Raw deflate evidence (`Codec::evidence`) excludes leading stored blocks, so level-0 raw needs `--raw-min-compressed 0 --raw-min-ratio 0`.
- Inflate uses `miniz_oxide`'s core API directly: O(1) reset per candidate offset, one reused buffer (`DecodeCtx`). Compression uses stock zlib 1.3.2, bundled static via `libz-sys` (`deflater.rs`), because that's what most files were made with. Don't enable zlib-ng: its output differs.
- Param matching compares only the deflate *body*. Pack reuses each stream's original header bytes (gzip name/mtime/flags, zlib FLEVEL) and recomputes the trailer. Level 0 is matched as a single `compress2`-style call, because stored block sizes depend on output buffering.
- Pack copies unedited streams byte for byte. Edited streams try the matched params first, then level 9 × memLevel {9,8} × {default, filtered}, never with a window larger than the original header declares. Output is verified by decoding every stream before anything is written. Zero slack is opt-in (`--use-slack`); relocation and length fields are stage 5.
- Scan runs two passes: gzip/zlib first, then raw deflate only in the gaps. A raw match that a later match starting inside it runs past is dropped as misaligned.
- Raw deflate defaults: min 256 *compressed* bytes, output entropy ≤ 7.5, ratio ≥ 1.1. The ratio rule came from 4 GiB of mixed data, where chance stored blocks such as `00 00 00 ff ff` showed up in structured data. As a result, level-0 raw deflate is skipped unless `--raw-min-ratio 0`. See the `ScanOptions` docs.
- Stage 3 performance, on a Core Ultra 9 285K with 24 threads and a 4 GiB mixed file: scan 11 s (≈400 MiB/s), extract 2 s, pack including write and read-back verify 7.5 s. Private memory stays under 35 MiB for every command. The raw pass runs 30 MiB/s single-threaded. Stage 4 added ~1 s per 4 GiB for the extra magic probes.
  - The fixed-Huffman static-table probe (`probe_fixed_block`) gave a 10× speedup. It must only reject what inflate rejects; unit tests enforce that.
  - `DecodeCtx::take_output` copies, never moves: moving the buffer re-zeroed MBs after every garbage hit, which made scanning 60× slower.
- Parallel scan (`scan_chunked`) collects every hit per chunk without skipping, then replays skip-past and lookahead sequentially. Results must be identical to the sequential oracle in `scan.rs` tests for any chunk size. Keep `try_at` a pure function of (offset, window end).
- Pack returns patches, not a whole-file buffer. The CLI streams output to a temp file, mmaps it back, `verify_output` decodes every stream, then renames.
- Benchmarks (files live in `E:\zscan-bench`, outside the repo): `gen-big <out> <MiB> [seed]` writes a mixed file plus expected list; `zscan scan <out> -o m.json --stats`; `check-scan m.json <out>.expected.json`.
- Fixtures: `crates/zscan-fixtures` builds them deterministically; `cargo run -p zscan-fixtures --bin gen-fixtures` writes `tests/fixtures/*.bin` + `*.expected.json`.
- cargo is at `%USERPROFILE%\.cargo\bin` and is not on the Git Bash PATH; use PowerShell. `cargo test --workspace`.

## Working notes
- Prefer direct, plain explanations with concrete next steps.
- Write tests alongside each stage; fixtures should cover each format, false-positive traps, and a pack round-trip.
