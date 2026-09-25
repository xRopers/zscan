//! Writes every fixture to a directory (default `tests/fixtures`) as `<name>.bin`
//! plus `<name>.expected.json` listing the streams the scanner should report.

use std::fs;
use std::path::PathBuf;

use serde_json::json;

fn main() -> std::io::Result<()> {
    let dir = std::env::args().nth(1).map_or_else(|| PathBuf::from("tests/fixtures"), PathBuf::from);
    fs::create_dir_all(&dir)?;
    for fixture in zscan_fixtures::all() {
        let streams: Vec<_> = fixture
            .expected
            .iter()
            .map(|e| {
                json!({
                    "offset": e.offset,
                    "format": e.kind.as_str(),
                    "compressed_size": e.compressed_size,
                    "decompressed_size": e.payload.len(),
                    "crc32": format!("{:08x}", crc32fast::hash(&e.payload)),
                    "original_name": e.name,
                    "zlib_made": e.zlib_made,
                })
            })
            .collect();
        let expected = json!({ "description": fixture.description, "size": fixture.data.len(), "streams": streams });
        fs::write(dir.join(format!("{}.bin", fixture.name)), &fixture.data)?;
        fs::write(
            dir.join(format!("{}.expected.json", fixture.name)),
            serde_json::to_string_pretty(&expected).unwrap() + "\n",
        )?;
        println!("{:<12} {:>8} bytes, {} streams", fixture.name, fixture.data.len(), fixture.expected.len());
    }
    Ok(())
}
