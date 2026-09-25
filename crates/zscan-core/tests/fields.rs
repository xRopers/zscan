//! Length fields: detection, and pack keeping them right. Every packed archive is read
//! back through its own directory by an independent reader (`read_archive`).

use std::collections::BTreeMap;
use std::path::Path;

use zscan_core::fields::measure;
use zscan_core::{
    DetectOptions, Endian, Error, LengthField, Manifest, Measures, Outcome, PackOptions, ScanOptions, SourceInfo,
    apply_unambiguous, check_fields, detect_fields, pack, scan,
};
use zscan_fixtures::{Fixture, Rng, archive, read_archive};

fn manifest_for(f: &Fixture) -> Manifest {
    let opts = ScanOptions::default();
    Manifest::new(SourceInfo::describe(Path::new("a.zarc"), &f.data), opts.clone(), scan(&f.data, &opts))
}

fn field(offset: u64, endian: Endian, measures: Measures) -> LengthField {
    LengthField { offset, width: 4, endian, measures, adjust: 0 }
}

/// Every field the archive layout defines, per stream.
fn layout_fields(f: &Fixture, prefixed: bool) -> Vec<Vec<LengthField>> {
    (0..f.expected.len())
        .map(|i| {
            let table = 12 + 16 * i as u64;
            let mut fields = vec![
                field(table, Endian::Little, Measures::Offset),
                field(table + 4, Endian::Little, Measures::Compressed),
                field(table + 8, Endian::Little, Measures::Decompressed),
            ];
            if prefixed {
                fields.push(field(f.expected[i].offset as u64 - 4, Endian::Big, Measures::Compressed));
            }
            fields
        })
        .collect()
}

fn with_layout_fields(f: &Fixture, prefixed: bool) -> Manifest {
    let mut m = manifest_for(f);
    for (entry, fields) in m.streams.iter_mut().zip(layout_fields(f, prefixed)) {
        entry.length_fields = fields;
    }
    check_fields(&f.data, &m).unwrap();
    m
}

fn payloads(f: &Fixture) -> Vec<Vec<u8>> {
    f.expected.iter().map(|e| e.payload.clone()).collect()
}

fn incompressible(len: usize) -> Vec<u8> {
    Rng::new(9).bytes(len)
}

#[test]
fn the_reader_accepts_both_fixtures() {
    for prefixed in [true, false] {
        let f = archive(prefixed);
        assert_eq!(read_archive(&f.data).unwrap(), payloads(&f));
        assert_eq!(manifest_for(&f).streams.len(), 3);
    }
}

#[test]
fn detection_finds_every_field_and_nothing_else() {
    let f = archive(true);
    let m = manifest_for(&f);
    let opts = DetectOptions { window: 8, min_global_value: 2048 };
    let found = detect_fields(&f.data, &m, &opts);
    // Directory fields are found only when their value is large enough to search for.
    let mut expected = Vec::new();
    for (entry, fields) in m.streams.iter().zip(layout_fields(&f, true)) {
        for fl in fields {
            let near = fl.offset + 4 == entry.offset;
            if near || measure(entry, fl.measures) >= opts.min_global_value {
                expected.push((entry.id, fl));
            }
        }
    }
    let mut got: Vec<_> = found.iter().map(|c| (c.stream_id, c.field)).collect();
    got.sort_by_key(|(id, fl)| (*id, fl.offset));
    expected.sort_by_key(|(id, fl)| (*id, fl.offset));
    assert_eq!(got, expected);

    let mut applied = m.clone();
    let added = apply_unambiguous(&mut applied, &found);
    assert_eq!(added.len(), expected.len());
    check_fields(&f.data, &applied).unwrap();
}

#[test]
fn pack_updates_fields_in_place() {
    let f = archive(true);
    let m = with_layout_fields(&f, true);
    let mut want = payloads(&f);
    want[0] = want[0][..40_000].to_vec();
    want[2] = b"a much shorter third entry".repeat(10);
    let edits = BTreeMap::from([(0, want[0].clone()), (2, want[2].clone())]);
    let result = pack(&f.data, &m, &edits, &PackOptions::default()).unwrap();
    // Each edited stream: directory csize and dsize, plus its size prefix.
    assert_eq!(result.field_updates.len(), 6);
    let out = result.apply(&f.data).unwrap();
    assert_eq!(out.len(), f.data.len());
    assert_eq!(read_archive(&out).unwrap(), want);
    let packed = result.verify_output(&out).unwrap();
    check_fields(&out, &packed).unwrap();
}

#[test]
fn growth_relocates_when_allowed() {
    let f = archive(false);
    let m = with_layout_fields(&f, false);
    let mut want = payloads(&f);
    want[1] = incompressible(30_000);
    let edits = BTreeMap::from([(1, want[1].clone())]);

    let strict = pack(&f.data, &m, &edits, &PackOptions::default()).unwrap();
    assert!(matches!(strict.streams[1].outcome, Outcome::TooLarge { relocatable: true, .. }));

    let opts = PackOptions { relocate: true, align: 16, ..Default::default() };
    let result = pack(&f.data, &m, &edits, &opts).unwrap();
    let Outcome::Repacked { relocated_to: Some(to), new_size, .. } = result.streams[1].outcome else { panic!() };
    assert!(to >= f.data.len() as u64 && to % 16 == 0);
    assert_eq!(result.output_len(), to + new_size);
    let out = result.apply(&f.data).unwrap();
    assert_eq!(read_archive(&out).unwrap(), want);
    let old = &f.expected[1];
    assert!(out[old.offset..old.offset + old.compressed_size].iter().all(|&b| b == 0), "old slot zeroed");
    let packed = result.verify_output(&out).unwrap();

    // Packing the same edit into the packed file changes nothing.
    let again = pack(&out, &packed, &edits, &opts).unwrap();
    assert!(again.apply(&out).unwrap() == out);
}

#[test]
fn streams_with_a_local_header_or_missing_fields_are_not_relocated() {
    let edits = BTreeMap::from([(1u32, incompressible(30_000))]);
    let opts = PackOptions { relocate: true, ..Default::default() };

    let f = archive(true);
    let r = pack(&f.data, &with_layout_fields(&f, true), &edits, &opts).unwrap();
    assert!(matches!(r.streams[1].outcome, Outcome::TooLarge { relocatable: false, .. }), "local header");

    let f = archive(false);
    let mut m = with_layout_fields(&f, false);
    m.streams[1].length_fields.retain(|fl| fl.measures != Measures::Compressed);
    let r = pack(&f.data, &m, &edits, &opts).unwrap();
    assert!(matches!(r.streams[1].outcome, Outcome::TooLarge { relocatable: false, .. }), "no size field");
}

#[test]
fn bad_rules_are_rejected_before_anything_is_planned() {
    let f = archive(false);
    let good = with_layout_fields(&f, false);
    let reject = |m: &Manifest| {
        let r = pack(&f.data, m, &BTreeMap::new(), &PackOptions::default());
        assert!(matches!(r, Err(Error::InvalidManifest(_))), "{r:?}");
    };
    let mut m = good.clone();
    m.streams[0].length_fields[1].adjust = 1; // holds the wrong value
    reject(&m);
    let mut m = good.clone();
    m.streams[0].length_fields[0].offset = m.streams[1].offset + 10; // inside a stream
    reject(&m);
    let mut m = good.clone();
    m.streams[0].length_fields[2].width = 3;
    reject(&m);
    let mut m = good.clone();
    let dup = m.streams[0].length_fields[0];
    m.streams[1].length_fields.push(LengthField { offset: dup.offset + 2, ..dup }); // overlaps
    reject(&m);
}

#[test]
fn a_value_that_no_longer_fits_its_field_fails_cleanly() {
    let f = archive(false);
    let mut m = with_layout_fields(&f, false);
    // Treat the directory's csize for stream 1 as a u16 (its low half, while small).
    m.streams[1].length_fields[1].width = 2;
    check_fields(&f.data, &m).unwrap();
    let edits = BTreeMap::from([(1, incompressible(100_000))]);
    let opts = PackOptions { relocate: true, ..Default::default() };
    let r = pack(&f.data, &m, &edits, &opts);
    assert!(matches!(r, Err(Error::Pack(ref msg)) if msg.contains("doesn't fit")), "{r:?}");
}

#[test]
fn verify_catches_a_damaged_field() {
    let f = archive(false);
    let m = with_layout_fields(&f, false);
    let edits = BTreeMap::from([(0, payloads(&f)[0][..1000].to_vec())]);
    let result = pack(&f.data, &m, &edits, &PackOptions::default()).unwrap();
    let mut out = result.apply(&f.data).unwrap();
    result.verify_output(&out).unwrap();
    out[12 + 8] ^= 1; // stream 0's directory dsize
    assert!(matches!(result.verify_output(&out), Err(Error::Verify { .. })));
}
