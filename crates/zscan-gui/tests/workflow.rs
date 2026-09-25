//! The GUI's model driven headlessly, through the same jobs the window uses: open,
//! scan, edit, save and reopen a project, dry run, pack, and cancel.

mod common;

use std::sync::Arc;

use zscan_core::content::ContentClass;
use zscan_core::{Outcome, PackOptions, Progress, ScanOptions};
use zscan_gui::jobs::{Jobs, finish};
use zscan_gui::project::Project;
use zscan_gui::session::{self, Level, Session};

fn open_and_scan(input: &common::Input) -> (Session, Jobs) {
    let (mut s, mut jobs) = (Session::default(), Jobs::default());
    let path = input.path.clone();
    assert!(jobs.start("open", None, move || finish("Open", session::open_file(&path), Session::set_file)));
    assert!(jobs.busy());
    jobs.wait(&mut s);
    let file = s.file.as_ref().expect("file opened");
    assert_eq!(file.len(), input.data.len() as u64);
    assert!(!file.entropy.is_empty());

    let file = session::OpenFile { path: file.path.clone(), data: file.data.clone(), entropy: Vec::new() };
    let progress = Arc::new(Progress::default());
    let p = progress.clone();
    jobs.start("scan", Some(progress), move || {
        finish("Scan", session::run_scan(&file, ScanOptions::default(), &p), |s, (l, st)| s.set_scanned(l, st))
    });
    jobs.wait(&mut s);
    (s, jobs)
}

#[test]
fn scan_finds_and_classifies_every_stream() {
    let input = common::input();
    let (s, _) = open_and_scan(&input);
    let streams = s.streams();
    assert_eq!(streams.len(), 3, "{:?}", s.log);
    assert!(streams.iter().all(|st| st.exact_params.is_some()), "zlib-made streams match exactly");
    let kinds: Vec<_> = streams.iter().map(|st| s.content[&st.id]).collect();
    assert_eq!(kinds[0].class, ContentClass::Text);
    assert_eq!(kinds[1].name, "PNG");
    assert_eq!(kinds[2].class, ContentClass::Binary);
    assert!(s.dirty, "a fresh scan is unsaved work");
}

#[test]
fn edit_save_reopen_and_pack() {
    let input = common::input();
    let (mut s, mut jobs) = open_and_scan(&input);

    // Replace the text stream with a shorter edit.
    let edit_path = input.dir.path().join("edited.txt");
    let edit = input.payloads[0][..15_000].to_ascii_uppercase();
    std::fs::write(&edit_path, &edit).unwrap();
    let id = s.streams()[0].id;
    s.set_edit(id, edit_path.clone());

    // Save as a project and open it again: the same manifest and edits come back.
    let project_path = input.dir.path().join("work.zscan");
    s.to_project().unwrap().save(&project_path).unwrap();
    s.saved_project(project_path.clone());
    assert!(!s.dirty);
    let (file, loaded, edits) = session::open_project(Project::load(&project_path).unwrap()).unwrap();
    assert_eq!(loaded.mismatch, None);
    assert_eq!(&loaded.manifest, s.manifest.as_ref().unwrap());
    assert_eq!(edits.get(&id), Some(&edit_path));
    let mut reopened = Session::default();
    reopened.set_file(file);
    reopened.set_manifest(loaded, edits);
    assert_eq!(reopened.content.len(), 3);

    // Dry run: fits, nothing written.
    let data = s.file.as_ref().unwrap().data.clone();
    let manifest = s.manifest.clone().unwrap();
    let edit_bytes = session::read_edits(&s.edits).unwrap();
    let (report, _) = session::run_pack(&data, &manifest, &edit_bytes, &PackOptions::default(), None).unwrap();
    assert!(report.fits && report.written.is_none());
    assert!(matches!(report.streams[0].outcome, Outcome::Repacked { .. }));
    assert!(report.streams[1..].iter().all(|p| p.outcome == Outcome::Unchanged));

    // Pack for real through a job, then check the output holds the edit.
    let out = input.dir.path().join("input.packed.bin");
    let (d, m, o) = (data.clone(), manifest.clone(), out.clone());
    jobs.start("pack", None, move || {
        let result = session::run_pack(&d, &m, &edit_bytes, &PackOptions::default(), Some(&o)).map(|(r, _)| r);
        finish("Pack", result, Session::set_pack_report)
    });
    jobs.wait(&mut s);
    assert_eq!(s.last_pack.as_ref().unwrap().written.as_deref(), Some(out.as_path()), "{:?}", s.log);
    let packed = std::fs::read(&out).unwrap();
    assert_eq!(packed.len(), input.data.len());
    let found = zscan_core::scan(&packed, &ScanOptions { match_params: false, ..Default::default() });
    let entry = zscan_core::Manifest::new(zscan_core::SourceInfo::describe(&out, &packed), ScanOptions::default(), found);
    assert_eq!(session::stream_contents(&packed, &entry.streams[0], None).unwrap(), edit);
    assert_eq!(session::stream_contents(&packed, &entry.streams[1], None).unwrap(), input.payloads[1]);

    // Refuses to write over the input.
    assert!(session::check_not_input(&input.path, &input.path).is_err());
}

#[test]
fn manifest_for_another_file_is_flagged() {
    let input = common::input();
    let (s, _) = open_and_scan(&input);
    let mut other = input.data.clone();
    other[0] ^= 1;
    let other_path = input.dir.path().join("other.bin");
    std::fs::write(&other_path, &other).unwrap();
    let file = session::open_file(&other_path).unwrap();
    let loaded = session::prepare_manifest(&file, s.manifest.clone().unwrap());
    assert!(loaded.mismatch.as_deref().unwrap().contains("CRC-32"), "{:?}", loaded.mismatch);
}

#[test]
fn cancelled_scan_is_reported_quietly() {
    let input = common::input();
    let (mut s, mut jobs) = (Session::default(), Jobs::default());
    let file = session::open_file(&input.path).unwrap();
    let progress = Arc::new(Progress::default());
    progress.cancel();
    let p = progress.clone();
    jobs.start("scan", Some(progress), move || {
        finish("Scan", session::run_scan(&file, ScanOptions::default(), &p), |s, (l, st)| s.set_scanned(l, st))
    });
    jobs.wait(&mut s);
    assert!(s.manifest.is_none());
    let last = s.log.last().unwrap();
    assert_eq!((last.level, last.text.as_str()), (Level::Info, "Scan cancelled"));
}

#[test]
fn one_job_at_a_time() {
    let mut jobs = Jobs::default();
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    assert!(jobs.start("slow", None, move || {
        rx.recv().unwrap();
        Box::new(|s: &mut Session| s.info("done"))
    }));
    assert!(!jobs.start("second", None, || Box::new(|_: &mut Session| {})), "busy");
    tx.send(()).unwrap();
    let mut s = Session::default();
    jobs.wait(&mut s);
    assert!(!jobs.busy());
    assert_eq!(s.log.last().unwrap().text, "done");
}
