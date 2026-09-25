//! The window itself, driven with egui_kittest (no GPU): clicks go through the real
//! widgets and are checked through the accessibility tree.

mod common;

use std::time::{Duration, Instant};

use egui_kittest::Harness;
use egui_kittest::kittest::{NodeT, Queryable};
use zscan_gui::App;
use zscan_gui::app::{Action, Tab};

fn harness() -> Harness<'static, App> {
    Harness::builder().with_size([1400.0, 900.0]).build_ui_state(|ui, app: &mut App| app.show(ui), App::new())
}

/// Finish the running job (if any) and let the window catch up.
fn settle(h: &mut Harness<'static, App>) {
    let app = h.state_mut();
    app.jobs.wait(&mut app.session);
    h.run_steps(3);
}

/// Step until `label` appears (previews load on their own thread).
fn wait_for(h: &mut Harness<'static, App>, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while h.query_by_label_contains(label).is_none() {
        assert!(Instant::now() < deadline, "'{label}' never appeared");
        std::thread::sleep(Duration::from_millis(10));
        h.step();
    }
}

fn open_and_scan(h: &mut Harness<'static, App>, input: &common::Input) {
    h.state_mut().request(Action::OpenFile(input.path.clone()));
    settle(h);
    h.get_by_label("Not scanned yet.");
    h.get_by_label("Scan the file").click();
    h.run_steps(2);
    settle(h);
}

#[test]
fn welcome_screen() {
    let mut h = harness();
    h.run_steps(2);
    h.get_by_label("Open a file…");
    h.get_by_label("Open a project…");
}

#[test]
fn scan_select_and_preview() {
    let input = common::input();
    let mut h = harness();
    open_and_scan(&mut h, &input);
    assert_eq!(h.state().session.streams().len(), 3);
    h.get_by_label("3 streams, 3 exact, 0 edited");

    // Click the PNG row: its details and image preview appear.
    h.get_by_label("PNG").click();
    h.run_steps(2);
    let id = h.state().selected.expect("a stream is selected");
    h.get_by_label(&format!("Stream {id}"));
    h.get_by_label("Image").click();
    h.run_steps(1);
    assert_eq!(h.state().tab, Tab::Image);
    wait_for(&mut h, "6×4");

    // The text stream shows as text.
    h.get_by_label("ASCII text").click();
    h.get_by_label("Text").click();
    h.run_steps(1);
    let first_line = String::from_utf8_lossy(&input.payloads[0]).lines().next().unwrap().to_string();
    wait_for(&mut h, &first_line[..20]);

    // The raw compressed bytes start with the zlib header.
    h.get_by_label("Raw bytes").click();
    h.run_steps(2);
    let offset = h.state().session.streams()[0].offset;
    wait_for(&mut h, &format!("{offset:08x}  78 9c"));
}

#[test]
fn edit_and_dry_run_from_the_pack_window() {
    let input = common::input();
    let mut h = harness();
    open_and_scan(&mut h, &input);

    let edit = input.dir.path().join("new.txt");
    std::fs::write(&edit, b"short replacement text, well within the original stream's slot").unwrap();
    let id = h.state().session.streams()[0].id;
    h.state_mut().session.set_edit(id, edit);
    h.run_steps(2);
    h.get_by_label("edited");

    h.get_by_label("Pack (1 edited)…").click();
    h.run_steps(2);
    h.get_by_label("Dry run").click();
    h.run_steps(1);
    settle(&mut h);
    h.get_by_label_contains("Dry run: every edited stream fits");
    h.get_by_label("repacked");
}

#[test]
fn unsaved_work_asks_before_closing() {
    let input = common::input();
    let mut h = harness();
    open_and_scan(&mut h, &input);
    assert!(h.state().session.dirty);

    h.state_mut().request(Action::Close);
    h.run_steps(2);
    h.get_by_label("Unsaved changes");
    h.get_by_label("Cancel").click();
    h.run_steps(2);
    assert!(h.query_by_label("Unsaved changes").is_none());
    assert!(h.state().session.file.is_some(), "cancel keeps the file open");

    h.state_mut().request(Action::Close);
    h.run_steps(2);
    h.get_by_label("Discard").click();
    h.run_steps(2);
    assert!(h.state().session.file.is_none());
    h.get_by_label("Open a file…");
}

#[test]
fn plugins_window_sets_the_oodle_library() {
    let mut h = harness();
    h.state_mut().show_plugins = true;
    h.run_steps(2);
    h.get_by_label("LZO");
    if cfg!(feature = "lzo") {
        h.get_by_label("Built in (raw LZO1X).");
    } else {
        h.get_by_label_contains("--features lzo");
    }
    if !cfg!(feature = "oodle") {
        h.get_by_label_contains("--features oodle");
        return;
    }
    // A library that doesn't exist: the window says so, and so does the log.
    h.state_mut().oodle_dll_text = "no/such/oo2core_9_win64.dll".into();
    h.run_steps(1);
    h.get_by_label("Apply").click();
    h.run_steps(2);
    assert!(h.query_all_by_label_contains("not found").next().is_some(), "status shows the error");
    assert!(h.state().session.log.last().unwrap().text.contains("not found"));
    // Scanning for Oodle can't be switched on until the library loads.
    h.state_mut().show_scan = true;
    h.run_steps(2);
    assert!(h.get_by_label("oodle").accesskit_node().is_disabled());

    // With a real library (ZSCAN_OODLE_DLL), it loads and Oodle scanning can be switched on.
    if let Some(dll) = std::env::var_os("ZSCAN_OODLE_DLL") {
        h.state_mut().oodle_dll_text = dll.to_string_lossy().into_owned();
        h.get_by_label("Apply").click();
        h.run_steps(2);
        h.get_by_label("Oodle is ready.");
        assert!(!h.get_by_label("oodle").accesskit_node().is_disabled());
    }
    zscan_core::set_oodle_dll(None);
}
