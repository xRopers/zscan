//! The zscan window: entropy map, stream table, details and preview, and the scan,
//! add-stream and pack windows. State lives in [`Session`]; this file only draws it
//! and turns clicks into jobs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use egui::{Align, Color32, Key, Layout, Modifiers, RichText, Sense, Ui, ViewportCommand};
use egui_extras::{Column, TableBuilder};
use zscan_core::codec::codec_for;
use zscan_core::content::sniff;
use zscan_core::scan::{DEFAULT_MAX_OUTPUT, DEFAULT_RAW_MAX_ENTROPY};
use zscan_core::{
    DecodeCtx, ExtractOptions, Format, Manifest, Outcome, PackOptions, Progress, ScanOptions, StreamEntry, decode_at,
    extract_all, load_edits, rebuild_file, unpack,
};

use crate::jobs::{Jobs, finish};
use crate::preview::{self, Previewer};
use crate::project::{self, Project};
use crate::session::{self, Level, Session, check_not_input, default_packed_path, read_edits};
use crate::widgets::{self, entropy_strip, format_color, hex_view, human_size, text_view};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortKey {
    Id,
    Offset,
    Format,
    Compressed,
    Decompressed,
    Ratio,
    Content,
    Exact,
    Edited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Hex,
    Text,
    Image,
    Compressed,
}

/// Something that would throw away unsaved work, waiting for the user to confirm.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    OpenFile(PathBuf),
    OpenProject(PathBuf),
    LoadManifest(PathBuf),
    Scan,
    Close,
    Exit,
}

struct TryAt {
    offset: String,
    format: Format,
    match_params: bool,
}

struct PackUi {
    use_slack: bool,
    relocate: bool,
    align: u64,
    save_manifest: bool,
}

pub struct App {
    pub session: Session,
    pub jobs: Jobs,
    /// The context of the last frame drawn (for windows, repaints and viewport commands).
    ctx: egui::Context,
    preview: Previewer,
    pub selected: Option<u32>,
    scroll_to_selected: bool,
    sort: (SortKey, bool),
    filter: String,
    pub tab: Tab,
    show_edit: bool,
    pub show_scan: bool,
    pub show_try: bool,
    pub show_pack: bool,
    show_log: bool,
    try_at: TryAt,
    pack_ui: PackUi,
    confirm: Option<Action>,
    allow_close: bool,
    title: String,
    last_extract_dir: Option<PathBuf>,
}

impl App {
    pub fn new() -> Self {
        Self {
            session: Session::default(),
            jobs: Jobs::default(),
            ctx: egui::Context::default(),
            preview: Previewer::default(),
            selected: None,
            scroll_to_selected: false,
            sort: (SortKey::Offset, true),
            filter: String::new(),
            tab: Tab::Hex,
            show_edit: true,
            show_scan: false,
            show_try: false,
            show_pack: false,
            show_log: false,
            try_at: TryAt { offset: String::new(), format: Format::Brotli, match_params: true },
            pack_ui: PackUi { use_slack: false, relocate: false, align: 1, save_manifest: false },
            confirm: None,
            allow_close: false,
            title: String::new(),
            last_extract_dir: None,
        }
    }

    // ----- actions -------------------------------------------------------------------

    /// Run `action`, first asking for confirmation if it would discard unsaved work.
    pub fn request(&mut self, action: Action) {
        let discards = self.session.dirty && (self.session.manifest.is_some() || !self.session.edits.is_empty());
        let harmless_scan = action == Action::Scan && self.session.edits.is_empty();
        if discards && !harmless_scan {
            self.confirm = Some(action);
        } else {
            self.perform(action);
        }
    }

    fn perform(&mut self, action: Action) {
        match action {
            Action::OpenFile(path) => self.open_file(path),
            Action::OpenProject(path) => self.open_project(path),
            Action::LoadManifest(path) => self.load_manifest(path),
            Action::Scan => self.start_scan(),
            Action::Close => {
                self.session.close();
                self.selected = None;
                self.preview.clear();
            }
            Action::Exit => {
                self.allow_close = true;
                self.ctx.send_viewport_cmd(ViewportCommand::Close);
            }
        }
    }

    pub fn open_file(&mut self, path: PathBuf) {
        self.selected = None;
        self.preview.clear();
        self.jobs.start("Opening", None, move || finish("Open", session::open_file(&path), Session::set_file));
    }

    pub fn open_project(&mut self, path: PathBuf) {
        self.selected = None;
        self.preview.clear();
        self.jobs.start("Opening project", None, move || {
            let result = Project::load(&path).and_then(session::open_project);
            finish("Open project", result, move |s, (file, loaded, edits)| {
                s.set_file(file);
                s.set_manifest(loaded, edits);
                s.saved_project(path);
            })
        });
    }

    fn load_manifest(&mut self, path: PathBuf) {
        let Some(file) = &self.session.file else { return };
        let (data, file_path) = (file.data.clone(), file.path.clone());
        self.selected = None;
        self.jobs.start("Loading manifest", None, move || {
            let result = Manifest::load(&path).map_err(anyhow::Error::from).map(|m| {
                let file = session::OpenFile { path: file_path, data, entropy: Vec::new() };
                session::prepare_manifest(&file, m)
            });
            finish("Load manifest", result, move |s, loaded| {
                s.info(format!("loaded manifest {}", path.display()));
                s.set_manifest(loaded, Default::default());
            })
        });
    }

    pub fn start_scan(&mut self) {
        let Some(file) = &self.session.file else { return };
        let progress = Arc::new(Progress::default());
        let (p, opts) = (progress.clone(), self.session.scan_options.clone());
        let file = session::OpenFile { path: file.path.clone(), data: file.data.clone(), entropy: Vec::new() };
        self.selected = None;
        self.preview.clear();
        self.jobs.start("Scanning", Some(progress), move || {
            finish("Scan", session::run_scan(&file, opts, &p), |s, (loaded, stats)| s.set_scanned(loaded, stats))
        });
    }

    fn start_try(&mut self) {
        let (Some(file), Some(_)) = (&self.session.file, &self.session.manifest) else { return };
        let Some(offset) = parse_offset(&self.try_at.offset) else {
            self.session.error(format!("'{}' is not an offset (decimal, or hex with 0x)", self.try_at.offset));
            return;
        };
        let (data, format, match_params) = (file.data.clone(), self.try_at.format, self.try_at.match_params);
        self.jobs.start(format!("Decoding {format} at {offset:#x}"), None, move || {
            let result = decode_at(&data, offset, format, DEFAULT_MAX_OUTPUT, match_params)
                .map_err(|e| anyhow::anyhow!("no {format} stream decodes at {offset:#x}: {e}"))
                .map(|found| {
                    let mut ctx = DecodeCtx::new(found.decompressed_size as usize);
                    let content = codec_for(format)
                        .decode(&data[offset as usize..], &mut ctx)
                        .ok()
                        .map(|d| sniff(&d.data[..d.data.len().min(4096)]));
                    (found, content)
                });
            finish("Add stream", result, |s, (found, content)| {
                if let Err(e) = s.add_stream(found, content) {
                    s.error(format!("Add stream: {e:#}"));
                }
            })
        });
    }

    fn start_fields(&mut self) {
        let (Some(file), Some(manifest)) = (&self.session.file, &self.session.manifest) else { return };
        let (data, manifest) = (file.data.clone(), manifest.clone());
        self.jobs.start("Detecting length fields", None, move || {
            finish("Detect length fields", session::run_fields(&data, &manifest), |s, (m, candidates, added)| {
                s.set_fields(m, candidates, added)
            })
        });
    }

    fn start_pack(&mut self, output: Option<PathBuf>) {
        let (Some(file), Some(manifest)) = (&self.session.file, &self.session.manifest) else { return };
        if let Some(out) = &output
            && let Err(e) = check_not_input(out, &file.path)
        {
            self.session.error(format!("Pack: {e}"));
            return;
        }
        let (data, manifest, edits) = (file.data.clone(), manifest.clone(), self.session.edits.clone());
        let opts = PackOptions {
            verify_source: true,
            use_zero_slack: self.pack_ui.use_slack,
            relocate: self.pack_ui.relocate,
            align: self.pack_ui.align.max(1),
        };
        let save_manifest = self.pack_ui.save_manifest;
        let label = if output.is_some() { "Packing" } else { "Dry run" };
        self.jobs.start(label, None, move || {
            let result = read_edits(&edits).and_then(|edits| {
                let (report, packed) = session::run_pack(&data, &manifest, &edits, &opts, output.as_deref())?;
                if let (Some(m), Some(out), true) = (&packed, &output, save_manifest) {
                    m.save(&manifest_path_for(out))?;
                }
                Ok(report)
            });
            finish("Pack", result, Session::set_pack_report)
        });
    }

    fn export_stream(&mut self, id: u32) {
        let (Some(file), Some(entry)) = (&self.session.file, self.session.stream(id).cloned()) else { return };
        let Some(path) = rfd::FileDialog::new().set_file_name(&entry.file).save_file() else { return };
        let data = file.data.clone();
        let edit = self.session.edits.get(&id).cloned().filter(|_| self.show_edit);
        self.jobs.start("Exporting", None, move || {
            let result = session::stream_contents(&data, &entry, edit.as_deref())
                .and_then(|bytes| std::fs::write(&path, &bytes).map_err(Into::into).map(|()| bytes.len()));
            finish("Export", result, move |s, n| s.info(format!("stream {id}: {n} bytes written to {}", path.display())))
        });
    }

    fn replace_stream(&mut self, id: u32) {
        if let Some(path) = rfd::FileDialog::new().set_title(format!("New contents for stream {id}")).pick_file() {
            self.session.set_edit(id, path);
            self.show_edit = true;
        }
    }

    fn extract_all(&mut self) {
        let (Some(file), Some(manifest)) = (&self.session.file, &self.session.manifest) else { return };
        let Some(dir) = rfd::FileDialog::new().set_title("Extract every stream to").pick_folder() else { return };
        let (data, manifest) = (file.data.clone(), manifest.clone());
        self.last_extract_dir = Some(dir.clone());
        self.jobs.start("Extracting", None, move || {
            let result = extract_all(&data, &manifest, &dir, &ExtractOptions::default());
            finish("Extract", result.map_err(Into::into), move |s, files| {
                s.info(format!(
                    "{} stream(s) extracted to {}; edit them there, then use Streams > Import edits",
                    files.len(),
                    dir.display()
                ))
            })
        });
    }

    fn import_edits(&mut self) {
        let Some(manifest) = &self.session.manifest else { return };
        let mut dialog = rfd::FileDialog::new().set_title("Folder with edited stream files");
        if let Some(dir) = &self.last_extract_dir {
            dialog = dialog.set_directory(dir);
        }
        let Some(dir) = dialog.pick_folder() else { return };
        let manifest = manifest.clone();
        self.jobs.start("Looking for edits", None, move || {
            let result = load_edits(&dir, &manifest).map(|edits| edits.into_keys().collect::<Vec<_>>());
            finish("Import edits", result.map_err(Into::into), move |s, ids| s.set_edits_from_dir(&dir, ids))
        });
    }

    fn unpack_to_folder(&mut self) {
        let (Some(file), Some(manifest)) = (&self.session.file, &self.session.manifest) else { return };
        let Some(dir) = rfd::FileDialog::new().set_title("Unpack to (an empty folder)").pick_folder() else { return };
        let (data, manifest) = (file.data.clone(), manifest.clone());
        self.jobs.start("Unpacking", None, move || {
            finish("Unpack", unpack(&data, &manifest, &dir).map_err(Into::into), move |s, sum| {
                s.info(format!(
                    "unpacked {} stream(s) to {}: {} by encoder settings, {} by preflate, {} stored as is",
                    sum.streams,
                    dir.display(),
                    sum.encoded,
                    sum.preflated,
                    sum.stored
                ))
            })
        });
    }

    fn rebuild_from_folder(&mut self) {
        let Some(dir) = rfd::FileDialog::new().set_title("Folder written by Unpack").pick_folder() else { return };
        let Some(out) = rfd::FileDialog::new().set_title("Rebuild to").save_file() else { return };
        self.jobs.start("Rebuilding", None, move || {
            finish("Rebuild", rebuild_file(&dir, &out).map_err(Into::into), move |s, sum| {
                s.info(format!(
                    "rebuilt {} ({} bytes, {} streams); size and CRC-32 match the original",
                    out.display(),
                    sum.bytes,
                    sum.streams
                ))
            })
        });
    }

    pub fn save_project(&mut self, save_as: bool) {
        let Some(project) = self.session.to_project() else {
            self.session.error("Save project: open and scan a file first");
            return;
        };
        let path = match (&self.session.project_path, save_as) {
            (Some(p), false) => p.clone(),
            _ => {
                let stem = project.input.file_stem().map_or("project".into(), |s| s.to_string_lossy().into_owned());
                let mut dialog = rfd::FileDialog::new()
                    .add_filter("zscan project", &[project::EXTENSION])
                    .set_file_name(format!("{stem}.{}", project::EXTENSION));
                if let Some(dir) = project.input.parent() {
                    dialog = dialog.set_directory(dir);
                }
                let Some(p) = dialog.save_file() else { return };
                p
            }
        };
        match project.save(&path) {
            Ok(()) => self.session.saved_project(path),
            Err(e) => self.session.error(format!("Save project: {e:#}")),
        }
    }

    fn save_manifest(&mut self) {
        let Some(manifest) = &self.session.manifest else { return };
        let Some(path) = rfd::FileDialog::new().add_filter("manifest", &["json"]).set_file_name("manifest.json").save_file()
        else {
            return;
        };
        match manifest.save(&path) {
            Ok(()) => self.session.info(format!("manifest saved to {}", path.display())),
            Err(e) => self.session.error(format!("Save manifest: {e}")),
        }
    }

    fn select(&mut self, id: u32) {
        self.selected = Some(id);
        self.scroll_to_selected = true;
    }

    // ----- drawing -------------------------------------------------------------------

    /// Draw one frame.
    pub fn show(&mut self, ui: &mut Ui) {
        if self.ctx != *ui.ctx() {
            self.ctx = ui.ctx().clone();
            let waker = self.ctx.clone();
            self.jobs.set_waker(move || waker.request_repaint());
        }
        self.preview.poll();
        if self.jobs.poll(&mut self.session) {
            self.preview.clear();
        }
        if let Some(id) = self.session.select.take() {
            self.select(id);
        }
        if self.selected.is_some_and(|id| self.session.stream(id).is_none()) {
            self.selected = None;
        }
        self.handle_input(ui);
        self.update_title();

        egui::Panel::top("menu").show(ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| self.menu_bar(ui));
            ui.add_space(2.0);
            self.toolbar(ui);
            ui.add_space(4.0);
        });
        egui::Panel::bottom("status").show(ui, |ui| self.status_bar(ui));
        if self.session.file.is_some() {
            egui::Panel::top("map").show(ui, |ui| {
                ui.add_space(4.0);
                self.map(ui);
                ui.add_space(4.0);
            });
        }
        if self.selected.is_some() {
            egui::Panel::right("details").resizable(true).default_size(520.0).min_size(320.0).show(ui, |ui| self.details(ui));
        }
        egui::CentralPanel::default().show(ui, |ui| self.central(ui));

        self.scan_window();
        self.try_window();
        self.pack_window();
        self.log_window();
        self.confirm_modal();
        if self.jobs.busy() || self.preview.loading() {
            // Keep the progress display moving.
            self.ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn handle_input(&mut self, ui: &Ui) {
        let ctx = ui.ctx().clone();
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close && self.session.dirty {
            ctx.send_viewport_cmd(ViewportCommand::CancelClose);
            self.confirm = Some(Action::Exit);
        }
        let dropped = ctx.input(|i| i.raw.dropped_files.first().map(|f| f.path().to_path_buf()).filter(|p| !p.as_os_str().is_empty()));
        if let Some(path) = dropped
            && !self.jobs.busy()
        {
            let is_project = path.extension().is_some_and(|e| e == project::EXTENSION);
            self.request(if is_project { Action::OpenProject(path) } else { Action::OpenFile(path) });
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::O)) && !self.jobs.busy() {
            self.pick_and_open();
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::COMMAND, Key::S)) {
            self.save_project(false);
        }
        // Arrow keys move through the table when nothing else has focus.
        if ctx.memory(|m| m.focused().is_none()) {
            let step = ctx.input(|i| i.key_pressed(Key::ArrowDown) as i64 - i.key_pressed(Key::ArrowUp) as i64);
            if step != 0 {
                let view = self.view();
                let streams = self.session.streams();
                let pos = self.selected.and_then(|id| view.iter().position(|&i| streams[i].id == id));
                let next = match pos {
                    Some(p) => (p as i64 + step).clamp(0, view.len() as i64 - 1) as usize,
                    None => 0,
                };
                if let Some(&i) = view.get(next) {
                    let id = streams[i].id;
                    self.select(id);
                }
            }
        }
    }

    fn update_title(&mut self) {
        let name = |p: &Path| p.file_name().map_or_else(|| p.display().to_string(), |n| n.to_string_lossy().into_owned());
        let mut title = match (&self.session.project_path, &self.session.file) {
            (Some(p), _) => format!("{} - zscan", name(p)),
            (None, Some(f)) => format!("{} - zscan", name(&f.path)),
            _ => "zscan".to_string(),
        };
        if self.session.dirty {
            title.insert(0, '*');
        }
        if title != self.title {
            self.ctx.send_viewport_cmd(ViewportCommand::Title(title.clone()));
            self.title = title;
        }
    }

    fn pick_and_open(&mut self) {
        if let Some(path) = rfd::FileDialog::new().set_title("Open a file to scan").pick_file() {
            self.request(Action::OpenFile(path));
        }
    }

    fn pick_project(&mut self) {
        if let Some(path) = rfd::FileDialog::new().add_filter("zscan project", &[project::EXTENSION]).pick_file() {
            self.request(Action::OpenProject(path));
        }
    }

    fn menu_bar(&mut self, ui: &mut Ui) {
        let busy = self.jobs.busy();
        let has_file = self.session.file.is_some();
        let has_manifest = self.session.manifest.is_some();
        let can_pack = has_manifest && self.session.source_mismatch.is_none();
        let selected = self.selected;

        ui.menu_button("File", |ui| {
            if ui.add_enabled(!busy, egui::Button::new("Open file…").shortcut_text("Ctrl+O")).clicked() {
                ui.close();
                self.pick_and_open();
            }
            if ui.add_enabled(!busy, egui::Button::new("Open project…")).clicked() {
                ui.close();
                self.pick_project();
            }
            ui.separator();
            if ui.add_enabled(has_manifest, egui::Button::new("Save project").shortcut_text("Ctrl+S")).clicked() {
                ui.close();
                self.save_project(false);
            }
            if ui.add_enabled(has_manifest, egui::Button::new("Save project as…")).clicked() {
                ui.close();
                self.save_project(true);
            }
            ui.separator();
            if ui.add_enabled(has_file && !busy, egui::Button::new("Load manifest…")).clicked() {
                ui.close();
                if let Some(p) = rfd::FileDialog::new().add_filter("manifest", &["json"]).pick_file() {
                    self.request(Action::LoadManifest(p));
                }
            }
            if ui.add_enabled(has_manifest, egui::Button::new("Save manifest as…")).clicked() {
                ui.close();
                self.save_manifest();
            }
            ui.separator();
            if ui.add_enabled(has_file && !busy, egui::Button::new("Close file")).clicked() {
                ui.close();
                self.request(Action::Close);
            }
            if ui.button("Exit").clicked() {
                ui.close();
                self.request(Action::Exit);
            }
        });
        ui.menu_button("Scan", |ui| {
            if ui.add_enabled(has_file && !busy, egui::Button::new("Scan")).clicked() {
                ui.close();
                self.request(Action::Scan);
            }
            if ui.add_enabled(has_file, egui::Button::new("Scan options…")).clicked() {
                ui.close();
                self.show_scan = true;
            }
            ui.separator();
            if ui.add_enabled(has_manifest, egui::Button::new("Add stream at offset…"))
                .on_hover_text("Decode one format at a known offset, e.g. brotli, which can't be scanned for")
                .clicked()
            {
                ui.close();
                self.show_try = true;
            }
            if ui.add_enabled(can_pack && !busy, egui::Button::new("Detect length fields"))
                .on_hover_text("Find size and offset fields for each stream, so pack can update them and relocate streams")
                .clicked()
            {
                ui.close();
                self.start_fields();
            }
        });
        ui.menu_button("Streams", |ui| {
            if ui.add_enabled(can_pack && !busy, egui::Button::new("Extract all to folder…")).clicked() {
                ui.close();
                self.extract_all();
            }
            if ui.add_enabled(has_manifest && !busy, egui::Button::new("Import edits from folder…")).clicked() {
                ui.close();
                self.import_edits();
            }
            ui.separator();
            if let Some(id) = selected {
                self.stream_actions(ui, id);
            } else {
                ui.add_enabled(false, egui::Button::new("Select a stream for more"));
            }
        });
        ui.menu_button("Pack", |ui| {
            if ui.add_enabled(has_manifest, egui::Button::new("Pack…")).clicked() {
                ui.close();
                self.show_pack = true;
            }
        });
        ui.menu_button("Tools", |ui| {
            if ui.add_enabled(can_pack && !busy, egui::Button::new("Unpack to folder…"))
                .on_hover_text("Expand the file into its streams' contents plus what's needed to rebuild it bit for bit")
                .clicked()
            {
                ui.close();
                self.unpack_to_folder();
            }
            if ui.add_enabled(!busy, egui::Button::new("Rebuild from folder…")).clicked() {
                ui.close();
                self.rebuild_from_folder();
            }
            ui.separator();
            if ui.button("Log").clicked() {
                ui.close();
                self.show_log = true;
            }
        });
    }

    /// Export / replace / revert, for menus.
    fn stream_actions(&mut self, ui: &mut Ui, id: u32) {
        let busy = self.jobs.busy();
        let edited = self.session.edits.contains_key(&id);
        if ui.add_enabled(!busy, egui::Button::new(format!("Export stream {id}…"))).clicked() {
            ui.close();
            self.export_stream(id);
        }
        if ui.button(format!("Replace stream {id}…")).clicked() {
            ui.close();
            self.replace_stream(id);
        }
        if ui.add_enabled(edited, egui::Button::new(format!("Revert stream {id}"))).clicked() {
            ui.close();
            self.session.revert(id);
        }
    }

    fn toolbar(&mut self, ui: &mut Ui) {
        let busy = self.jobs.busy();
        ui.horizontal(|ui| {
            if ui.add_enabled(!busy, egui::Button::new("Open…")).clicked() {
                self.pick_and_open();
            }
            let has_file = self.session.file.is_some();
            if ui.add_enabled(has_file && !busy, egui::Button::new("Scan")).clicked() {
                self.request(Action::Scan);
            }
            if ui.add_enabled(has_file, egui::Button::new("Options…")).clicked() {
                self.show_scan = true;
            }
            let n_edits = self.session.edits.len();
            let pack_label = if n_edits > 0 { format!("Pack ({n_edits} edited)…") } else { "Pack…".to_string() };
            if ui.add_enabled(self.session.manifest.is_some(), egui::Button::new(pack_label)).clicked() {
                self.show_pack = true;
            }
            ui.separator();
            ui.label("Filter:");
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("format, content, offset…").desired_width(180.0));
            if !self.filter.is_empty() && ui.small_button("×").on_hover_text("Clear the filter").clicked() {
                self.filter.clear();
            }
        });
    }

    fn map(&mut self, ui: &mut Ui) {
        let Some(file) = &self.session.file else { return };
        let edits = &self.session.edits;
        let clicked =
            entropy_strip(ui, &file.entropy, file.len(), self.session.streams(), self.selected, |id| edits.contains_key(&id));
        if let Some(id) = clicked {
            self.select(id);
        }
    }

    fn status_bar(&mut self, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if let Some(job) = self.jobs.current() {
                ui.spinner();
                ui.label(format!("{}… {:.1} s", job.label, job.started.elapsed().as_secs_f64()));
                if let Some(p) = &job.progress {
                    let (phase, done, total) = p.get();
                    let what = match phase {
                        zscan_core::ScanPhase::Verified => "checksummed formats",
                        zscan_core::ScanPhase::Unverified => "raw deflate",
                        zscan_core::ScanPhase::Params => "matching encoder settings",
                    };
                    let fraction = if total == 0 { 0.0 } else { done as f32 / total as f32 };
                    ui.add(egui::ProgressBar::new(fraction).desired_width(200.0).text(what));
                    if ui.button("Cancel").clicked() {
                        p.cancel();
                    }
                }
            } else if let Some(line) = self.session.log.last() {
                let text = RichText::new(&line.text).color(level_color(ui, line.level));
                if ui.add(egui::Label::new(text).sense(Sense::click()).truncate()).on_hover_text("Show the log").clicked() {
                    self.show_log = true;
                }
            } else {
                ui.label("Open a file, or drop one on the window.");
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if let Some(file) = &self.session.file {
                    ui.label(human_size(file.len()));
                    if let Some(m) = &self.session.manifest {
                        let exact = m.streams.iter().filter(|s| s.exact_params.is_some()).count();
                        ui.separator();
                        ui.label(format!("{} streams, {exact} exact, {} edited", m.streams.len(), self.session.edits.len()));
                    }
                }
            });
        });
    }

    fn central(&mut self, ui: &mut Ui) {
        if self.session.file.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 3.0);
                ui.heading("zscan");
                ui.label("Find, extract and reinject compressed streams inside binary files.");
                ui.add_space(12.0);
                let busy = self.jobs.busy();
                if ui.add_enabled(!busy, egui::Button::new("Open a file…")).clicked() {
                    self.pick_and_open();
                }
                if ui.add_enabled(!busy, egui::Button::new("Open a project…")).clicked() {
                    self.pick_project();
                }
                ui.add_space(8.0);
                ui.weak("or drop a file on this window");
            });
            return;
        }
        if let Some(why) = &self.session.source_mismatch {
            ui.colored_label(ui.visuals().error_fg_color, format!("This manifest doesn't describe the open file: {why}"));
        }
        if self.session.manifest.is_none() {
            ui.vertical_centered(|ui| {
                ui.add_space(ui.available_height() / 3.0);
                ui.label("Not scanned yet.");
                ui.add_space(8.0);
                let busy = self.jobs.busy();
                if ui.add_enabled(!busy, egui::Button::new("Scan the file")).clicked() {
                    self.request(Action::Scan);
                }
                if ui.button("Scan options…").clicked() {
                    self.show_scan = true;
                }
            });
            return;
        }
        self.table(ui);
    }

    /// Indices into the manifest's streams, filtered and sorted for the table.
    fn view(&self) -> Vec<usize> {
        let streams = self.session.streams();
        let needle = self.filter.trim().to_lowercase();
        let mut view: Vec<usize> = (0..streams.len())
            .filter(|&i| {
                if needle.is_empty() {
                    return true;
                }
                let s = &streams[i];
                let content = self.session.content.get(&s.id).map_or("", |c| c.name);
                s.format.name().contains(&needle)
                    || content.to_lowercase().contains(&needle)
                    || format!("{:#x}", s.offset).contains(&needle)
                    || s.id.to_string() == needle
                    || (needle == "edited" && self.session.edits.contains_key(&s.id))
            })
            .collect();
        let (key, ascending) = self.sort;
        let content = |s: &StreamEntry| self.session.content.get(&s.id).map_or("", |c| c.name);
        view.sort_by(|&a, &b| {
            let (a, b) = (&streams[a], &streams[b]);
            let ord = match key {
                SortKey::Id => a.id.cmp(&b.id),
                SortKey::Offset => a.offset.cmp(&b.offset),
                SortKey::Format => a.format.name().cmp(b.format.name()),
                SortKey::Compressed => a.compressed_size.cmp(&b.compressed_size),
                SortKey::Decompressed => a.decompressed_size.cmp(&b.decompressed_size),
                SortKey::Ratio => a.ratio().total_cmp(&b.ratio()),
                SortKey::Content => content(a).cmp(content(b)),
                SortKey::Exact => a.exact_params.is_some().cmp(&b.exact_params.is_some()),
                SortKey::Edited => self.session.edits.contains_key(&a.id).cmp(&self.session.edits.contains_key(&b.id)),
            };
            let ord = ord.then(a.offset.cmp(&b.offset));
            if ascending { ord } else { ord.reverse() }
        });
        view
    }

    fn table(&mut self, ui: &mut Ui) {
        // Selectable labels would take clicks meant for the row.
        ui.style_mut().interaction.selectable_labels = false;
        let view = self.view();
        let streams = self.session.streams();
        let mut clicked: Option<u32> = None;
        let mut action: Option<(u32, &'static str)> = None;
        let mut sort = self.sort;

        let mut table = TableBuilder::new(ui)
            .striped(true)
            .sense(Sense::click())
            .cell_layout(Layout::left_to_right(Align::Center))
            .column(Column::auto().at_least(40.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(60.0))
            .columns(Column::auto().at_least(90.0), 2)
            .column(Column::auto().at_least(50.0))
            .column(Column::auto().at_least(110.0))
            .column(Column::auto().at_least(50.0))
            .column(Column::remainder().at_least(50.0));
        if self.scroll_to_selected {
            if let Some(row) = self.selected.and_then(|id| view.iter().position(|&i| streams[i].id == id)) {
                table = table.scroll_to_row(row, Some(Align::Center));
            }
            self.scroll_to_selected = false;
        }
        let headers = [
            ("#", SortKey::Id),
            ("Offset", SortKey::Offset),
            ("Format", SortKey::Format),
            ("Compressed", SortKey::Compressed),
            ("Decompressed", SortKey::Decompressed),
            ("Ratio", SortKey::Ratio),
            ("Content", SortKey::Content),
            ("Exact", SortKey::Exact),
            ("Edited", SortKey::Edited),
        ];
        table
            .header(22.0, |mut header| {
                for (label, key) in headers {
                    header.col(|ui| {
                        let arrow = match sort {
                            (k, true) if k == key => " ⏶",
                            (k, false) if k == key => " ⏷",
                            _ => "",
                        };
                        if ui.add(egui::Button::new(RichText::new(format!("{label}{arrow}")).strong()).frame(false)).clicked() {
                            sort = if sort.0 == key { (key, !sort.1) } else { (key, true) };
                        }
                    });
                }
            })
            .body(|mut body| {
                let row_height = body.ui_mut().text_style_height(&egui::TextStyle::Body) + 4.0;
                body.rows(row_height, view.len(), |mut row| {
                    let s = &streams[view[row.index()]];
                    row.set_selected(self.selected == Some(s.id));
                    row.col(|ui| {
                        ui.label(s.id.to_string());
                    });
                    row.col(|ui| {
                        ui.monospace(format!("{:#010x}", s.offset));
                    });
                    row.col(|ui| {
                        ui.colored_label(format_color(s.format), s.format.name());
                    });
                    row.col(|ui| {
                        ui.label(s.compressed_size.to_string());
                    });
                    row.col(|ui| {
                        ui.label(s.decompressed_size.to_string());
                    });
                    row.col(|ui| {
                        ui.label(format!("{:.2}", s.ratio()));
                    });
                    row.col(|ui| {
                        ui.label(self.session.content.get(&s.id).map_or("?", |c| c.name));
                    });
                    row.col(|ui| {
                        match &s.exact_params {
                            Some(p) => ui.label("✔").on_hover_text(format!("reproduced exactly by {p}")),
                            None => ui.weak("–").on_hover_text("no encoder settings reproduce this stream exactly"),
                        };
                    });
                    row.col(|ui| {
                        if self.session.edits.contains_key(&s.id) {
                            ui.strong("edited");
                        }
                    });
                    let response = row.response();
                    if response.clicked() {
                        clicked = Some(s.id);
                    }
                    response.context_menu(|ui| {
                        clicked = Some(s.id);
                        if ui.button("Export…").clicked() {
                            action = Some((s.id, "export"));
                            ui.close();
                        }
                        if ui.button("Replace with file…").clicked() {
                            action = Some((s.id, "replace"));
                            ui.close();
                        }
                        if ui.add_enabled(self.session.edits.contains_key(&s.id), egui::Button::new("Revert edit")).clicked() {
                            action = Some((s.id, "revert"));
                            ui.close();
                        }
                    });
                });
            });

        self.sort = sort;
        if let Some(id) = clicked {
            self.selected = Some(id);
        }
        match action {
            Some((id, "export")) => self.export_stream(id),
            Some((id, "replace")) => self.replace_stream(id),
            Some((id, "revert")) => self.session.revert(id),
            _ => {}
        }
    }

    fn details(&mut self, ui: &mut Ui) {
        let Some(id) = self.selected else { return };
        let (Some(entry), Some(data)) = (self.session.stream(id).cloned(), self.session.file.as_ref().map(|f| f.data.clone()))
        else {
            return;
        };
        let edit = self.session.edits.get(&id).cloned();

        ui.horizontal(|ui| {
            ui.heading(format!("Stream {id}"));
            ui.colored_label(format_color(entry.format), entry.format.name());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.small_button("×").on_hover_text("Close").clicked() {
                    self.selected = None;
                }
            });
        });
        egui::Grid::new("details").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
            ui.label("Offset");
            ui.monospace(format!("{:#x} – {:#x}", entry.offset, entry.end()));
            ui.end_row();
            ui.label("Size");
            ui.label(format!(
                "{} bytes compressed, {} decompressed (ratio {:.2})",
                entry.compressed_size, entry.decompressed_size, entry.ratio()
            ));
            ui.end_row();
            ui.label("CRC-32");
            ui.monospace(format!("{:08x}", entry.crc32));
            ui.end_row();
            ui.label("Content");
            ui.label(self.session.content.get(&id).map_or("?", |c| c.name));
            ui.end_row();
            ui.label("Exact settings");
            match &entry.exact_params {
                Some(p) => ui.label(p.to_string()),
                None => ui.weak("none found: a repack uses settings from the header, so unedited bytes won't match"),
            };
            ui.end_row();
            if let Some(name) = &entry.original_name {
                ui.label("Original name");
                ui.label(name);
                ui.end_row();
            }
            if !entry.length_fields.is_empty() {
                ui.label("Length fields");
                ui.vertical(|ui| {
                    for f in &entry.length_fields {
                        ui.label(format!(
                            "{:?} at {:#x}: {} bytes, {:?}{}",
                            f.measures,
                            f.offset,
                            f.width,
                            f.endian,
                            if f.adjust != 0 { format!(", adjust {:+}", f.adjust) } else { String::new() }
                        ));
                    }
                });
                ui.end_row();
            }
            ui.label("Edit");
            match &edit {
                Some(path) => ui.label(path.display().to_string()),
                None => ui.weak("unchanged"),
            };
            ui.end_row();
        });
        ui.horizontal(|ui| {
            if ui.add_enabled(!self.jobs.busy(), egui::Button::new("Export…")).clicked() {
                self.export_stream(id);
            }
            if ui.button("Replace…").clicked() {
                self.replace_stream(id);
            }
            if ui.add_enabled(edit.is_some(), egui::Button::new("Revert")).clicked() {
                self.session.revert(id);
            }
        });
        ui.separator();
        ui.horizontal(|ui| {
            for (tab, label) in [(Tab::Hex, "Hex"), (Tab::Text, "Text"), (Tab::Image, "Image"), (Tab::Compressed, "Raw bytes")] {
                ui.selectable_value(&mut self.tab, tab, label);
            }
            if edit.is_some() && self.tab != Tab::Compressed {
                ui.separator();
                ui.selectable_value(&mut self.show_edit, false, "Original");
                ui.selectable_value(&mut self.show_edit, true, "Edited");
            }
        });

        if self.tab == Tab::Compressed {
            let start = entry.offset as usize;
            let end = (entry.end() as usize).min(data.len());
            hex_view(ui, ("raw", id), &data[start.min(end)..end], entry.offset);
            return;
        }

        let key = preview::Key {
            id,
            edited: edit.clone().filter(|_| self.show_edit),
            generation: self.session.generation,
        };
        let ctx = self.ctx.clone();
        self.preview.request(key.clone(), data, entry.clone(), move || ctx.request_repaint());
        if self.preview.key.as_ref() != Some(&key) {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Decoding…");
            });
            return;
        }
        let tab = self.tab;
        let preview = &mut self.preview;
        match &preview.current {
            None => {}
            Some(Err(e)) => {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            Some(Ok(loaded)) => {
                ui.weak(format!("{} · {}", loaded.kind.name, human_size(loaded.bytes.len() as u64)));
                match tab {
                    Tab::Hex => hex_view(ui, ("hex", id), &loaded.bytes, 0),
                    Tab::Text => match &loaded.text {
                        Some(text) => {
                            if text.truncated {
                                ui.weak("showing the first 4 MiB");
                            }
                            text_view(ui, ("text", id), text);
                        }
                        None => {
                            let lines = widgets::TextLines::new(&loaded.bytes, 64 << 10);
                            ui.weak("doesn't look like text; showing the first 64 KiB as UTF-8");
                            text_view(ui, ("text", id), &lines);
                        }
                    },
                    Tab::Image => match &loaded.image {
                        Some(Ok(image)) => {
                            let texture = preview.texture.get_or_insert_with(|| {
                                ui.ctx().load_texture(format!("stream-{id}"), image.clone(), Default::default())
                            });
                            let size = texture.size_vec2();
                            ui.weak(format!("{}×{}", size.x, size.y));
                            // Fit the pane; small images are enlarged (up to 16×) with sharp pixels.
                            let avail = ui.available_size();
                            let scale = (avail.x / size.x).min(avail.y / size.y).clamp(0.01, 16.0);
                            ui.add(
                                egui::Image::new(&*texture)
                                    .texture_options(egui::TextureOptions::NEAREST)
                                    .fit_to_exact_size(size * scale),
                            );
                        }
                        Some(Err(e)) => {
                            ui.colored_label(ui.visuals().error_fg_color, format!("can't decode the image: {e}"));
                        }
                        None => {
                            ui.weak("not an image this viewer knows (PNG, JPEG, GIF, BMP, WebP, TIFF, ICO)");
                        }
                    },
                    Tab::Compressed => unreachable!(),
                }
            }
        }
    }

    // ----- windows -------------------------------------------------------------------

    fn scan_window(&mut self) {
        let mut open = self.show_scan;
        let mut start = false;
        egui::Window::new("Scan options").open(&mut open).resizable(false).show(&self.ctx.clone(), |ui| {
            let o = &mut self.session.scan_options;
            ui.label("Formats");
            ui.horizontal_wrapped(|ui| {
                for f in Format::SCANNABLE {
                    let mut on = o.formats.contains(&f);
                    if ui.checkbox(&mut on, f.name()).changed() {
                        if on {
                            o.formats.push(f);
                        } else {
                            o.formats.retain(|&x| x != f);
                        }
                    }
                }
            });
            ui.weak("Brotli can't be scanned for: add brotli streams with Scan > Add stream at offset.");
            ui.separator();
            egui::Grid::new("scan-opts").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("Minimum decompressed size");
                ui.add(egui::DragValue::new(&mut o.min_size).range(0..=u64::MAX).suffix(" bytes"));
                ui.end_row();
                ui.label("Minimum ratio");
                ui.add(egui::DragValue::new(&mut o.min_ratio).range(0.0..=100.0).speed(0.01));
                ui.end_row();
                ui.label("Maximum output entropy");
                optional_f64(ui, &mut o.max_entropy, 8.0);
                ui.end_row();
                let mut max_mib = o.max_output >> 20;
                ui.label("Largest stream");
                if ui.add(egui::DragValue::new(&mut max_mib).range(1..=1 << 20).suffix(" MiB")).changed() {
                    o.max_output = max_mib << 20;
                }
                ui.end_row();
                ui.label("Raw deflate: minimum compressed size");
                ui.add(egui::DragValue::new(&mut o.raw_min_compressed).range(0..=u64::MAX).suffix(" bytes"));
                ui.end_row();
                ui.label("Raw deflate: minimum ratio");
                ui.add(egui::DragValue::new(&mut o.raw_min_ratio).range(0.0..=100.0).speed(0.01));
                ui.end_row();
                ui.label("Raw deflate: maximum output entropy");
                optional_f64(ui, &mut o.raw_max_entropy, DEFAULT_RAW_MAX_ENTROPY);
                ui.end_row();
            });
            ui.checkbox(&mut o.match_params, "Find encoder settings that reproduce each stream exactly")
                .on_hover_text("Needed for unedited streams to repack bit-identically. Slow on files with many large xz/zstd streams");
            ui.separator();
            ui.horizontal(|ui| {
                if ui.button("Defaults").clicked() {
                    *o = ScanOptions::default();
                }
                if ui.add_enabled(!self.jobs.busy(), egui::Button::new("Scan")).clicked() {
                    start = true;
                }
            });
        });
        self.show_scan = open && !start;
        if start {
            self.request(Action::Scan);
        }
    }

    fn try_window(&mut self) {
        let mut open = self.show_try;
        let mut start = false;
        egui::Window::new("Add stream at offset").open(&mut open).resizable(false).show(&self.ctx.clone(), |ui| {
            ui.label("Decode a stream at an exact offset and add it to the manifest.");
            egui::Grid::new("try").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                ui.label("Offset");
                ui.add(egui::TextEdit::singleline(&mut self.try_at.offset).hint_text("0x1234 or 4660"));
                ui.end_row();
                ui.label("Format");
                egui::ComboBox::from_id_salt("try-format").selected_text(self.try_at.format.name()).show_ui(ui, |ui| {
                    for f in Format::ALL {
                        ui.selectable_value(&mut self.try_at.format, f, f.name());
                    }
                });
                ui.end_row();
            });
            ui.checkbox(&mut self.try_at.match_params, "Find exact encoder settings");
            if ui.add_enabled(!self.jobs.busy(), egui::Button::new("Decode and add")).clicked() {
                start = true;
            }
        });
        self.show_try = open;
        if start {
            self.start_try();
        }
    }

    fn pack_window(&mut self) {
        let mut open = self.show_pack;
        let mut run: Option<Option<PathBuf>> = None;
        egui::Window::new("Pack")
            .open(&mut open)
            .default_width(640.0)
            .pivot(egui::Align2::CENTER_CENTER)
            .default_pos(self.ctx.content_rect().center())
            .show(&self.ctx.clone(), |ui| {
            let s = &self.session;
            if let Some(why) = &s.source_mismatch {
                ui.colored_label(ui.visuals().error_fg_color, format!("Can't pack: {why}"));
                return;
            }
            if s.edits.is_empty() {
                ui.label("No edited streams yet. Replace a stream (right-click it in the table), or extract all, edit the files and import the edits.");
            } else {
                ui.label(format!("{} edited stream(s) will be recompressed into a copy of the file.", s.edits.len()));
            }
            ui.add_space(4.0);
            let p = &mut self.pack_ui;
            ui.checkbox(&mut p.use_slack, "Let a stream grow into zero bytes after it")
                .on_hover_text("Only safe if whatever reads the file finds the stream's end by decoding it, or reads its size from a length field");
            ui.horizontal(|ui| {
                ui.checkbox(&mut p.relocate, "Move streams that don't fit to the end of the file")
                    .on_hover_text("Needs offset and compressed-size fields for the stream (Scan > Detect length fields)");
                ui.add_enabled(p.relocate, egui::DragValue::new(&mut p.align).range(1..=1 << 20).prefix("align "));
            });
            ui.checkbox(&mut p.save_manifest, "Also save a manifest for the packed file (next to it, .json)");
            ui.horizontal(|ui| {
                let busy = self.jobs.busy();
                let has_edits = !self.session.edits.is_empty();
                if ui.add_enabled(!busy && has_edits, egui::Button::new("Dry run")).clicked() {
                    run = Some(None);
                }
                if ui.add_enabled(!busy && has_edits, egui::Button::new("Pack to file…")).clicked()
                    && let Some(input) = self.session.file.as_ref().map(|f| f.path.clone())
                {
                    let default = default_packed_path(&input);
                    let mut dialog = rfd::FileDialog::new().set_title("Write the packed file to");
                    if let (Some(dir), Some(name)) = (default.parent(), default.file_name()) {
                        dialog = dialog.set_directory(dir).set_file_name(name.to_string_lossy());
                    }
                    if let Some(out) = dialog.save_file() {
                        run = Some(Some(out));
                    }
                }
            });
            if let Some(report) = &self.session.last_pack {
                ui.separator();
                pack_report(ui, report);
            }
        });
        self.show_pack = open;
        if let Some(output) = run {
            self.start_pack(output);
        }
    }

    fn log_window(&mut self) {
        let mut open = self.show_log;
        egui::Window::new("Log").open(&mut open).default_size([640.0, 320.0]).show(&self.ctx.clone(), |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink(false).show(ui, |ui| {
                for line in &self.session.log {
                    ui.colored_label(level_color(ui, line.level), &line.text);
                }
            });
        });
        self.show_log = open;
    }

    fn confirm_modal(&mut self) {
        let Some(action) = self.confirm.clone() else { return };
        let what = match &action {
            Action::OpenFile(_) | Action::OpenProject(_) => "Open another file",
            Action::LoadManifest(_) => "Load another manifest",
            Action::Scan => "Scan again (edits refer to stream numbers, so they are dropped)",
            Action::Close => "Close the file",
            Action::Exit => "Exit",
        };
        let mut choice = None;
        egui::Modal::new(egui::Id::new("confirm")).show(&self.ctx.clone(), |ui| {
            ui.set_max_width(380.0);
            ui.heading("Unsaved changes");
            ui.label(format!("{what}? Changes to the streams and edits that aren't saved in a project will be lost."));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Save project first").clicked() {
                    choice = Some(0);
                }
                if ui.button("Discard").clicked() {
                    choice = Some(1);
                }
                if ui.button("Cancel").clicked() {
                    choice = Some(2);
                }
            });
        });
        match choice {
            Some(0) => {
                self.save_project(false);
                if !self.session.dirty {
                    self.confirm = None;
                    self.perform(action);
                }
            }
            Some(1) => {
                self.confirm = None;
                self.session.dirty = false;
                self.perform(action);
            }
            Some(_) => self.confirm = None,
            None => {}
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        self.show(ui);
    }
}

fn pack_report(ui: &mut Ui, report: &session::PackReport) {
    let changed: Vec<_> = report.streams.iter().filter(|s| s.outcome != Outcome::Unchanged).collect();
    egui::Grid::new("pack-report").striped(true).num_columns(7).spacing([10.0, 3.0]).show(ui, |ui| {
        for h in ["#", "Offset", "Format", "Result", "Old size", "New size", "Details"] {
            ui.strong(h);
        }
        ui.end_row();
        for s in changed {
            ui.label(s.id.to_string());
            ui.monospace(format!("{:#x}", s.offset));
            ui.label(s.format.name());
            let (status, detail, bad) = match &s.outcome {
                Outcome::Unchanged => ("unchanged", String::new(), false),
                Outcome::Repacked { params, reused_original_params, slack_used, relocated_to, .. } => {
                    let mut d = params.to_string();
                    if *reused_original_params {
                        d += " (original settings)";
                    }
                    if *slack_used > 0 {
                        d += &format!(", {slack_used} bytes of slack");
                    }
                    if let Some(to) = relocated_to {
                        d += &format!(", moved to {to:#x}");
                    }
                    (if relocated_to.is_some() { "relocated" } else { "repacked" }, d, false)
                }
                Outcome::TooLarge { best_size, available, relocatable } => {
                    let hint = if *relocatable { "; relocation would work" } else { "" };
                    ("too large", format!("{} bytes over{hint}", best_size - available), true)
                }
            };
            if bad {
                ui.colored_label(ui.visuals().error_fg_color, status);
            } else {
                ui.label(status);
            }
            ui.label(s.original_size.to_string());
            ui.label(format!("{} ({:+})", s.new_size(), s.delta()));
            ui.label(detail);
            ui.end_row();
        }
    });
    if !report.field_updates.is_empty() {
        ui.label(format!("{} length field(s) updated", report.field_updates.len()));
    }
    if report.fits && report.output_len != report.input_len {
        ui.label(format!("The file grows from {} to {} bytes.", report.input_len, report.output_len));
    }
    match (&report.written, report.fits) {
        (Some(path), _) => {
            ui.colored_label(Color32::from_rgb(80, 180, 90), format!("Written to {} and every stream verified.", path.display()));
        }
        (None, true) => {
            ui.label("Dry run: every edited stream fits and decodes correctly. Nothing written.");
        }
        (None, false) => {
            ui.colored_label(ui.visuals().error_fg_color, "Some streams don't fit, so nothing can be written.");
        }
    }
}

fn optional_f64(ui: &mut Ui, value: &mut Option<f64>, default: f64) {
    ui.horizontal(|ui| {
        let mut on = value.is_some();
        if ui.checkbox(&mut on, "").changed() {
            *value = on.then_some(value.unwrap_or(default));
        }
        if let Some(v) = value {
            ui.add(egui::DragValue::new(v).range(0.0..=8.0).speed(0.01).suffix(" bits/byte"));
        } else {
            ui.weak("off");
        }
    });
}

fn level_color(ui: &Ui, level: Level) -> Color32 {
    match level {
        Level::Info => ui.visuals().text_color(),
        Level::Warn => ui.visuals().warn_fg_color,
        Level::Error => ui.visuals().error_fg_color,
    }
}

/// `<output>.json`: where the packed file's manifest goes.
fn manifest_path_for(output: &Path) -> PathBuf {
    let mut name = output.as_os_str().to_owned();
    name.push(".json");
    PathBuf::from(name)
}

pub fn parse_offset(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}
