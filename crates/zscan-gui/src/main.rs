// No console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use zscan_gui::App;
use zscan_gui::app::Action;

fn main() -> eframe::Result {
    // `zscan-gui [--oodle-dll PATH] [FILE]`: FILE (or a .zscan project) opens straight away.
    let mut args = std::env::args_os().skip(1);
    let (mut arg, mut oodle_dll) = (None, None);
    while let Some(a) = args.next() {
        if a == "--oodle-dll" {
            oodle_dll = args.next().map(PathBuf::from);
        } else {
            arg = Some(PathBuf::from(a));
        }
    }
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("zscan").with_inner_size([1280.0, 800.0]).with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "zscan",
        options,
        Box::new(move |_cc| {
            let mut app = App::new();
            app.load_settings(zscan_gui::settings::Settings::default_path(), oodle_dll);
            if let Some(path) = arg {
                let is_project = path.extension().is_some_and(|e| e == zscan_gui::project::EXTENSION);
                app.request(if is_project { Action::OpenProject(path) } else { Action::OpenFile(path) });
            }
            Ok(Box::new(app))
        }),
    )
}
