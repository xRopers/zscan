// No console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;

use zscan_gui::App;
use zscan_gui::app::Action;

fn main() -> eframe::Result {
    // `zscan-gui FILE` opens a file (or a .zscan project) straight away.
    let arg = std::env::args_os().nth(1).map(PathBuf::from);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_title("zscan").with_inner_size([1280.0, 800.0]).with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "zscan",
        options,
        Box::new(move |_cc| {
            let mut app = App::new();
            if let Some(path) = arg {
                let is_project = path.extension().is_some_and(|e| e == zscan_gui::project::EXTENSION);
                app.request(if is_project { Action::OpenProject(path) } else { Action::OpenFile(path) });
            }
            Ok(Box::new(app))
        }),
    )
}
