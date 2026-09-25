//! Loading the selected stream's contents for the preview pane, off the UI thread.
//! A newer request replaces an older one; a stale result is dropped.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};

use egui::{ColorImage, TextureHandle};
use zscan_core::StreamEntry;
use zscan_core::content::{ContentClass, ContentType, sniff};
use zscan_core::input::Input;

use crate::session::stream_contents;
use crate::widgets::TextLines;

/// Text shown in the text tab, at most.
const TEXT_LIMIT: usize = 4 << 20;
/// Largest image decoded for display, in pixels.
const IMAGE_PIXELS: u64 = 64 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key {
    pub id: u32,
    /// Showing the edit rather than the original.
    pub edited: Option<PathBuf>,
    /// Session generation, so a changed manifest reloads.
    pub generation: u64,
}

pub struct Loaded {
    pub bytes: Vec<u8>,
    pub kind: ContentType,
    pub text: Option<TextLines>,
    pub image: Option<Result<ColorImage, String>>,
}

#[derive(Default)]
pub struct Previewer {
    pending: Option<(Key, Receiver<Result<Loaded, String>>)>,
    pub key: Option<Key>,
    pub current: Option<Result<Loaded, String>>,
    pub texture: Option<TextureHandle>,
}

impl Previewer {
    /// Load `entry` (or its edit) unless it is already shown or loading.
    pub fn request(&mut self, key: Key, data: Arc<Input>, entry: StreamEntry, wake: impl Fn() + Send + 'static) {
        if self.key.as_ref() == Some(&key) || self.pending.as_ref().is_some_and(|(k, _)| *k == key) {
            return;
        }
        let (tx, rx) = mpsc::channel();
        let edit = key.edited.clone();
        std::thread::spawn(move || {
            let _ = tx.send(load(&data, &entry, edit));
            wake();
        });
        self.pending = Some((key, rx));
    }

    pub fn clear(&mut self) {
        *self = Self::default();
    }

    pub fn loading(&self) -> bool {
        self.pending.is_some()
    }

    /// Take a finished load, if there is one.
    pub fn poll(&mut self) {
        let Some((_, rx)) = &self.pending else { return };
        match rx.try_recv() {
            Ok(result) => {
                let (key, _) = self.pending.take().unwrap();
                self.key = Some(key);
                self.current = Some(result);
                self.texture = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                let (key, _) = self.pending.take().unwrap();
                self.key = Some(key);
                self.current = Some(Err("preview failed unexpectedly".into()));
            }
        }
    }
}

fn load(data: &[u8], entry: &StreamEntry, edit: Option<PathBuf>) -> Result<Loaded, String> {
    let bytes = stream_contents(data, entry, edit.as_deref()).map_err(|e| format!("{e:#}"))?;
    let kind = sniff(&bytes[..bytes.len().min(4096)]);
    let text = (kind.class == ContentClass::Text).then(|| TextLines::new(&bytes, TEXT_LIMIT));
    let image = (kind.class == ContentClass::Image).then(|| decode_image(&bytes));
    Ok(Loaded { bytes, kind, text, image })
}

fn decode_image(bytes: &[u8]) -> Result<ColorImage, String> {
    let reader = image::ImageReader::new(std::io::Cursor::new(bytes)).with_guessed_format().map_err(|e| e.to_string())?;
    let (w, h) = reader.into_dimensions().map_err(|e| e.to_string())?;
    if u64::from(w) * u64::from(h) > IMAGE_PIXELS {
        return Err(format!("{w}×{h} is too large to preview"));
    }
    let img = image::load_from_memory(bytes).map_err(|e| e.to_string())?.to_rgba8();
    Ok(ColorImage::from_rgba_unmultiplied([img.width() as usize, img.height() as usize], img.as_raw()))
}
