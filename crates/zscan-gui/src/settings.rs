//! Settings kept between runs, in `zscan/gui.json` in the user's config folder. For now
//! that is only the Oodle library, which is machine-specific and so doesn't belong in a
//! project file.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// The user's oo2core library. `None` falls back to `ZSCAN_OODLE_DLL`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oodle_dll: Option<PathBuf>,
}

impl Settings {
    /// `%APPDATA%\zscan\gui.json` on Windows, else `$XDG_CONFIG_HOME/zscan/gui.json` or
    /// `~/.config/zscan/gui.json`.
    pub fn default_path() -> Option<PathBuf> {
        let var = |name| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let base = if cfg!(windows) {
            var("APPDATA")?
        } else {
            var("XDG_CONFIG_HOME").or_else(|| var("HOME").map(|h| h.join(".config")))?
        };
        Some(base.join("zscan").join("gui.json"))
    }

    /// The settings at `path`; defaults if the file is missing or unreadable.
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
        }
        let text = serde_json::to_string_pretty(self)? + "\n";
        fs::write(path, text).with_context(|| path.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("gui.json");
        assert_eq!(Settings::load(&path), Settings::default());
        let s = Settings { oodle_dll: Some(PathBuf::from("C:/games/x/oo2core_9_win64.dll")) };
        s.save(&path).unwrap();
        assert_eq!(Settings::load(&path), s);
        fs::write(&path, "not json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
    }
}
