//! Project files: the input file, its manifest and the edits, saved together so work can
//! be picked up later. Paths inside the project's folder are stored relative to it, so
//! a project folder can be moved as a whole.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};
use zscan_core::Manifest;

pub const PROJECT_VERSION: u32 = 1;
pub const EXTENSION: &str = "zscan";

#[derive(Debug, Clone, PartialEq)]
pub struct Project {
    pub input: PathBuf,
    pub manifest: Manifest,
    /// Stream id -> file with its new contents.
    pub edits: BTreeMap<u32, PathBuf>,
}

/// On-disk form. The manifest goes through [`Manifest::from_json`] so old manifest
/// versions are migrated.
#[derive(Serialize, Deserialize)]
struct ProjectFile {
    zscan_project: u32,
    input: PathBuf,
    manifest: serde_json::Value,
    #[serde(default)]
    edits: BTreeMap<u32, PathBuf>,
}

impl Project {
    pub fn save(&self, path: &Path) -> Result<()> {
        let base = path.parent().unwrap_or(Path::new(""));
        let file = ProjectFile {
            zscan_project: PROJECT_VERSION,
            input: relative_to(base, &self.input),
            manifest: serde_json::to_value(&self.manifest)?,
            edits: self.edits.iter().map(|(&id, p)| (id, relative_to(base, p))).collect(),
        };
        let text = serde_json::to_string_pretty(&file)? + "\n";
        std::fs::write(path, text).with_context(|| path.display().to_string())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let file: ProjectFile = serde_json::from_str(&text).with_context(|| format!("{} is not a zscan project", path.display()))?;
        if file.zscan_project != PROJECT_VERSION {
            bail!("project version {} is not supported (this build reads {PROJECT_VERSION})", file.zscan_project);
        }
        let base = path.parent().unwrap_or(Path::new(""));
        Ok(Self {
            input: base.join(file.input),
            manifest: Manifest::from_json(&file.manifest.to_string())?,
            edits: file.edits.into_iter().map(|(id, p)| (id, base.join(p))).collect(),
        })
    }
}

/// `path` relative to `base` if it is inside it, else unchanged.
fn relative_to(base: &Path, path: &Path) -> PathBuf {
    match path.strip_prefix(base) {
        Ok(rel) if !base.as_os_str().is_empty() => rel.to_path_buf(),
        _ => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zscan_core::{ScanOptions, SourceInfo};

    #[test]
    fn round_trip_with_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("game.pak");
        let outside = std::env::temp_dir().join("elsewhere.bin");
        let manifest = Manifest::new(SourceInfo::describe(&input, b"abc"), ScanOptions::default(), vec![]);
        let project = Project {
            input: input.clone(),
            manifest,
            edits: BTreeMap::from([(3, dir.path().join("edits").join("a.txt")), (7, outside.clone())]),
        };
        let path = dir.path().join("p.zscan");
        project.save(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        let raw: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(raw["input"], "game.pak", "inside the project folder: relative");
        assert_eq!(raw["edits"]["7"], outside.display().to_string(), "outside it: absolute");

        assert_eq!(Project::load(&path).unwrap(), project);
    }

    #[test]
    fn rejects_other_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.zscan");
        std::fs::write(&path, "{\"version\": 2}").unwrap();
        assert!(Project::load(&path).unwrap_err().to_string().contains("not a zscan project"));
    }
}
