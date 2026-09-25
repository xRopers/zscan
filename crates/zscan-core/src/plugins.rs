//! Optional codecs.
//!
//! - LZO (cargo feature `lzo`) is compiled in: a decoder written here, and the `lzo1x`
//!   crate's port of liblzo for encoding.
//! - Oodle (cargo feature `oodle`) is closed source, so zscan never includes it. It loads
//!   the user's own oo2core library at run time, from [`set_oodle_dll`] (the front ends'
//!   `--oodle-dll`) or the `ZSCAN_OODLE_DLL` environment variable.
//!
//! [`Format::Lzo`], [`Format::Oodle`], their encoder settings and this module exist in
//! every build, so a manifest always parses, and a build without a feature can say
//! what's missing instead of failing on an unknown name.

use std::path::PathBuf;
use std::sync::Mutex;

use crate::codec::{Codec, Format};

/// Environment variable naming the oo2core library, when [`set_oodle_dll`] wasn't called.
pub const OODLE_DLL_ENV: &str = "ZSCAN_OODLE_DLL";

/// A format this build or configuration can't handle, and how to fix that.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{format} support is unavailable: {reason}")]
pub struct Unavailable {
    pub format: Format,
    pub reason: String,
}

static OODLE_DLL: Mutex<Option<PathBuf>> = Mutex::new(None);

/// Load Oodle from this oo2core library rather than the one `ZSCAN_OODLE_DLL` names.
/// `None` goes back to the environment variable. A library already loaded stays loaded;
/// the next Oodle use loads the new one.
pub fn set_oodle_dll(path: Option<PathBuf>) {
    *OODLE_DLL.lock().unwrap_or_else(|e| e.into_inner()) = path;
}

/// The oo2core library to load: the one given to [`set_oodle_dll`], else `ZSCAN_OODLE_DLL`.
pub fn oodle_dll_path() -> Option<PathBuf> {
    let set = OODLE_DLL.lock().unwrap_or_else(|e| e.into_inner()).clone();
    set.or_else(|| std::env::var_os(OODLE_DLL_ENV).filter(|v| !v.is_empty()).map(PathBuf::from))
}

/// What to tell a user who hasn't said where their oo2core library is.
pub const NO_OODLE_DLL: &str = "no Oodle library given. zscan doesn't include Oodle: pass \
    --oodle-dll <path to oo2core_*.dll> or set ZSCAN_OODLE_DLL, using the copy that came with \
    the game or SDK the file is from";

#[cfg_attr(all(feature = "lzo", feature = "oodle"), allow(dead_code))]
fn not_built(format: Format) -> Unavailable {
    Unavailable { format, reason: format!("this zscan was built without it (rebuild with `--features {format}`)") }
}

pub(crate) fn lzo() -> Result<&'static dyn Codec, Unavailable> {
    #[cfg(feature = "lzo")]
    return Ok(&crate::codecs::lzo::LzoCodec);
    #[cfg(not(feature = "lzo"))]
    Err(not_built(Format::Lzo))
}

pub(crate) fn oodle() -> Result<&'static dyn Codec, Unavailable> {
    #[cfg(feature = "oodle")]
    return crate::codecs::oodle::codec()
        .map(|c| c as &dyn Codec)
        .map_err(|reason| Unavailable { format: Format::Oodle, reason });
    #[cfg(not(feature = "oodle"))]
    Err(not_built(Format::Oodle))
}
