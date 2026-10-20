//! Paths in the session (RFC 959 section 2.3 "pathname").
//!
//! The backend never sees the text the client sent. A client's path is resolved against the current directory into an [`FtpPath`]: absolute,
//! with `.` and `..` resolved and no way above the root, and without control characters.

use std::fmt;
use std::path::{Path, PathBuf};

/// The longest path the library accepts, in bytes
const MAX_PATH_BYTES: usize = 4096;

/// An absolute, normalised path under the session's root. The root is `/`.
///
/// Every component is a non-empty name that is not `.` or `..`, and holds no control characters (the C0 and C1 controls and DEL). The path says
/// nothing more: a backend that maps names to a file system has to refuse the names that file system treats specially (a backslash or a drive letter
/// on Windows). [`FtpPath::to_native`] does that for a folder on disk.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FtpPath {
    components: Vec<String>,
}

/// Why a path from the client was refused
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PathError {
    /// A control character (NUL, CR, LF and the others below space, DEL and the C1 controls) is in the path
    #[error("the path holds a control character")]
    ControlCharacter,
    /// The path is longer than 4096 bytes
    #[error("the path is too long")]
    TooLong,
    /// A single name that is empty, `.`, `..`, or holds a `/`
    #[error("not a single name")]
    NotAName,
    /// A name that the file system of this system treats in its own way: see [`FtpPath::to_native`]
    #[error("the name is not safe on this system")]
    UnsafeName,
}

impl FtpPath {
    /// The place on disk of this path under `root`, for a backend that keeps its files in a folder.
    ///
    /// On Windows a name is refused when it holds a character that file system treats as more than a name (`\` and `:` start another folder or drive, and
    /// `* ? " < > |` are wildcards), when it ends with a dot or a space, or when it is the name of a device (`CON`, `PRN`, `AUX`, `NUL`, `COM1`
    /// to `COM9`, `LPT1` to `LPT9`, with any extension). Elsewhere every name is kept. A backend that shares its files with Windows computers can use
    /// [`FtpPath::to_portable`] to apply the rules of Windows everywhere.
    pub fn to_native(&self, root: &Path) -> Result<PathBuf, PathError> {
        self.locate(root, cfg!(windows))
    }

    /// Like [`FtpPath::to_native`], with the rules of Windows on every system
    pub fn to_portable(&self, root: &Path) -> Result<PathBuf, PathError> {
        self.locate(root, true)
    }

    fn locate(&self, root: &Path, strict: bool) -> Result<PathBuf, PathError> {
        let mut location = root.to_path_buf();
        for name in &self.components {
            if strict && !windows_safe(name) {
                return Err(PathError::UnsafeName);
            }
            location.push(name);
        }
        Ok(location)
    }

    /// The root, `/`
    pub fn root() -> FtpPath {
        FtpPath::default()
    }

    /// Resolves what the client sent against the current directory. A path that starts with `/` is absolute; `..` at the root stays at the root
    pub fn resolve(current: &FtpPath, requested: &str) -> Result<FtpPath, PathError> {
        if requested.len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        if requested.chars().any(|c| c.is_control()) {
            return Err(PathError::ControlCharacter);
        }
        let mut components = if requested.starts_with('/') { Vec::new() } else { current.components.clone() };
        for part in requested.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                name => components.push(name.to_string()),
            }
        }
        let path = FtpPath { components };
        if path.to_string().len() > MAX_PATH_BYTES {
            return Err(PathError::TooLong);
        }
        Ok(path)
    }

    /// The directory that holds this path, or the root for the root
    pub fn parent(&self) -> FtpPath {
        let mut components = self.components.clone();
        components.pop();
        FtpPath { components }
    }

    /// The path with one more name at the end. The name can't be empty, `.`, `..`, or hold a `/` or a control character
    pub fn join(&self, name: &str) -> Result<FtpPath, PathError> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(PathError::NotAName);
        }
        FtpPath::resolve(self, name)
    }

    /// The last name, or `None` for the root
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    /// The names from the root down
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// Whether this is the root
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }
}

/// Whether a name is only a name for the file system of Windows (see [`FtpPath::to_native`])
fn windows_safe(name: &str) -> bool {
    if name.chars().any(|c| matches!(c, '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|')) || name.ends_with(['.', ' ']) {
        return false;
    }
    // CON, CON.txt, con.tar.gz: the device, whatever follows the first dot
    let stem = name.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    let device = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((stem.starts_with("COM") || stem.starts_with("LPT")) && stem.len() == 4 && stem.as_bytes().get(3).is_some_and(|digit| digit.is_ascii_digit()));
    !device
}

impl fmt::Display for FtpPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.components.is_empty() {
            return f.write_str("/");
        }
        for component in &self.components {
            write!(f, "/{component}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolve(current: &str, requested: &str) -> Result<String, PathError> {
        let current = FtpPath::resolve(&FtpPath::root(), current).unwrap();
        FtpPath::resolve(&current, requested).map(|p| p.to_string())
    }

    #[test]
    fn absolute_and_relative() {
        assert_eq!(resolve("/a", "/b/c").unwrap(), "/b/c");
        assert_eq!(resolve("/a", "b/c").unwrap(), "/a/b/c");
        assert_eq!(resolve("/a/b", "").unwrap(), "/a/b");
        assert_eq!(resolve("/a", "/").unwrap(), "/");
    }

    #[test]
    fn dots_are_resolved() {
        assert_eq!(resolve("/a/b", "..").unwrap(), "/a");
        assert_eq!(resolve("/a/b", "../c/./d").unwrap(), "/a/c/d");
        assert_eq!(resolve("/", "a/../b").unwrap(), "/b");
        assert_eq!(resolve("/a", "b//c/").unwrap(), "/a/b/c");
    }

    #[test]
    fn nothing_goes_above_the_root() {
        assert_eq!(resolve("/a", "../../..").unwrap(), "/");
        assert_eq!(resolve("/", "..").unwrap(), "/");
        assert_eq!(resolve("/", "/../../etc/passwd").unwrap(), "/etc/passwd");
        assert_eq!(resolve("/", "a/../../..//b").unwrap(), "/b");
    }

    #[test]
    fn control_characters_are_refused() {
        for bad in ["a\0b", "a\rb", "a\nb", "a\x1bb", "a\x7fb", "\0"] {
            assert_eq!(resolve("/", bad), Err(PathError::ControlCharacter), "{bad:?}");
        }
    }

    #[test]
    fn a_long_path_is_refused() {
        assert_eq!(resolve("/", &"a".repeat(5000)), Err(PathError::TooLong));
        let long = "a".repeat(3000);
        let current = FtpPath::resolve(&FtpPath::root(), &long).unwrap();
        assert_eq!(FtpPath::resolve(&current, &long), Err(PathError::TooLong));
    }

    #[test]
    fn names_with_spaces_dots_and_unicode_are_kept() {
        assert_eq!(resolve("/", "My Scans/2026 .. x/\u{2026}/文件.pdf").unwrap(), "/My Scans/2026 .. x/\u{2026}/文件.pdf");
        assert_eq!(resolve("/", "...").unwrap(), "/...");
    }

    #[test]
    fn the_names_that_windows_treats_in_its_own_way() {
        for bad in [
            "a\\b",
            "..\\x",
            "C:",
            "c:x",
            "a:b",
            "a*",
            "a?",
            "a\"b",
            "a<b",
            "a>b",
            "a|b",
            "name.",
            "name ",
            "CON",
            "con",
            "Con.txt",
            "PRN",
            "aux.log",
            "NUL",
            "nul.tar.gz",
            "COM1",
            "com9.txt",
            "LPT1",
            "lpt9",
            "CONIN$",
            "CON .txt",
        ] {
            let path = FtpPath::resolve(&FtpPath::root(), bad).unwrap();
            assert_eq!(path.to_portable(Path::new("root")), Err(PathError::UnsafeName), "{bad:?}");
        }
        for good in [
            "scan.pdf",
            "My Scans",
            "2026-10-20 12.30.00.jpg",
            "COM",
            "COM10",
            "LPT",
            "console",
            "CONSOLE.txt",
            "a-b_c",
            "\u{6587}\u{4ef6}.pdf",
            ".hidden",
            "NULL",
            "AUXILIARY",
        ] {
            let path = FtpPath::resolve(&FtpPath::root(), good).unwrap();
            assert!(path.to_portable(Path::new("root")).is_ok(), "{good:?}");
        }
        // The same names are fine where the file system has no use for them, except on Windows itself
        let colon = FtpPath::resolve(&FtpPath::root(), "12:30.jpg").unwrap();
        assert_eq!(colon.to_native(Path::new("root")).is_ok(), !cfg!(windows));
    }

    #[test]
    fn a_path_is_placed_under_the_folder_and_cannot_leave_it() {
        let path = FtpPath::resolve(&FtpPath::root(), "/a/../../b/c.txt").unwrap();
        assert_eq!(path.to_native(Path::new("root")).unwrap(), Path::new("root").join("b").join("c.txt"));
        assert_eq!(FtpPath::root().to_native(Path::new("root")).unwrap(), Path::new("root"));
        // What the client wrote with backslashes is a name of one piece, refused as a whole where a backslash is a separator
        let sneaky = FtpPath::resolve(&FtpPath::root(), "..\\..\\evil.txt").unwrap();
        assert_eq!(sneaky.components().len(), 1);
        assert_eq!(sneaky.to_portable(Path::new("root")), Err(PathError::UnsafeName));
    }

    #[test]
    fn parent_join_and_name() {
        let path = FtpPath::resolve(&FtpPath::root(), "/a/b").unwrap();
        assert_eq!(path.parent().to_string(), "/a");
        assert_eq!(FtpPath::root().parent().to_string(), "/");
        assert_eq!(path.join("c").unwrap().to_string(), "/a/b/c");
        assert_eq!(path.join(".."), Err(PathError::NotAName));
        assert_eq!(path.join("x/y"), Err(PathError::NotAName));
        assert_eq!(path.join(""), Err(PathError::NotAName));
        assert_eq!(path.join("a\nb"), Err(PathError::ControlCharacter));
        assert_eq!(path.file_name(), Some("b"));
        assert_eq!(FtpPath::root().file_name(), None);
        assert!(FtpPath::root().is_root());
        assert_eq!(path.components(), ["a", "b"]);
    }
}
