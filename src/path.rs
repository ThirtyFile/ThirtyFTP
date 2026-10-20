//! Paths in the session (RFC 959 section 2.3 "pathname").
//!
//! The backend never sees the text the client sent. A client's path is resolved against the current directory into an [`FtpPath`]: absolute,
//! with `.` and `..` resolved and no way above the root, and without control characters.

use std::fmt;

/// The longest path the library accepts, in bytes
const MAX_PATH_BYTES: usize = 4096;

/// An absolute, normalised path under the session's root. The root is `/`.
///
/// Every component is a non-empty name that is not `.` or `..`, and holds no control characters. The library checks nothing more: a backend
/// that maps names to a file system also has to refuse the names that file system treats specially (a backslash or a drive letter on Windows).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct FtpPath {
    components: Vec<String>,
}

/// Why a path from the client was refused
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PathError {
    /// A control character (NUL, CR, LF and the others below space, and DEL) is in the path
    #[error("the path holds a control character")]
    ControlCharacter,
    /// The path is longer than 4096 bytes
    #[error("the path is too long")]
    TooLong,
    /// A single name that is empty, `.`, `..`, or holds a `/`
    #[error("not a single name")]
    NotAName,
}

impl FtpPath {
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
