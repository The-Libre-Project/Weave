//! One-click install backend for Weave.
//!
//! Manages application prefixes (per-app isolated environments) and provides
//! the install orchestration model: fetch config → create prefix → ready to run.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Errors returned by weave-installer operations.
#[derive(Debug)]
pub enum InstallerError {
    Io(io::Error),
    /// A prefix with this name already exists.
    AlreadyExists(String),
    /// No prefix with this name was found.
    NotFound(String),
    /// The prefix directory or its config file is malformed.
    Corrupt(String),
}

impl From<io::Error> for InstallerError {
    fn from(e: io::Error) -> Self {
        InstallerError::Io(e)
    }
}

impl std::fmt::Display for InstallerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallerError::Io(e) => write!(f, "I/O error: {e}"),
            InstallerError::AlreadyExists(n) => write!(f, "prefix '{n}' already exists"),
            InstallerError::NotFound(n) => write!(f, "prefix '{n}' not found"),
            InstallerError::Corrupt(s) => write!(f, "corrupt prefix: {s}"),
        }
    }
}

/// A Weave application prefix — an isolated directory containing the virtual
/// drive layout, registry, and per-app config for one Windows application.
///
/// On-disk structure:
/// ```text
/// <base>/<name>/
///   prefix.toml      — config file
///   drive_c/         — virtual C: drive root
///   registry/        — registry hive files
/// ```
#[derive(Debug, Clone)]
pub struct Prefix {
    /// Human-readable identifier (e.g. `"notepad"`, `"my-game"`).
    pub name: String,
    /// Absolute path to the prefix root directory on disk.
    pub path: PathBuf,
}

impl Prefix {
    /// Returns the path to the prefix's virtual C: drive root.
    pub fn drive_c(&self) -> PathBuf {
        self.path.join("drive_c")
    }

    /// Returns the path to the prefix's registry directory.
    pub fn registry_dir(&self) -> PathBuf {
        self.path.join("registry")
    }

    /// Returns the path to the prefix's config file.
    pub fn config_path(&self) -> PathBuf {
        self.path.join("prefix.toml")
    }

    /// Returns `true` if the prefix directory exists on disk.
    pub fn exists(&self) -> bool {
        self.path.is_dir()
    }
}

/// Manages the lifecycle of Weave prefixes.
///
/// All prefixes live under a common base directory, defaulting to
/// `$XDG_DATA_HOME/weave/prefixes` or `~/.local/share/weave/prefixes`.
pub struct PrefixManager {
    base_dir: PathBuf,
}

impl PrefixManager {
    /// Creates a `PrefixManager` using the default XDG base directory.
    pub fn new() -> Result<Self, InstallerError> {
        let base = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|_| std::env::var("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .map_err(|_| {
                InstallerError::Io(io::Error::new(
                    io::ErrorKind::NotFound,
                    "could not determine home directory",
                ))
            })?;
        Ok(Self {
            base_dir: base.join("weave/prefixes"),
        })
    }

    /// Creates a `PrefixManager` rooted at a specific directory.
    ///
    /// Useful for tests and for future CLI `--prefix-dir` overrides.
    pub fn with_base(base_dir: impl Into<PathBuf>) -> Self {
        Self {
            base_dir: base_dir.into(),
        }
    }

    /// Returns the base directory for all prefixes managed by this instance.
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    /// Creates a new prefix with the given name.
    ///
    /// Returns [`InstallerError::AlreadyExists`] if a prefix with that name
    /// already exists.
    pub fn create(&self, name: &str) -> Result<Prefix, InstallerError> {
        let path = self.base_dir.join(name);
        if path.exists() {
            return Err(InstallerError::AlreadyExists(name.to_string()));
        }
        fs::create_dir_all(&path)?;
        fs::create_dir_all(path.join("drive_c"))?;
        fs::create_dir_all(path.join("registry"))?;
        let config = format!("# Weave prefix config\nname = \"{name}\"\nversion = \"1.0\"\n");
        fs::write(path.join("prefix.toml"), config)?;
        Ok(Prefix {
            name: name.to_string(),
            path,
        })
    }

    /// Lists all prefixes in the base directory.
    ///
    /// Returns an empty `Vec` if the base directory does not exist yet.
    pub fn list(&self) -> Result<Vec<Prefix>, InstallerError> {
        if !self.base_dir.exists() {
            return Ok(vec![]);
        }
        let mut prefixes = Vec::new();
        for entry in fs::read_dir(&self.base_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                prefixes.push(Prefix { name, path });
            }
        }
        Ok(prefixes)
    }

    /// Returns the prefix with the given name.
    ///
    /// Returns [`InstallerError::NotFound`] if no such prefix exists.
    pub fn get(&self, name: &str) -> Result<Prefix, InstallerError> {
        let path = self.base_dir.join(name);
        if !path.is_dir() {
            return Err(InstallerError::NotFound(name.to_string()));
        }
        Ok(Prefix {
            name: name.to_string(),
            path,
        })
    }

    /// Deletes a prefix and all its contents.
    ///
    /// Returns `Ok(())` if the prefix did not exist.
    pub fn delete(&self, name: &str) -> Result<(), InstallerError> {
        let path = self.base_dir.join(name);
        match fs::remove_dir_all(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(InstallerError::Io(e)),
        }
    }
}

/// An install configuration for a Windows application.
///
/// Describes how to set up a prefix for a specific app. In the full Phase 5
/// implementation this will be fetched from `weave-compat-db` by `app_id`.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// Unique identifier matching the compat-db entry (e.g. `"notepad-plus-plus"`).
    pub app_id: String,
    /// Human-readable display name shown in the GUI.
    pub display_name: String,
    /// Path to the main executable within the prefix's `drive_c`, once installed.
    pub exe_path: Option<PathBuf>,
    /// Extra environment variables to set when launching this app.
    pub env_vars: Vec<(String, String)>,
    /// Whether to force VM mode (via `weave-vm-fallback`) for this app.
    pub force_vm: bool,
}

impl AppConfig {
    /// Creates a minimal config with just an ID and name.
    pub fn new(app_id: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            display_name: display_name.into(),
            exe_path: None,
            env_vars: Vec::new(),
            force_vm: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_base(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("weave-installer-test-{label}"));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn test_create_builds_directory_structure() {
        let base = temp_base("create");
        let mgr = PrefixManager::with_base(&base);

        let prefix = mgr.create("test-app").expect("create failed");

        assert_eq!(prefix.name, "test-app");
        assert!(prefix.exists());
        assert!(prefix.drive_c().is_dir());
        assert!(prefix.registry_dir().is_dir());
        assert!(prefix.config_path().is_file());

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_list_returns_created_prefixes() {
        let base = temp_base("list");
        let mgr = PrefixManager::with_base(&base);

        mgr.create("alpha").expect("create alpha failed");
        mgr.create("beta").expect("create beta failed");

        let list = mgr.list().expect("list failed");
        assert_eq!(list.len(), 2);

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_create_duplicate_returns_already_exists() {
        let base = temp_base("dup");
        let mgr = PrefixManager::with_base(&base);

        mgr.create("app").expect("first create failed");
        let result = mgr.create("app");
        assert!(matches!(result, Err(InstallerError::AlreadyExists(_))));

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_list_empty_base_dir_returns_empty() {
        let base = temp_base("empty-list");
        let mgr = PrefixManager::with_base(&base);

        let list = mgr.list().expect("list on non-existent base failed");
        assert!(list.is_empty());
    }

    #[test]
    fn test_get_nonexistent_returns_not_found() {
        let base = temp_base("get");
        let mgr = PrefixManager::with_base(&base);

        let result = mgr.get("no-such-app-xyz");
        assert!(matches!(result, Err(InstallerError::NotFound(_))));
    }

    #[test]
    fn test_delete_nonexistent_is_ok() {
        let base = temp_base("delete");
        let mgr = PrefixManager::with_base(&base);

        assert!(mgr.delete("ghost").is_ok());
    }

    #[test]
    fn test_delete_removes_prefix() {
        let base = temp_base("delete-real");
        let mgr = PrefixManager::with_base(&base);

        mgr.create("app").expect("create failed");
        assert!(mgr.get("app").is_ok());

        mgr.delete("app").expect("delete failed");
        assert!(matches!(mgr.get("app"), Err(InstallerError::NotFound(_))));

        fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn test_app_config_new_defaults() {
        let cfg = AppConfig::new("notepad-plus-plus", "Notepad++");
        assert_eq!(cfg.app_id, "notepad-plus-plus");
        assert_eq!(cfg.display_name, "Notepad++");
        assert!(!cfg.force_vm);
        assert!(cfg.env_vars.is_empty());
        assert!(cfg.exe_path.is_none());
    }
}
