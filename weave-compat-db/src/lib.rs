//! weave-compat-db — Compatibility Database for Weave
//!
//! Tracks application compatibility, import tables, and user reports.
//! Supports both local database and crowd-sourced reporting.

// Type alias for Result
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

// ── Data Models ─────────────────────────────────────────────────────────

// Application identity
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AppIdentity {
    pub name: String,
    pub version: Option<String>,
    pub pe_hash: Option<String>, // SHA256 of the PE file
}

// Compatibility status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CompatibilityStatus {
    Working,      // Fully functional
    Partial,      // Works with limitations
    Broken,       // Doesn't work
    Untested,     // Not tested yet
}

// Import table entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ImportEntry {
    pub dll: String,
    pub function: String,
}

// Configuration requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub prefix_settings: HashMap<String, String>,
    pub environment_variables: HashMap<String, String>,
    pub workarounds: Vec<String>,
}

// User report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserReport {
    pub user_id: Option<String>, // Anonymous if None
    pub timestamp: u64,
    pub status: CompatibilityStatus,
    pub notes: String,
    pub rating: Option<u8>, // 1-5 stars
}

// Application record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRecord {
    pub identity: AppIdentity,
    pub import_table: HashSet<ImportEntry>,
    pub status: CompatibilityStatus,
    pub config: AppConfig,
    pub reports: Vec<UserReport>,
    pub last_updated: u64,
    pub test_count: u32,
}

// ── Database ───────────────────────────────────────────────────────────

/// Compatibility database
#[derive(Debug)]
pub struct CompatDatabase {
    records: HashMap<AppIdentity, AppRecord>,
    db_path: PathBuf,
}

impl CompatDatabase {
    /// Create a new database instance
    pub fn new(db_path: PathBuf) -> Self {
        Self {
            records: HashMap::new(),
            db_path,
        }
    }

    /// Load database from disk
    pub fn load(db_path: PathBuf) -> Result<Self> {
        let mut db = Self::new(db_path.clone());

        if db_path.exists() {
            let data = fs::read_to_string(&db_path)?;
            let records: Vec<AppRecord> = serde_json::from_str(&data)?;
            for record in records {
                db.records.insert(record.identity.clone(), record);
            }
        }

        Ok(db)
    }

    /// Save database to disk
    pub fn save(&self) -> Result<()> {
        let records: Vec<&AppRecord> = self.records.values().collect();
        let data = serde_json::to_string_pretty(&records)?;
        fs::write(&self.db_path, data)?;
        Ok(())
    }

    /// Add or update an application record
    pub fn update_app(&mut self, record: AppRecord) {
        self.records.insert(record.identity.clone(), record);
    }

    /// Get application record by identity
    pub fn get_app(&self, identity: &AppIdentity) -> Option<&AppRecord> {
        self.records.get(identity)
    }

    /// Get all application records
    pub fn get_all_apps(&self) -> Vec<&AppRecord> {
        self.records.values().collect()
    }

    /// Add a user report for an application
    pub fn add_report(&mut self, identity: &AppIdentity, report: UserReport) -> Result<()> {
        if let Some(record) = self.records.get_mut(identity) {
            record.reports.push(report);
            record.test_count += 1;
            record.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            Ok(())
        } else {
            Err("Application not found".into())
        }
    }

    /// Report application import table (called on first launch)
    pub fn report_imports(&mut self, identity: AppIdentity, imports: HashSet<ImportEntry>) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();

        let record = AppRecord {
            identity: identity.clone(),
            import_table: imports,
            status: CompatibilityStatus::Untested,
            config: AppConfig {
                prefix_settings: HashMap::new(),
                environment_variables: HashMap::new(),
                workarounds: Vec::new(),
            },
            reports: Vec::new(),
            last_updated: timestamp,
            test_count: 0,
        };

        self.update_app(record);
        Ok(())
    }

    /// Update application status based on reports
    pub fn update_status(&mut self, identity: &AppIdentity, status: CompatibilityStatus) -> Result<()> {
        if let Some(record) = self.records.get_mut(identity) {
            record.status = status;
            record.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            Ok(())
        } else {
            Err("Application not found".into())
        }
    }

    /// Get applications that import a specific function
    pub fn get_apps_using_function(&self, dll: &str, function: &str) -> Vec<&AppRecord> {
        let target_import = ImportEntry {
            dll: dll.to_lowercase(),
            function: function.to_string(),
        };

        self.records.values()
            .filter(|record| record.import_table.contains(&target_import))
            .collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> CompatStats {
        let mut stats = CompatStats {
            total_apps: self.records.len(),
            working: 0,
            partial: 0,
            broken: 0,
            untested: 0,
            total_reports: 0,
        };

        for record in self.records.values() {
            match record.status {
                CompatibilityStatus::Working => stats.working += 1,
                CompatibilityStatus::Partial => stats.partial += 1,
                CompatibilityStatus::Broken => stats.broken += 1,
                CompatibilityStatus::Untested => stats.untested += 1,
            }
            stats.total_reports += record.reports.len();
        }

        stats
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct CompatStats {
    pub total_apps: usize,
    pub working: usize,
    pub partial: usize,
    pub broken: usize,
    pub untested: usize,
    pub total_reports: usize,
}

// ── Import Table Analysis ──────────────────────────────────────────────

/// Analyze a PE file's import table
pub fn analyze_imports(_pe_data: &[u8]) -> Result<HashSet<ImportEntry>> {
    // This would parse the PE import table
    // For now, return empty set - would be implemented with goblin or similar
    Ok(HashSet::new())
}

/// Generate application identity from PE file
pub fn identify_app(pe_data: &[u8], name_hint: Option<&str>) -> Result<AppIdentity> {
    // Calculate PE hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(pe_data);
    let hash = format!("{:x}", hasher.finalize());

    Ok(AppIdentity {
        name: name_hint.unwrap_or("Unknown").to_string(),
        version: None, // Would extract from PE version info
        pe_hash: Some(hash),
    })
}

// ── Integration with Weave CLI ────────────────────────────────────────

/// Report application launch to compatibility database
pub fn report_app_launch(db: &mut CompatDatabase, exe_path: &std::path::Path, exe_data: &[u8]) -> Result<()> {
    let app_name = exe_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("Unknown");

    let identity = identify_app(exe_data, Some(app_name))?;
    let imports = analyze_imports(exe_data)?;

    // Only report if we haven't seen this app before
    if db.get_app(&identity).is_none() {
        db.report_imports(identity, imports)?;
        db.save()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_app_identity() {
        let identity = AppIdentity {
            name: "test.exe".to_string(),
            version: Some("1.0.0".to_string()),
            pe_hash: Some("abcd1234".to_string()),
        };

        assert_eq!(identity.name, "test.exe");
        assert_eq!(identity.version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_database_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("compat.json");

        let mut db = CompatDatabase::new(db_path.clone());

        let identity = AppIdentity {
            name: "test.exe".to_string(),
            version: None,
            pe_hash: None,
        };

        let imports = HashSet::new();
        db.report_imports(identity.clone(), imports).unwrap();

        assert!(db.get_app(&identity).is_some());

        // Test save/load
        db.save().unwrap();
        let loaded_db = CompatDatabase::load(db_path).unwrap();
        assert!(loaded_db.get_app(&identity).is_some());
    }

    #[test]
    fn test_user_reports() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("compat.json");

        let mut db = CompatDatabase::new(db_path);

        let identity = AppIdentity {
            name: "test.exe".to_string(),
            version: None,
            pe_hash: None,
        };

        let imports = HashSet::new();
        db.report_imports(identity.clone(), imports).unwrap();

        let report = UserReport {
            user_id: Some("user123".to_string()),
            timestamp: 1234567890,
            status: CompatibilityStatus::Working,
            notes: "Works perfectly!".to_string(),
            rating: Some(5),
        };

        db.add_report(&identity, report).unwrap();

        let app = db.get_app(&identity).unwrap();
        assert_eq!(app.reports.len(), 1);
        assert_eq!(app.test_count, 1);
    }

    #[test]
    fn test_statistics() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("compat.json");

        let mut db = CompatDatabase::new(db_path);

        // Add a working app
        let identity1 = AppIdentity {
            name: "working.exe".to_string(),
            version: None,
            pe_hash: None,
        };
        db.report_imports(identity1.clone(), HashSet::new()).unwrap();
        db.update_status(&identity1, CompatibilityStatus::Working).unwrap();

        // Add a broken app
        let identity2 = AppIdentity {
            name: "broken.exe".to_string(),
            version: None,
            pe_hash: None,
        };
        db.report_imports(identity2.clone(), HashSet::new()).unwrap();
        db.update_status(&identity2, CompatibilityStatus::Broken).unwrap();

        let stats = db.get_stats();
        assert_eq!(stats.total_apps, 2);
        assert_eq!(stats.working, 1);
        assert_eq!(stats.broken, 1);
    }
}
