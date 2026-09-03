//! Read-only evidence collection for offline Cargo cache diagnosis.
//!
//! The scanner never invokes Cargo, contacts a registry, or reads credential
//! values. It inspects filenames, bounded metadata files, lockfiles, and
//! artifact hashes, then reports what is present, absent, or unverifiable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_SCAN_FILES: usize = 512;
pub const MAX_ERRORS: usize = 32;
pub const MAX_FINDINGS: usize = 512;
pub const MAX_ARTIFACT_HASH_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_METADATA_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_REPORT_BYTES: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactObservation {
    pub path: String,
    pub package: String,
    pub version: String,
    pub bytes: u64,
    pub checksum_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockfileSummary {
    pub path: String,
    pub package_count: usize,
    pub missing_metadata: usize,
    pub missing_artifacts: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigSummary {
    pub source_replacement_detected: bool,
    pub credentials_file_present: bool,
    pub auth_assumptions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheReport {
    pub schema_version: u32,
    pub ecosystem: String,
    pub root: String,
    pub offline: bool,
    pub complete: bool,
    pub scan_count: usize,
    pub artifact_count: usize,
    pub metadata_record_count: usize,
    pub lockfile_package_count: usize,
    pub verified_artifact_count: usize,
    pub missing_artifact_count: usize,
    pub artifacts: Vec<ArtifactObservation>,
    pub lockfile: Option<LockfileSummary>,
    pub config: ConfigSummary,
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanOptions {
    pub offline: bool,
}

/// Inspect a Cargo home or a deliberately constructed cache fixture.
pub fn inspect_cache(root: &Path, options: &ScanOptions) -> CacheReport {
    let mut state = ScanState::new(root, options);
    if !root.exists() {
        push_error(
            &mut state.errors,
            format!("cache root {} does not exist", display_path(root)),
        );
    } else if !root.is_dir() {
        push_error(
            &mut state.errors,
            format!("cache root {} is not a directory", display_path(root)),
        );
    } else {
        scan_directory(root, Path::new(""), &mut state);
    }
    finalize_report(state)
}

/// Locate the configured local Cargo home and inspect it without network use.
pub fn inspect_cargo_home(options: &ScanOptions) -> CacheReport {
    let root = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .unwrap_or_else(|| PathBuf::from(".cargo"));
    inspect_cache(&root, options)
}

/// Serialize a report with a hard output bound.
pub fn report_json(report: &CacheReport) -> Result<String, String> {
    let rendered = serde_json::to_string(report).map_err(|error| error.to_string())?;
    if rendered.len() > MAX_REPORT_BYTES {
        return Err(format!(
            "report is {} bytes, maximum is {} bytes",
            rendered.len(),
            MAX_REPORT_BYTES
        ));
    }
    Ok(rendered)
}

/// Render a concise explanation without rereading the cache.
pub fn explain_report(report: &CacheReport) -> String {
    let mut lines = vec![
        format!("root: {}", report.root),
        format!("offline: {}", report.offline),
        format!("complete: {}", report.complete),
        format!("scanned: {}", report.scan_count),
        format!("artifacts: {}", report.artifact_count),
        format!("metadata records: {}", report.metadata_record_count),
        format!("lockfile packages: {}", report.lockfile_package_count),
        format!("verified artifacts: {}", report.verified_artifact_count),
        format!("missing artifacts: {}", report.missing_artifact_count),
        format!(
            "source replacement: {}",
            report.config.source_replacement_detected
        ),
        format!(
            "credentials file present: {}",
            report.config.credentials_file_present
        ),
    ];
    if !report.findings.is_empty() {
        lines.push("findings:".to_owned());
        lines.extend(
            report
                .findings
                .iter()
                .map(|finding| format!("- [{}] {}", finding.kind, finding.detail)),
        );
    }
    if !report.errors.is_empty() {
        lines.push("errors:".to_owned());
        lines.extend(report.errors.iter().map(|error| format!("- {error}")));
    }
    lines.join("\n")
}

#[derive(Debug, Clone)]
struct IndexRecord {
    checksum: Option<String>,
    yanked: bool,
}

#[derive(Debug, Clone)]
struct ArtifactPath {
    absolute: PathBuf,
    relative: String,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct LockedPackage {
    name: String,
    version: String,
}

struct ScanState<'a> {
    root: &'a Path,
    options: &'a ScanOptions,
    scan_count: usize,
    errors: Vec<String>,
    findings: Vec<Finding>,
    index_records: BTreeMap<(String, String), IndexRecord>,
    artifact_paths: Vec<ArtifactPath>,
    lockfile: Option<(String, Vec<LockedPackage>, Option<SystemTime>)>,
    config: ConfigSummary,
    index_mtimes: Vec<(String, Option<SystemTime>)>,
}

impl<'a> ScanState<'a> {
    fn new(root: &'a Path, options: &'a ScanOptions) -> Self {
        Self {
            root,
            options,
            scan_count: 0,
            errors: Vec::new(),
            findings: Vec::new(),
            index_records: BTreeMap::new(),
            artifact_paths: Vec::new(),
            lockfile: None,
            config: ConfigSummary {
                source_replacement_detected: false,
                credentials_file_present: false,
                auth_assumptions: Vec::new(),
            },
            index_mtimes: Vec::new(),
        }
    }
}

fn scan_directory(root: &Path, relative: &Path, state: &mut ScanState<'_>) {
    if state.scan_count >= MAX_SCAN_FILES {
        push_error(
            &mut state.errors,
            format!("scan exceeds {} filesystem entries", MAX_SCAN_FILES),
        );
        return;
    }
    let iterator = match fs::read_dir(root.join(relative)) {
        Ok(iterator) => iterator,
        Err(error) => {
            record_error(
                state,
                &format!("read_dir {}", relative_display(relative)),
                error,
            );
            return;
        }
    };
    let mut entries = Vec::new();
    for entry in iterator {
        match entry {
            Ok(entry) => entries.push(entry),
            Err(error) => record_error(state, "read_dir entry", error),
        }
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        if state.scan_count >= MAX_SCAN_FILES {
            push_error(
                &mut state.errors,
                format!("scan exceeds {} filesystem entries", MAX_SCAN_FILES),
            );
            return;
        }
        state.scan_count += 1;
        let child_relative = relative.join(entry.file_name());
        let child_absolute = root.join(&child_relative);
        let metadata = match fs::symlink_metadata(&child_absolute) {
            Ok(metadata) => metadata,
            Err(error) => {
                record_error(
                    state,
                    &format!("metadata {}", relative_display(&child_relative)),
                    error,
                );
                continue;
            }
        };
        if metadata.is_dir() {
            scan_directory(root, &child_relative, state);
        } else if metadata.is_file() {
            scan_file(root, &child_relative, &child_absolute, &metadata, state);
        }
    }
}

fn scan_file(
    root: &Path,
    relative: &Path,
    absolute: &Path,
    metadata: &Metadata,
    state: &mut ScanState<'_>,
) {
    let name = relative
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name == "credentials" || name == "credentials.toml" {
        state.config.credentials_file_present = true;
        return;
    }
    if name == "config" || name == "config.toml" {
        inspect_config(absolute, state);
        return;
    }
    if name == "Cargo.lock" && state.lockfile.is_none() {
        match read_bounded(absolute, MAX_METADATA_FILE_BYTES) {
            Ok(contents) => {
                let packages = parse_lockfile(&contents);
                state.lockfile = Some((
                    relative_display(relative),
                    packages,
                    metadata.modified().ok(),
                ));
            }
            Err(error) => record_error(
                state,
                &format!("read lockfile {}", relative_display(relative)),
                error,
            ),
        }
        return;
    }
    let relative_text = relative_display(relative);
    if name.ends_with(".crate") {
        state.artifact_paths.push(ArtifactPath {
            absolute: absolute.to_owned(),
            relative: relative_text,
            bytes: metadata.len(),
        });
        return;
    }
    if is_index_path(&relative_text) {
        inspect_index(absolute, &relative_text, state);
    }
    let _ = root;
}

fn inspect_config(path: &Path, state: &mut ScanState<'_>) {
    match read_bounded(path, MAX_METADATA_FILE_BYTES) {
        Ok(contents) => {
            if contents.contains("replace-with") || contents.contains("[source.") {
                state.config.source_replacement_detected = true;
            }
            if contents.contains("registry") || contents.contains("source") {
                let note = "registry or source configuration may require authentication; credential values were not read".to_owned();
                if !state.config.auth_assumptions.contains(&note) {
                    state.config.auth_assumptions.push(note);
                }
            }
        }
        Err(error) => record_error(state, &format!("read config {}", display_path(path)), error),
    }
}

fn inspect_index(path: &Path, relative: &str, state: &mut ScanState<'_>) {
    let modified = fs::symlink_metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok());
    state.index_mtimes.push((relative.to_owned(), modified));
    let contents = match read_bounded(path, MAX_METADATA_FILE_BYTES) {
        Ok(contents) => contents,
        Err(error) => {
            record_error(state, &format!("read index {relative}"), error);
            return;
        }
    };
    let mut parsed = 0usize;
    for line in contents.split(['\n', '\0']) {
        let Some(value) = parse_json_fragment(line) else {
            continue;
        };
        let Some(name) = value.get("name").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(version) = value.get("vers").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let checksum = value
            .get("cksum")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let yanked = value
            .get("yanked")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        state.index_records.insert(
            (name.to_owned(), version.to_owned()),
            IndexRecord { checksum, yanked },
        );
        parsed += 1;
    }
    if parsed == 0 && contents.contains('{') {
        add_finding(
            &mut state.findings,
            "malformed_metadata",
            format!("index file {relative} contained no readable package records"),
        );
    }
}

fn finalize_report(mut state: ScanState<'_>) -> CacheReport {
    let mut artifacts = Vec::new();
    for artifact in &state.artifact_paths {
        let filename = Path::new(&artifact.relative)
            .file_name()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_default();
        let matched = state
            .index_records
            .iter()
            .find(|((name, version), _)| format!("{name}-{version}.crate") == filename);
        let (package, version, checksum_status) = match matched {
            Some(((name, version), index)) => {
                let status = match bounded_hash(&artifact.absolute, artifact.bytes) {
                    Ok(actual) => match index.checksum.as_deref() {
                        Some(expected) if expected == actual => "verified".to_owned(),
                        Some(_) => {
                            add_finding(
                                &mut state.findings,
                                "checksum_mismatch",
                                format!(
                                    "artifact {} does not match index checksum",
                                    artifact.relative
                                ),
                            );
                            "checksum_mismatch".to_owned()
                        }
                        None => {
                            add_finding(
                                &mut state.findings,
                                "metadata_missing",
                                format!("index record for {} has no checksum", artifact.relative),
                            );
                            "metadata_missing".to_owned()
                        }
                    },
                    Err(HashError::SizeLimit) => {
                        add_finding(
                            &mut state.findings,
                            "hash_limit",
                            format!("artifact {} exceeds hash bound", artifact.relative),
                        );
                        "size_limit".to_owned()
                    }
                    Err(HashError::Io(error)) => {
                        add_finding(
                            &mut state.findings,
                            "artifact_unreadable",
                            format!("artifact {}: {error}", artifact.relative),
                        );
                        "unreadable".to_owned()
                    }
                };
                if index.yanked {
                    add_finding(
                        &mut state.findings,
                        "yanked_metadata",
                        format!("index marks {} {} as yanked", name, version),
                    );
                }
                (name.clone(), version.clone(), status)
            }
            None => {
                add_finding(
                    &mut state.findings,
                    "metadata_missing",
                    format!("no index metadata matches artifact {}", artifact.relative),
                );
                (String::new(), String::new(), "metadata_missing".to_owned())
            }
        };
        artifacts.push(ArtifactObservation {
            path: artifact.relative.clone(),
            package,
            version,
            bytes: artifact.bytes,
            checksum_status,
        });
    }
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));

    let mut missing_artifact_count = 0usize;
    let lockfile_summary = state.lockfile.as_ref().map(|(path, packages, mtime)| {
        let mut missing_metadata = 0usize;
        let mut missing_artifacts = 0usize;
        let artifact_keys = artifacts
            .iter()
            .filter(|artifact| !artifact.package.is_empty())
            .map(|artifact| (artifact.package.clone(), artifact.version.clone()))
            .collect::<BTreeSet<_>>();
        for package in packages {
            if !state
                .index_records
                .contains_key(&(package.name.clone(), package.version.clone()))
            {
                missing_metadata += 1;
                add_finding(
                    &mut state.findings,
                    "missing_transitive_metadata",
                    format!(
                        "lockfile package {} {} is absent from the index",
                        package.name, package.version
                    ),
                );
            }
            if !artifact_keys.contains(&(package.name.clone(), package.version.clone())) {
                missing_artifacts += 1;
                add_finding(
                    &mut state.findings,
                    "artifact_missing",
                    format!(
                        "lockfile package {} {} has no cached artifact",
                        package.name, package.version
                    ),
                );
            }
        }
        missing_artifact_count = missing_artifacts;
        for (index_path, index_mtime) in &state.index_mtimes {
            if let (Some(index_mtime), Some(lock_mtime)) = (index_mtime, mtime) {
                if index_mtime < lock_mtime {
                    add_finding(
                        &mut state.findings,
                        "stale_index",
                        format!("index file {index_path} predates the lockfile"),
                    );
                }
            }
        }
        LockfileSummary {
            path: path.clone(),
            package_count: packages.len(),
            missing_metadata,
            missing_artifacts,
        }
    });

    let verified_artifact_count = artifacts
        .iter()
        .filter(|artifact| artifact.checksum_status == "verified")
        .count();
    if state.config.source_replacement_detected && !state.config.credentials_file_present {
        add_finding(
            &mut state.findings,
            "authentication_assumption",
            "source replacement is configured but no credentials file is present; values were not read".to_owned(),
        );
    }
    state.findings.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then(left.detail.cmp(&right.detail))
    });
    state.errors.sort();
    let mut notes = vec![
        "no network, Cargo command, registry login, or package installation was performed"
            .to_owned(),
        format!(
            "artifact hashes are checked only up to {} bytes",
            MAX_ARTIFACT_HASH_BYTES
        ),
        "credential file presence is recorded without reading credential values".to_owned(),
    ];
    if state.options.offline {
        notes.push(
            "offline mode was selected by the operator; the scanner itself never uses the network"
                .to_owned(),
        );
    }
    let complete = state.errors.is_empty();
    CacheReport {
        schema_version: SCHEMA_VERSION,
        ecosystem: "cargo".to_owned(),
        root: display_path(state.root),
        offline: state.options.offline,
        complete,
        scan_count: state.scan_count,
        artifact_count: artifacts.len(),
        metadata_record_count: state.index_records.len(),
        lockfile_package_count: lockfile_summary
            .as_ref()
            .map(|lockfile| lockfile.package_count)
            .unwrap_or(0),
        verified_artifact_count,
        missing_artifact_count,
        artifacts,
        lockfile: lockfile_summary,
        config: state.config,
        findings: state.findings,
        errors: state.errors,
        notes,
    }
}

fn parse_lockfile(contents: &str) -> Vec<LockedPackage> {
    let mut packages = Vec::new();
    let mut name = None;
    let mut version = None;
    for line in contents.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            if let (Some(name), Some(version)) = (name.take(), version.take()) {
                packages.push(LockedPackage { name, version });
            }
        } else if let Some(value) = parse_toml_string(line, "name") {
            name = Some(value);
        } else if let Some(value) = parse_toml_string(line, "version") {
            version = Some(value);
        }
    }
    if let (Some(name), Some(version)) = (name, version) {
        packages.push(LockedPackage { name, version });
    }
    packages.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then(left.version.cmp(&right.version))
    });
    packages
}

fn parse_toml_string(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key} = \"");
    line.strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
}

fn parse_json_fragment(line: &str) -> Option<serde_json::Value> {
    let start = line.find('{')?;
    let end = line.rfind('}')?;
    if end < start {
        return None;
    }
    serde_json::from_str(&line[start..=end]).ok()
}

fn is_index_path(relative: &str) -> bool {
    relative.starts_with("index/")
        || relative.contains("/index/")
        || relative.starts_with(".cache/")
        || relative.contains("/.cache/")
}

fn read_bounded(path: &Path, limit: u64) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {} byte bound", limit),
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[derive(Debug)]
enum HashError {
    SizeLimit,
    Io(io::Error),
}

fn bounded_hash(path: &Path, size: u64) -> Result<String, HashError> {
    if size > MAX_ARTIFACT_HASH_BYTES {
        return Err(HashError::SizeLimit);
    }
    let mut file = File::open(path).map_err(HashError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total = 0u64;
    loop {
        let read = file.read(&mut buffer).map_err(HashError::Io)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_ARTIFACT_HASH_BYTES {
            return Err(HashError::SizeLimit);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn record_error(state: &mut ScanState<'_>, operation: &str, error: io::Error) {
    push_error(&mut state.errors, format!("{operation}: {error}"));
}

fn push_error(errors: &mut Vec<String>, error: String) {
    if errors.len() < MAX_ERRORS {
        errors.push(error);
    }
}

fn add_finding(findings: &mut Vec<Finding>, kind: &str, detail: String) {
    if findings.len() < MAX_FINDINGS {
        findings.push(Finding {
            kind: kind.to_owned(),
            detail,
        });
    }
}

fn display_path(path: &Path) -> String {
    let rendered = path.to_string_lossy().replace('\\', "/");
    if rendered.is_empty() {
        ".".to_owned()
    } else {
        rendered
    }
}

fn relative_display(path: &Path) -> String {
    display_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    fn temp_root(label: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("cache-doctor-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn package_lock(name: &str, version: &str) -> String {
        format!("[[package]]\nname = \"{name}\"\nversion = \"{version}\"\n")
    }

    fn setup_artifact(root: &Path, contents: &[u8], checksum: Option<&str>) {
        let cache = root.join("registry/cache");
        let index = root.join("registry/index");
        fs::create_dir_all(&cache).unwrap();
        fs::create_dir_all(&index).unwrap();
        let artifact = cache.join("demo-1.0.0.crate");
        fs::write(&artifact, contents).unwrap();
        let actual = bounded_hash(&artifact, contents.len() as u64).unwrap();
        let checksum = checksum.unwrap_or(&actual);
        let record = format!(
            "{{\"name\":\"demo\",\"vers\":\"1.0.0\",\"cksum\":\"{checksum}\",\"yanked\":false}}\n"
        );
        fs::write(index.join("demo"), record).unwrap();
        fs::write(root.join("Cargo.lock"), package_lock("demo", "1.0.0")).unwrap();
    }

    #[test]
    fn complete_offline_cache_is_verified() {
        let root = temp_root("complete");
        setup_artifact(&root, b"crate", None);
        let report = inspect_cache(&root, &ScanOptions { offline: true });
        assert!(report.complete);
        assert!(report.offline);
        assert_eq!(report.verified_artifact_count, 1);
        assert_eq!(report.missing_artifact_count, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn artifact_without_metadata_is_reported() {
        let root = temp_root("artifact-only");
        fs::create_dir_all(root.join("registry/cache")).unwrap();
        fs::write(root.join("registry/cache/demo-1.0.0.crate"), b"crate").unwrap();
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == "metadata_missing")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn metadata_without_artifact_is_reported() {
        let root = temp_root("metadata-only");
        fs::create_dir_all(root.join("registry/index")).unwrap();
        fs::write(
            root.join("registry/index/demo"),
            b"{\"name\":\"demo\",\"vers\":\"1.0.0\",\"cksum\":\"abc\"}\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), package_lock("demo", "1.0.0")).unwrap();
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == "artifact_missing")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wrong_checksum_is_reported() {
        let root = temp_root("wrong-checksum");
        setup_artifact(&root, b"crate", Some(&"0".repeat(64)));
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == "checksum_mismatch")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_source_does_not_read_credentials() {
        let root = temp_root("private");
        fs::create_dir_all(root.join(".cargo")).unwrap();
        fs::write(
            root.join(".cargo/config.toml"),
            b"[source.crates-io]\nreplace-with = \"private\"\n[source.private]\nregistry = \"https://example.invalid\"\n",
        )
        .unwrap();
        fs::write(root.join("credentials.toml"), b"token = \"secret\"\n").unwrap();
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(report.config.source_replacement_detected);
        assert!(report.config.credentials_file_present);
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.detail.contains("secret"))
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_index_is_reported_against_newer_lockfile() {
        let root = temp_root("stale");
        fs::create_dir_all(root.join("registry/index")).unwrap();
        fs::write(
            root.join("registry/index/demo"),
            b"{\"name\":\"demo\",\"vers\":\"1.0.0\",\"cksum\":\"abc\"}\n",
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        fs::write(root.join("Cargo.lock"), package_lock("demo", "1.0.0")).unwrap();
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == "stale_index")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_cache_file_is_reported() {
        let root = temp_root("malformed");
        fs::create_dir_all(root.join("registry/index")).unwrap();
        fs::write(root.join("registry/index/bad"), b"{not valid metadata}\n").unwrap();
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.kind == "malformed_metadata")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_bound_and_report_are_deterministic() {
        let root = temp_root("deterministic");
        fs::create_dir_all(root.join("registry/cache")).unwrap();
        fs::write(root.join("registry/cache/a-1.0.0.crate"), b"a").unwrap();
        let first = inspect_cache(&root, &ScanOptions::default());
        let second = inspect_cache(&root, &ScanOptions::default());
        assert_eq!(first, second);
        assert!(report_json(&first).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scan_bound_is_reported() {
        let root = temp_root("bound");
        fs::create_dir_all(root.join("registry/cache")).unwrap();
        for index in 0..=MAX_SCAN_FILES {
            fs::write(
                root.join("registry/cache")
                    .join(format!("entry-{index}.crate")),
                b"x",
            )
            .unwrap();
        }
        let report = inspect_cache(&root, &ScanOptions::default());
        assert!(!report.complete);
        assert!(
            report
                .errors
                .iter()
                .any(|error| error.contains("scan exceeds"))
        );
        fs::remove_dir_all(root).unwrap();
    }
}
