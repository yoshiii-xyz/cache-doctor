use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cache-doctor"))
}

fn temp_root(label: &str) -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("cache-doctor-cli-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn version_and_help_are_available() {
    let version = Command::new(binary()).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).contains("cache-doctor"));
    let help = Command::new(binary()).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("inspect"));
}

#[test]
fn inspect_json_and_offline_text_work() {
    let root = temp_root("flow");
    fs::write(
        root.join("Cargo.lock"),
        "[[package]]\nname = \"demo\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();
    let json = Command::new(binary())
        .args(["inspect", root.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(json.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(report["ecosystem"], "cargo");
    assert_eq!(report["offline"], false);
    let text = Command::new(binary())
        .args(["inspect", root.to_str().unwrap(), "--format", "text"])
        .output()
        .unwrap();
    assert!(text.status.success());
    assert!(String::from_utf8_lossy(&text.stdout).contains("complete:"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn missing_cargo_home_returns_report_not_panic() {
    let root = temp_root("missing");
    let output = Command::new(binary())
        .args(["inspect", root.join("missing").to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["complete"], false);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn cargo_offline_scan_does_not_need_path_helpers() {
    let root = temp_root("offline");
    let output = Command::new(binary())
        .env("CARGO_HOME", &root)
        .env("HOME", &root)
        .env("PATH", root.join("empty-path"))
        .args(["cargo", "--offline"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["offline"], true);
    assert_eq!(report["complete"], true);
    fs::remove_dir_all(root).unwrap();
}
