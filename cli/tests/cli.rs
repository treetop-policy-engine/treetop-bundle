use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[test]
fn check_policy_reports_valid_json_and_exit_zero() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = temporary.path().join("policy.cedar");
    write(&policy, "permit(principal, action, resource);\n");

    let output = run(["check", "policy", path(&policy), "--format", "json"]);

    assert!(output.status.success(), "{}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["valid"], true);
    assert_eq!(value["diagnostics"], serde_json::json!([]));
}

#[test]
fn check_policy_emits_structured_diagnostics_and_exit_one() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = temporary.path().join("invalid.cedar");
    write(&policy, "this is not Cedar\n");

    let output = run(["check", "policy", path(&policy), "--format", "json"]);

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["valid"], false);
    assert_eq!(value["diagnostics"][0]["code"], "policy.syntax");
    assert!(value["diagnostics"][0]["line"].is_null());
}

#[test]
fn deny_warnings_changes_a_schema_free_label_check_to_exit_one() {
    let temporary = tempfile::tempdir().unwrap();
    let policy = temporary.path().join("policy.cedar");
    let labels = temporary.path().join("labels.json");
    write(&policy, "permit(principal, action, resource);\n");
    write(
        &labels,
        r#"[{"kind":"App::Host","field":"name","output":"labels","patterns":[{"name":"prod","regex":"^prod"}]}]"#,
    );

    let output = run([
        "check",
        "policy",
        path(&policy),
        "--labels",
        path(&labels),
        "--deny-warnings",
        "--format",
        "json",
    ]);

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["valid"], false);
    assert_eq!(
        value["diagnostics"][0]["code"],
        "labels.schema_check_skipped"
    );
}

#[test]
fn missing_input_is_a_filesystem_exit_two() {
    let output = run(["check", "policy", "definitely-missing.cedar"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("filesystem error"));
}

#[test]
fn build_emits_structured_content_errors_and_exit_one() {
    let temporary = tempfile::tempdir().unwrap();
    let manifest = temporary.path().join("treetop-bundle.toml");
    let output_path = temporary.path().join("bundle.tar.gz");
    write(
        &manifest,
        "format_version = 1\nname = \"broken\"\nunknown = true\n",
    );

    let output = run([
        "build",
        "--manifest",
        path(&manifest),
        "--output",
        path(&output_path),
        "--format",
        "json",
    ]);

    assert_eq!(output.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["valid"], false);
    assert_eq!(value["diagnostics"][0]["code"], "bundle.invalid_content");
    assert!(!output_path.exists());
}

fn run<const N: usize>(args: [&str; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_treetop-bundle"))
        .args(args)
        .output()
        .unwrap()
}

fn path(path: &Path) -> &str {
    path.to_str().unwrap()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write(path: impl Into<PathBuf>, content: &str) {
    fs::write(path.into(), content).unwrap();
}
