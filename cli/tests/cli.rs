use ed25519_dalek::pkcs8::EncodePrivateKey;
use pkcs8::{LineEnding, PrivateKeyInfo};
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

#[test]
fn signing_key_password_is_read_from_the_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let key = encrypted_key_file(temporary.path(), b"vault secret");
    let output_path = temporary.path().join("signed.tar.gz");

    let output = run_with_env(
        [
            "sign",
            "missing.tar.gz",
            "--signing-key",
            path(&key),
            "--output",
            path(&output_path),
        ],
        "TREETOP_BUNDLE_SIGNING_KEY_PASSWORD",
        "vault secret",
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("filesystem error"));
    assert!(!stderr(&output).contains("key error"));
}

#[test]
fn non_utf8_password_file_takes_precedence_over_the_environment() {
    let temporary = tempfile::tempdir().unwrap();
    let password = [0xff, 0xfe, b'x'];
    let key = encrypted_key_file(temporary.path(), &password);
    let password_file = temporary.path().join("password");
    fs::write(&password_file, [password.as_slice(), b"\r\n"].concat()).unwrap();
    let output_path = temporary.path().join("signed.tar.gz");

    let output = run_with_env(
        [
            "sign",
            "missing.tar.gz",
            "--signing-key",
            path(&key),
            "--signing-key-password-file",
            path(&password_file),
            "--output",
            path(&output_path),
        ],
        "TREETOP_BUNDLE_SIGNING_KEY_PASSWORD",
        "wrong environment secret",
    );

    assert_eq!(output.status.code(), Some(2));
    assert!(stderr(&output).contains("filesystem error"));
    assert!(!stderr(&output).contains("key error"));
}

fn run<const N: usize>(args: [&str; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_treetop-bundle"))
        .args(args)
        .output()
        .unwrap()
}

fn run_with_env<const N: usize>(args: [&str; N], name: &str, value: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_treetop-bundle"))
        .args(args)
        .env(name, value)
        .output()
        .unwrap()
}

fn encrypted_key_file(root: &Path, password: &[u8]) -> PathBuf {
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let der = key.to_pkcs8_der().unwrap();
    let private_key = PrivateKeyInfo::try_from(der.as_bytes()).unwrap();
    let parameters =
        pkcs8::pkcs5::pbes2::Parameters::pbkdf2_sha256_aes256cbc(2, &[3; 16], &[4; 16]).unwrap();
    let pem = private_key
        .encrypt_with_params(parameters, password)
        .unwrap();
    let pem = pem.to_pem("ENCRYPTED PRIVATE KEY", LineEnding::LF).unwrap();
    let path = root.join("private.pem");
    write(&path, &pem);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
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
