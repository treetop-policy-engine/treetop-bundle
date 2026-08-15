use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, BundleError, Diagnostic, DiagnosticSeverity,
    SignaturePolicy, SigningKey, TrustStore, TrustedKey, check_module, check_policy,
};

#[derive(Debug, Parser)]
#[command(version, about = "Compile, validate, and sign Treetop policy bundles")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Check(CheckArgs),
    Build(BuildArgs),
    Sign(SignArgs),
}

#[derive(Debug, Args)]
struct CheckArgs {
    #[command(subcommand)]
    target: CheckTarget,
}

#[derive(Debug, Subcommand)]
enum CheckTarget {
    Policy(CheckPolicyArgs),
    Module(CheckModuleArgs),
    Bundle(CheckBundleArgs),
    Archive(CheckArchiveArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignaturePolicyArg {
    AllowUnsigned,
    Required,
}

impl From<SignaturePolicyArg> for SignaturePolicy {
    fn from(value: SignaturePolicyArg) -> Self {
        match value {
            SignaturePolicyArg::AllowUnsigned => Self::AllowUnsigned,
            SignaturePolicyArg::Required => Self::Required,
        }
    }
}

#[derive(Debug, Clone, Copy, Args)]
struct CommonCheckArgs {
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(Debug, Args)]
struct CheckPolicyArgs {
    file: PathBuf,
    #[arg(long)]
    schema: Option<PathBuf>,
    #[arg(long)]
    labels: Option<PathBuf>,
    #[command(flatten)]
    common: CommonCheckArgs,
}

#[derive(Debug, Args)]
struct CheckModuleArgs {
    manifest: PathBuf,
    #[command(flatten)]
    common: CommonCheckArgs,
}

#[derive(Debug, Args)]
struct CheckBundleArgs {
    manifest: PathBuf,
    #[command(flatten)]
    common: CommonCheckArgs,
}

#[derive(Debug, Args)]
struct CheckArchiveArgs {
    archive: PathBuf,
    #[arg(long = "trusted-key")]
    trusted_keys: Vec<PathBuf>,
    #[arg(long, value_enum, default_value = "allow-unsigned")]
    signature_policy: SignaturePolicyArg,
    #[command(flatten)]
    common: CommonCheckArgs,
}

#[derive(Debug, Args)]
struct BuildArgs {
    #[arg(long)]
    manifest: PathBuf,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    signing_key: Option<PathBuf>,
    #[arg(long, value_enum, default_value = "human")]
    format: OutputFormat,
    #[arg(long)]
    deny_warnings: bool,
}

#[derive(Debug, Args)]
struct SignArgs {
    archive: PathBuf,
    #[arg(long)]
    signing_key: PathBuf,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Serialize)]
struct CommandOutput<'a> {
    valid: bool,
    diagnostics: &'a [Diagnostic],
    #[serde(skip_serializing_if = "Option::is_none")]
    bundle_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    archive_sha256: Option<&'a str>,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            if error.is_validation() {
                ExitCode::from(1)
            } else {
                ExitCode::from(2)
            }
        }
    }
}

fn run(cli: Cli) -> Result<(), BundleError> {
    match cli.command {
        Command::Check(args) => run_check(args),
        Command::Build(args) => run_build(args),
        Command::Sign(args) => run_sign(args),
    }
}

fn run_check(args: CheckArgs) -> Result<(), BundleError> {
    match args.target {
        CheckTarget::Policy(args) => {
            let policy = read_string(&args.file)?;
            let schema = args.schema.as_deref().map(read_string).transpose()?;
            let labels = args.labels.as_deref().map(read_string).transpose()?;
            let checked = check_policy(&policy, schema.as_deref(), labels.as_deref())?;
            render_check(args.common, checked.diagnostics(), None, None)
        }
        CheckTarget::Module(args) => render_policy_check(args.common, check_module(&args.manifest)),
        CheckTarget::Bundle(args) => {
            let checked =
                BundleBuilder::from_manifest(&args.manifest).and_then(|builder| builder.check());
            render_policy_check(args.common, checked)
        }
        CheckTarget::Archive(args) => {
            let trust_store = load_trust_store(&args.trusted_keys)?;
            let validated =
                BundleArchive::read(&args.archive, ArchiveLimits::DEFAULT_MAX_COMPRESSED_BYTES)
                    .and_then(|archive| {
                        archive.validate(
                            args.signature_policy.into(),
                            &trust_store,
                            ArchiveLimits::default(),
                        )
                    });
            match validated {
                Ok(validated) => render_check(
                    args.common,
                    validated.diagnostics(),
                    Some(validated.bundle_id()),
                    Some(validated.archive_sha256()),
                ),
                Err(error) => render_content_error(args.common, error),
            }
        }
    }
}

fn render_policy_check(
    common: CommonCheckArgs,
    result: Result<treetop_bundle::PolicyCheck, BundleError>,
) -> Result<(), BundleError> {
    match result {
        Ok(checked) => render_check(common, checked.diagnostics(), None, None),
        Err(error) => render_content_error(common, error),
    }
}

fn render_content_error(common: CommonCheckArgs, error: BundleError) -> Result<(), BundleError> {
    if !error.is_validation() {
        return Err(error);
    }
    let diagnostics = match error {
        BundleError::Validation(diagnostics) => diagnostics,
        other => vec![Diagnostic {
            severity: DiagnosticSeverity::Error,
            code: "bundle.invalid_content".to_string(),
            module: None,
            path: None,
            line: None,
            column: None,
            message: other.to_string(),
        }],
    };
    render_check(common, &diagnostics, None, None)
}

fn run_build(args: BuildArgs) -> Result<(), BundleError> {
    refuse_overwrite(&args.output)?;
    let signing_key = args
        .signing_key
        .as_deref()
        .map(SigningKey::from_pkcs8_pem_file)
        .transpose()?;
    let common = CommonCheckArgs {
        format: args.format,
        deny_warnings: args.deny_warnings,
    };
    let archive = match BundleBuilder::from_manifest(&args.manifest).and_then(|builder| {
        builder
            .deny_warnings(args.deny_warnings)
            .build(signing_key.as_ref())
    }) {
        Ok(archive) => archive,
        Err(error) => return render_content_error(common, error),
    };
    fs::write(&args.output, archive.as_bytes()).map_err(|error| BundleError::Io {
        path: args.output.clone(),
        source: error,
    })?;
    match args.format {
        OutputFormat::Human => println!("wrote {}", args.output.display()),
        OutputFormat::Json => println!(
            "{}",
            serde_json::json!({
                "built": true,
                "output": args.output,
                "archive_sha256": archive.sha256(),
            })
        ),
    }
    Ok(())
}

fn run_sign(args: SignArgs) -> Result<(), BundleError> {
    refuse_overwrite(&args.output)?;
    let key = SigningKey::from_pkcs8_pem_file(&args.signing_key)?;
    let archive = BundleArchive::read(&args.archive, ArchiveLimits::DEFAULT_MAX_COMPRESSED_BYTES)?;
    let signed = archive.resign(&key, ArchiveLimits::default())?;
    fs::write(&args.output, signed.as_bytes()).map_err(|error| BundleError::Io {
        path: args.output.clone(),
        source: error,
    })?;
    println!("wrote {}", args.output.display());
    Ok(())
}

fn render_check(
    common: CommonCheckArgs,
    diagnostics: &[Diagnostic],
    bundle_id: Option<&str>,
    archive_sha256: Option<&str>,
) -> Result<(), BundleError> {
    let invalid = diagnostics.iter().any(|diagnostic| {
        diagnostic.severity == DiagnosticSeverity::Error
            || (common.deny_warnings && diagnostic.severity == DiagnosticSeverity::Warning)
    });
    match common.format {
        OutputFormat::Human => {
            for diagnostic in diagnostics {
                let location = diagnostic
                    .path
                    .as_deref()
                    .or(diagnostic.module.as_deref())
                    .unwrap_or("bundle");
                println!(
                    "{:?} [{}] {location}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                );
            }
            if !invalid {
                println!("valid");
            }
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string(&CommandOutput {
                valid: !invalid,
                diagnostics,
                bundle_id,
                archive_sha256,
            })
            .map_err(|error| BundleError::Serialization(error.to_string()))?
        ),
    }
    if invalid {
        Err(BundleError::Validation(diagnostics.to_vec()))
    } else {
        Ok(())
    }
}

fn load_trust_store(paths: &[PathBuf]) -> Result<TrustStore, BundleError> {
    TrustStore::from_keys(
        paths
            .iter()
            .map(TrustedKey::from_spki_pem_file)
            .collect::<Result<Vec<_>, _>>()?,
    )
}

fn read_string(path: &Path) -> Result<String, BundleError> {
    fs::read_to_string(path).map_err(|error| BundleError::Io {
        path: path.to_path_buf(),
        source: error,
    })
}

fn refuse_overwrite(path: &Path) -> Result<(), BundleError> {
    if path.exists() {
        Err(BundleError::Io {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "refusing to overwrite output",
            ),
        })
    } else {
        Ok(())
    }
}
