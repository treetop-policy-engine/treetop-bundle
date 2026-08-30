# treetop-bundle

`treetop-bundle` compiles separately owned Cedar policy projects into a
deterministic, optionally signed archive that can be loaded atomically by
Treetop REST.

The published library owns manifest parsing, strict label validation, policy
and schema composition, Ed25519 trust policy, archive limits, and preparation
of a complete `treetop_core::PolicyEngine`. The `treetop-bundle-cli` workspace
package builds the GitHub-distributed `treetop-bundle` binary and is not
published to crates.io.

## Source manifests

Each project has a `treetop-module.toml`:

```toml
format_version = 1
name = "dns"
namespace = "ExampleCo::DNS"
imports = ["ExampleCo::Identity"]
policies = ["permissions/base.cedar", "permissions/admin.cedar"]
schemas = ["schema/entities.cedarschema"]
labels = ["labels/resources.json"]
```

The organization-level manifest selects modules and is the only place that can
grant a global policy role:

```toml
format_version = 1
name = "production"

[[modules]]
manifest = "../identity/treetop-module.toml"
role = "ordinary"

[[modules]]
manifest = "../platform-policy/treetop-module.toml"
role = "global"
```

All module inputs are explicit relative paths. Absolute paths, globs, `..`, and
symlink escapes are rejected. Bundle output is a canonical gzip-compressed tar
containing `manifest.json`, an optional `signature.json`, `policies.cedar`, an
optional `schema.json`, and `labels.json` in that exact order.

Validated archives can be prepared as either a backward-compatible monolithic
policy engine with `ValidatedBundle::prepare_engine()` or an opt-in
namespace-partitioned engine with
`ValidatedBundle::prepare_engine_with_policy_stores()`. In the partitioned
form, each ordinary module is a store and global-module policies are installed
in every store. Ordinary modules must be independent: a policy that references
another ordinary module's namespace makes scoped preparation fail closed.

Label patterns in each rule are compiled into one `RegexSet`, so all patterns
are evaluated in a single search. To keep untrusted label documents within a
predictable resource budget, a document may contain at most 256 rules, 1,024
patterns per rule, 4,096 patterns in total, 16 KiB per regex, and 1 MiB of
regex source in total. Each compiled set also has explicit 2 MiB program and
1 MiB lazy-DFA cache limits.

## Commands

```text
treetop-bundle check policy FILE [--schema FILE] [--labels FILE]
treetop-bundle check module TREETOP-MODULE.TOML
treetop-bundle check bundle TREETOP-BUNDLE.TOML
treetop-bundle check archive BUNDLE.TAR.GZ [--trusted-key PUBLIC.PEM]...
treetop-bundle build --manifest TREETOP-BUNDLE.TOML --output BUNDLE.TAR.GZ [--signing-key PRIVATE.PEM] [--signing-key-password-file FILE]
treetop-bundle sign BUNDLE.TAR.GZ --signing-key PRIVATE.PEM [--signing-key-password-file FILE] --output SIGNED.TAR.GZ
```

Check and build commands accept `--format human|json` and `--deny-warnings`.
Archive checks accept `--signature-policy allow-unsigned|required`. Exit status
is 0 for success, 1 for invalid content, and 2 for usage, filesystem,
configuration, or key-loading failures.

## Signing keys

Private keys must be PKCS#8 PEM and may be unencrypted or password-encrypted
with PBES2. On Unix, group or other access to a private-key file is rejected.
Trusted public keys must be SPKI PEM. Generate an encrypted key pair using
OpenSSL:

```sh
openssl genpkey -algorithm Ed25519 -aes-256-cbc -out private.pem
chmod 600 private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

For encrypted keys, `build` and `sign` read the password from
`--signing-key-password-file` when supplied, then from the
`TREETOP_BUNDLE_SIGNING_KEY_PASSWORD` environment variable, and otherwise
prompt on the terminal without echoing. The file option takes precedence over
the environment. Password files are read as raw bytes and may contain non-UTF-8
values; a single trailing CRLF or LF is removed. Environment passwords must be
valid UTF-8. Passwords cannot be supplied directly as command-line values.

PBES2 decryption is enabled by the library's default `encrypted-keys` Cargo
feature. Library consumers that only accept unencrypted keys can avoid the AES,
PBKDF2, and scrypt dependency stack with `default-features = false`. The CLI
keeps encrypted-key support enabled.

Key generation, Sigstore, multiple signatures, and live trust store reloads
are intentionally outside version 1.

## Distribution

The `treetop-bundle` library is published to crates.io. The CLI package remains
unpublished and is distributed as native x86-64 and ARM64 archives for Linux
musl, ARM64 for macOS, and x86-64 for Windows on the matching GitHub release,
together with `SHA256SUMS`. Every binary is built and smoke-tested on a native
GitHub-hosted runner. Release tags must exactly match the library version; the
release workflow publishes the library before building and attaching the CLI
archives.

## Performance regression checks

Pull requests run deterministic Gungraun instruction-count benchmarks through
the organization's reusable Rust benchmark workflow. Each hot path is a small,
separate Cargo benchmark target containing exactly one measured scenario. This
keeps target-level regression totals meaningful while compilation is shared and
execution fans out across jobs. Shared fixture code lives in `benches/support/`
and is not a benchmark target. The current probes independently measure strict
label parsing, large `RegexSet` compilation, runtime labeler construction and
matching, archive validation and re-signing, plus unencrypted key loading,
encrypted-key detection, and encrypted key loading.

The signing-key probe uses a deterministic PBKDF2-SHA256/AES-256-CBC fixture
with 2,048 iterations. It is a regression fixture, not a recommendation to
weaken production KDF settings: encrypted-key load time is expected to be
dominated by the work factor encoded in each key.

Run any probe locally with the matching runner:

```sh
cargo install gungraun-runner --version 0.19.4 --locked
cargo bench --bench labels_parse_callgrind
cargo bench --bench labels_parse_many_callgrind
cargo bench --bench labels_to_labelers_callgrind
cargo bench --bench labels_to_labelers_many_callgrind
cargo bench --bench labels_apply_many_callgrind
cargo bench --bench archive_validate_callgrind
cargo bench --bench archive_resign_callgrind
cargo bench --bench signing_key_load_unencrypted_callgrind
cargo bench --bench signing_key_detect_encrypted_callgrind
cargo bench --bench signing_key_load_encrypted_callgrind
```
