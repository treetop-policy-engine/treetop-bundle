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
unpublished and is distributed as x86-64 and ARM64 Linux musl archives on the
matching GitHub release, together with `SHA256SUMS`. Release tags must exactly
match the library version; the release workflow publishes the library before
building and attaching the CLI archives.

## Performance regression checks

Pull requests run deterministic Gungraun instruction-count benchmarks through
the organization's reusable Rust benchmark workflow. Each hot path is a small,
separate Cargo benchmark target so compilation is shared while execution fans
out across jobs. The current probes independently measure strict label parsing
and conversion of validated labels into runtime labelers, plus unencrypted key
loading, encrypted-key detection, and encrypted key loading.

The signing-key probe uses a deterministic PBKDF2-SHA256/AES-256-CBC fixture
with 2,048 iterations. It is a regression fixture, not a recommendation to
weaken production KDF settings: encrypted-key load time is expected to be
dominated by the work factor encoded in each key.

Run any probe locally with the matching runner:

```sh
cargo install gungraun-runner --version 0.19.4 --locked
cargo bench --bench labels_parse_callgrind
cargo bench --bench labels_to_labelers_callgrind
cargo bench --bench signing_key_load_callgrind
```
