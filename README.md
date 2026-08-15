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
treetop-bundle build --manifest TREETOP-BUNDLE.TOML --output BUNDLE.TAR.GZ [--signing-key PRIVATE.PEM]
treetop-bundle sign BUNDLE.TAR.GZ --signing-key PRIVATE.PEM --output SIGNED.TAR.GZ
```

Check and build commands accept `--format human|json` and `--deny-warnings`.
Archive checks accept `--signature-policy allow-unsigned|required`. Exit status
is 0 for success, 1 for invalid content, and 2 for usage, filesystem,
configuration, or key-loading failures.

## Signing keys

Private keys must be unencrypted PKCS#8 PEM. On Unix, group or other access to a
private-key file is rejected. Trusted public keys must be SPKI PEM. Generate a
key pair using OpenSSL:

```sh
openssl genpkey -algorithm Ed25519 -out private.pem
chmod 600 private.pem
openssl pkey -in private.pem -pubout -out public.pem
```

Encrypted keys, key generation, Sigstore, multiple signatures, and live trust
store reloads are intentionally outside version 1.

## Distribution

The `treetop-bundle` library is published to crates.io. The CLI package remains
unpublished and is distributed as x86-64 and ARM64 Linux musl archives on the
matching GitHub release, together with `SHA256SUMS`. Release tags must exactly
match the library version; the release workflow publishes the library before
building and attaching the CLI archives.
