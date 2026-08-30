# Changelog

## [Unreleased]

### Added

- Add opt-in namespace-partitioned engine preparation from signed bundle module
  boundaries while preserving the existing monolithic preparation method.

### Changed

- Update the exact `treetop-core` dependency and archive generator metadata to
  0.0.23.

## [0.0.5] - 2026-08-18

### Changed

- Update `treetop-core` to 0.0.22 and refresh all direct and transitive
  dependencies to their latest stable releases.

## [0.0.4] - 2026-08-16

### Added

- Accept password-encrypted PKCS#8 Ed25519 signing keys, with passwords read
  from a file, `TREETOP_BUNDLE_SIGNING_KEY_PASSWORD`, or a hidden terminal
  prompt.
- Publish native CLI archives for Linux musl on x86-64 and ARM64, macOS on
  ARM64, and Windows on x86-64, with per-platform smoke tests and a shared
  checksum manifest.

### Security

- Reject weak Ed25519 public keys and verify signatures with strict point
  validation.
- Bound archive, private-key, and password reads; zeroize private-key and
  password buffers; and enforce document-wide label and regex-program resource
  budgets.

### Changed

- Make `treetop-bundle build` and `treetop-bundle sign` refuse to overwrite an
  existing output path by using atomic create-new semantics.
- Enable encrypted-key support by default while allowing library-only users to
  omit its AES, PBKDF2, and scrypt dependencies with
  `default-features = false`.

### Performance

- Compile large label rules as bounded `RegexSet`s while retaining a bounded
  individual-regex fast path for small rules.
- Stream tar data through gzip during archive encoding and decoding, avoid
  artifact clones, and remove the redundant post-signing decompression pass.
- Replace quadratic namespace-overlap checks with sorted adjacent checks and
  reuse parsed policies for aggregate validation.

### Development

- Expand deterministic Gungraun coverage for label compilation and matching,
  archive validation and re-signing, and encrypted and unencrypted key loading,
  with one independently gated scenario per benchmark target.

## [0.0.3] - 2026-08-15

- Reuse regex programs compiled during strict label validation when constructing runtime labelers, and avoid
  recompiling validated module labels during bundle composition.
- Add small, independently fanned-out Gungraun benchmarks for strict label parsing and runtime labeler construction.

## [0.0.2] - 2026-08-15

- Update the exact `treetop-core` compatibility dependency to 0.0.21.

## [0.0.1] - 2026-08-15

- Add deterministic Treetop policy bundle compilation and strict validation.
- Add detached Ed25519 signatures and rotating public-key trust stores.
- Add the `treetop-bundle` validation, build, and signing CLI.
