# Changelog

## [Unreleased]

- Compile each label rule as a bounded `RegexSet`, enforce document-wide label
  resource budgets, and benchmark large-set compilation and matching.
- Stream tar data through gzip during archive encoding and decoding, avoid
  artifact clones, and remove the redundant post-signing decompression pass.
- Atomically create CLI output files, bound archive, private-key, and password
  reads, zeroize private-key PEM buffers, and use one file handle for metadata
  checks and reads.
- Reject weak Ed25519 public keys and verify signatures with strict point
  validation.
- Replace quadratic namespace-overlap checks with sorted adjacent checks and
  reuse parsed policies for aggregate validation.
- Add end-to-end archive validation and re-signing regression benchmarks.
- Accept password-encrypted PKCS#8 Ed25519 signing keys, with passwords read
  from a file, `TREETOP_BUNDLE_SIGNING_KEY_PASSWORD`, or a hidden terminal
  prompt.
- Decode each signing-key PEM document once and cover the key-loading paths
  with deterministic instruction-count regression benchmarks.
- Keep encrypted-key support enabled by default while allowing library-only
  users to omit its AES, PBKDF2, and scrypt dependencies with
  `default-features = false`.

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
