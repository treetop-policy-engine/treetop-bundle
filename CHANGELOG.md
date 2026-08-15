# Changelog

## [Unreleased]

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
