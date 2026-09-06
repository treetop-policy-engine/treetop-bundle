# Breaking migration to Bundle 0.1.0

This release uses Core 0.1.0 and format version 2. Early Treetop releases prioritize
correctness and a strict shared contract over compatibility adapters.

1. Change every bundle and module manifest to `format_version = 2`.
2. Replace rule-level `kind` and `output` with
   `"target": {"resource_type": "App::Host", "attribute": "labels"}`.
   Keep `field` and `patterns`. Unknown fields, wildcards, missing target components,
   and invalid/reserved names fail validation.
3. Use one rule per exact `(fully qualified resource type, attribute)`. Different
   types can share attribute names. Duplicate tuples are rejected, including across
   module composition. Schema and module namespace ownership checks still apply.
4. Constrain resource types in Cedar policies before trusting derived attributes.
   Only outputs owned on that type are removed before derivation; unrelated
   application-owned attributes survive. A missing derivation removes its output.
5. Rebuild and re-sign archives using Bundle CLI 0.1.0. Old manifest, archive,
   signature, and generator versions are rejected. Never edit signed archives.
6. Upgrade REST, SDKs, the CLI, workbench, and Bundle Action together. Policy versions
   now require explicit `label_set` (nullable) and unsigned `generation` metadata.

Custom Rust labelers return a validated Core `LabelTarget` from `target()` and
implement immutable `derive`. Arbitrary `applies_to` predicates and global output
ownership are removed. `LabelRule::target()` replaces `kind()` and `output()`.

The coordinated PRs remain unmerged pending approval. Candidate dependency commits
are pinned and package verification uses those exact candidates. Publish Core before
Bundle, then REST and SDKs, before updating consumers to their published artifacts.

## Candidate verification and release order

The checked-in Cargo configuration pins the exact unmerged Core candidate for
reproducible CI and package verification. The published manifest requires Core
0.1.0. After approval, publish Core first, switch this candidate patch to the
registry release, refresh the lockfile, and repeat package verification before
publishing Bundle. Do not merge or publish these coordinated changes before
user approval.
