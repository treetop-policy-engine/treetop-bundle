# Repository Guidelines

## Performance benchmarks

- Put every Cargo benchmark entrypoint in a top-level `benches/*.rs` file.
- Define exactly one measured scenario in each benchmark target. The PR
  benchmark workflow fans out and gates regressions by Cargo target, so adding
  multiple `#[library_benchmark]` functions or argument cases to one target
  produces misleading aggregate totals and prevents independent execution.
- Put shared setup, fixtures, and generators in nested modules under
  `benches/support/`. Nested support files must not define measured benchmarks
  and are intentionally excluded from autodiscovery.
- Give targets descriptive names ending in `_callgrind`, declare each target in
  `Cargo.toml` with `harness = false`, and set `required-features` when needed.
- When adding or changing a scenario, compile the full benchmark suite with
  `cargo bench --locked --workspace --all-features --no-run` and run each
  affected target individually before publishing.
