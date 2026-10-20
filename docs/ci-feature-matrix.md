# Rust CI feature coverage

The Rust workflow shares one matrix between `cargo check`, `cargo test` and
`cargo clippy`:

- The complete workspace with default features.
- The workspace with all features except the explicitly excluded
  `jetstreamer-node` package. The node is covered by the default-workspace job
  and its isolated mode jobs instead.
- Each of the six node diagnostic/qualification features individually, selected
  with `-p jetstreamer-node --features FEATURE`.

Node qualification features are deliberately not additive: combining the
epoch-225 comparison or full-span route with another private route must remain a
compile error. CI therefore covers every supported mode without removing those
safety guards or attempting a meaningless all-node-modes build.

`jetstreamer-node/tests/ci_feature_matrix.rs` checks the declared node features
against the shared matrix, its consumers and the retained archive-example test
steps. Adding a node feature requires adding its isolated CI entry. Workflow
syntax, including the YAML anchor, can be checked with `actionlint`.

The epoch-213 file-identity regression must not assume that consecutive writes
receive different filesystem timestamps. Keep the old descriptor open and
atomically replace its path to test inode substitution. Test length changes and
same-length content hashing separately. Do not fix a timing-dependent fixture
by adding sleeps, skipping it, or weakening production identity/hash checks.

For local reproduction, use CI's test artifact settings:

```sh
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --workspace
CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --workspace --exclude jetstreamer-node --all-features
cargo check --workspace --exclude jetstreamer-node --all-features
cargo clippy --workspace --exclude jetstreamer-node --all-features
```

Repeat check, test and clippy with `-p jetstreamer-node --features FEATURE` for
each isolated mode. Run both `jetstreamer-horizon` archive-example regressions
with default and all features as the workflow does. Passing a narrow package's
tests alone does not establish workspace or CI readiness.
