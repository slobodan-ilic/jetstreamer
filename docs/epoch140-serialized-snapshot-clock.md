# Fixed epoch140 serialized snapshot clock

The separate `jetstreamer-epoch140-snapshot-clock` binary is available only with
the old workspace's explicit `epoch140-snapshot-clock-diagnostic` feature. It
uses exact Rust1.46.0 and the pinned v1.4.25 runtime. No ordinary worker protocol,
runtime registry, snapshot route or replay limit changes. Existing sealed
workers remain untouched.

Build and test from `historical-runtime/v1_4_25`, not the modern workspace root:

```text
cargo test --locked --offline --manifest-path worker/Cargo.toml \
  --features epoch140-snapshot-clock-diagnostic \
  --bin jetstreamer-epoch140-snapshot-clock private_clock::tests
cargo build --release --locked --offline --manifest-path worker/Cargo.toml \
  --features epoch140-snapshot-clock-diagnostic \
  --bin jetstreamer-epoch140-snapshot-clock
```

Give native serialization tests `RUST_MIN_STACK=134217728` and a bounded
`SOLANA_RAYON_THREADS` environment. The differential regression serializes an
actual pinned Bank with the runtime's `add_snapshot` writer and compares its
clock/hash fields. It does not claim to execute the excluded vendored crate's
own unit suite.

The read-only executable is fixed to the retained60911751snapshot path,
generation-bound whole-file SHA256, compressed size, device and inode. Its
usage is:

```text
jetstreamer-epoch140-snapshot-clock --output ABSOLUTE_NEW_RECEIPT \
  MINIMUM_PROTECTED_FREE_BYTES --self-sha256 EXACT_EXECUTABLE_SHA256
```

Freshly admit and seal the executable and exact launch intent first. Protect all
older claims, the century floor and the64MiB live census reservation; the tool
cannot lower its retained minimum5153080892870byte stop floor. Reserve bounded
receipt/log space independently above that sum. Use a persistent non-restarting
private-network oneshot with CPU/memory/task ceilings, read-only home/system
mounts, only required traversal capability and the exact root-private output
directory writable. The internal900-second/runtime/free-space guard runs on
every compressed read, including the full digest pass. Bind and verify the
actual `initial-guard.json` invocation/digest before leaving the job unattended.
Never reuse an output directory after a failed initial-guard/final write.

The tool hashes its own running executable and the full compressed snapshot,
checks the compile-bound pinned `future.rs` layout source hash, then uses the
existing hardened snapshot tar framing/layout/duplicate/size limits. It writes
no accounts or extracted files. It rejects unsupported snapshot versions and
requires the exact bank member plus status-cache presence. It decodes the
**actual** pinned `DeserializableVersionedBank` type through a feature-scoped
runtime helper; no hand-rolled substitute layout or genesis-derived clock is
used. The remaining Bank-file bytes are independently hashed, all tar members
are censused, the compression trailer is drained, and source identity is
rechecked before the fsynced no-clobber receipt is written.

The receipt provides serialized clock fields and an unpacked logical/stored
footprint census. It does not reconstruct Bank/AccountsDb, recompute or verify
the Bank hash, recover an accounts hash, compare validator-local write cursors,
or decode/validate the status-cache contents or every appendvec. It therefore
cannot prove a native checkpoint match or authorize suffix replay, PoH runtime
input promotion, assembly, import, sidecars, publication or local retirement.
Those gates stay independent, including the actual executing suffix worker's
native tuple comparison and a complete retained-prefix reread/hash. Preserve
the snapshot, original140archive and all141repair evidence on diagnostic failure.
