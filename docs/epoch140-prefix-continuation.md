# Epoch 140 private prefix continuation: qualification work

The original 103,138,915,297-byte archive remains unchanged and private. Its
independent full PoH scan and separate anchored ordered-chain pass succeeded.
The chain receipt is `horizon-private-anchored-chain-verification-v3`; it does
not establish a complete prefix manifest or authorize continuation/publication.

The intended retained prefix is slots 60,480,000 through 60,911,751 inclusive
(431,752 slots). The remaining suffix has 248 slots through 60,911,999. Native
snapshot restoration matched the cut's consensus tuple with zero bootstrap
writes, but the actual suffix worker must repeat that check before entries.
The original raw cursor 28,029,693,043 and restored native cursor 28,087,370,409
are independent namespaces: neither may be forced to equal the other.

## Existing implementation boundaries

- `reencode_archive` exports whole archives or bucket subsets. Bucket subsets
  deliberately omit provenance and retain the original declared range; they
  cannot stand in for an exact checkpoint prefix.
- `reencode_archive_prefix` is a library-only primitive for a proper, dense,
  uninterrupted V2 prefix. It retains the source bootstrap, worker digest,
  metadata policy and raw update order, narrows provenance/header range and
  segment-local epoch slot count, preserves a nonzero incoming PoH anchor,
  and rejects discontinuous slots or stored links. Its semantic output digest
  must match an independent reread. It does not hash-bind paths, admit disk,
  create files/manifests/sidecars, prove a checkpoint, or authorize operation.
- `jetstreamer-segment-recover` implements a different delayed-reaping profile:
  legacy v1 full receipt, owner-only archive, common private root, and specific
  failure/journal schemas. Do not chmod the retained 0440 archive, relabel its
  v2/v3 receipts, or manufacture old-profile evidence to use it.
- `checkpoint_continuation.rs` is explicitly build/input-bound to epoch 213,
  Solana v1.6.16 and its 457-slot suffix. Do not broaden or reuse those flags
  for epoch 140. The reusable archive merger's V4 restart provenance keeps
  independent raw cursors and normalizes update versions in recorded order.
- The checked-in v1.4.25 worker snapshot/entry guards cover this intended
  interval, but source inspection is not proof about any newly sealed worker.

## Remaining gates

Qualify a dedicated Rust, hash-bound private prefix-export/manifest profile
against the actual sealed full, anchored, bootstrap-journal, cut-journal,
raw-cut and native-restoration evidence. It must bind source identity/digest,
the exact cut tuple and actual observed raw write range; independently reread
the exported prefix before returning a usable proof. The observed cut's
post-phase count minus one agrees with 20 journal-drained writes, but that
single observation is not a generic arbitrary-mid-checkpoint derivation.

Then qualify the dedicated v1.4.25 actual-worker restart and suffix path,
canonical-root coverage, V4 assembly, independent full/plugin verification,
and explicit provenance-aware canonical import. The ordinary terminal-root
obligation remains even though the restart cut is near the epoch end.

Any large copy, restore or assembly needs fresh admission for its complete
incremental peak while protecting all live growth claims, ongoing epoch-141
ledger retention, and the century floor. Keep outputs private and sidecar-free
until every independent gate passes. No replay, assembly or publication is
authorized by this document or by passing library tests.
