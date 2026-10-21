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

## Read-only selected-prefix audit

`jetstreamer-epoch140-prefix-audit` is a separate fixed-input audit of the
original archive through 60,911,751. It makes no large prefix copy: its
`jetstreamer-epoch140-private-selected-prefix-audit-v1` result explicitly binds
the original 432,000-slot source and a distinct 431,752-slot selection. It is
not a `HistoricalSegmentManifest`, a shortened archive, or a continuation
approval. A future selected-range consumer must explicitly support that
distinction rather than pass the whole original archive to a prefix-only
manifest reader.

The immutable plan binds the exact sealed full, anchored-chain, bootstrap
journal, cut journal, raw-cut and native-restoration receipts by their actual
digests. The tool rehashes the whole source before and after independently
decoding the selected prefix, checks every selected slot and incoming bucket
anchor, and verifies the exact complete raw-write range. Per-slot sorting is
used only to detect missing/duplicate versions; the semantic event digest
retains original wire order across epoch, pre, transaction and post phases.
The original source's previously established full PoH proof remains separate;
the audit does not pretend to perform another full PoH scan.

Invoke a separately sealed root-owned executable and owner-only immutable plan:

```text
jetstreamer-epoch140-prefix-audit PLAN --plan-sha256 HEX --self-sha256 HEX [--check-only]
```

The strict plan schema is `jetstreamer-epoch140-private-prefix-audit-plan-v1`.
It contains `unit`, six `{path, sha256}` bindings named `full`, `anchored`,
`bootstrap`, `checkpoint`, `edge`, `native`, the `output` receipt path, and
`minimum_free_bytes` / `minimum_available_memory_bytes`. Pre-create an empty
root-only `epoch140-prefix-audit-UNIQUE` directory directly under this host's
private campaign root; the result must be named `prefix-audit.json`.
`--check-only` validates the exact profile, source identity/header and admission
without a large source hash, decode or output. Prove that mode under the same
sandbox before the real non-restarting persistent service. Real execution
authenticates its exact systemd invocation and PID, retains a shared source
lock, and enforces the reserve/runtime guard throughout reads. Use a bounded
memory cgroup and a oneshot timeout longer than its six-hour internal bound.

No input, archive, sidecar, existing manifest or remote object is modified.
The small no-clobber result and its directory are individually fsynced.
Failure preserves all previous evidence and has no automatic retry authority.
Actual suffix-worker restart validation, selected-range assembly/provenance,
normal full/plugin/root gates and canonical import remain outstanding.

## Selected-range assembly primitive (not an operational approval)

`merge_checkpoint_restart_with_retained_prefix` is a separate library entry
point for one selected original prefix plus one independently restarted
suffix. Its first `RuntimeSegmentSource::retained_prefix` binds the **whole**
unchanged original container hash, the selected checkpoint blockhash and a
`RetainedPrefixSelection` with original/selected slot counts and the independent
digest of original selected wire events. Source header, V2 provenance and epoch
metadata retain their original range. No prefix-only manifest is fabricated.

The source container must cover the entire destination range. Only its proper
prefix is decoded into the first generation; an explicit bounded bucket reader
stops at the cut even inside a bucket. Epoch, pre, transaction and post writes
are checked and normalized in their original event order. The original tail
is excluded, but remains committed by the whole source digest. The source
selection's event digest is checked before moving to the suffix. Independent
raw/native cursors remain represented by the V4 handoff and normalization maps.

Ordinary V3 and complete-source V4 assembly reject selected-prefix inputs.
The new entry point requires two generations, a proper first-source selection,
a complete second source, and an explicit V4 assembly profile ending in
`/retained-prefix-selection-v1`. It writes no file or receipt itself and grants
no canonical admission, replay, root, plugin, sidecar or publication authority.

For epoch 140, 248 slots describe only the remaining **epoch-140 output** after
the cut. That count is not permission to stop at the epoch end without the
ordinary trusted-terminal-root obligation. The dedicated replay may need a
larger compatible verification cohort. The retained 11-target gap audit covers
only 60,911,751..60,912,005; a wider execution interval needs its own complete
gap census and exact-state recovery. Never extrapolate that bounded evidence
to an entire later epoch or use the earlier cut root to erase a required gate.
