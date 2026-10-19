# Exact epoch 213 V4 artifact publication

`jetstreamer-epoch213-publish` is a narrow artifact admission, not ordinary V4
reuse or historical-runtime registry promotion. It accepts only the original
epoch-213 checkpoint-continuation producer and the independently verified output
of the pinned `ccbe0f1` private full/plugin runner. It performs local publication
only, never an R2 operation or local retirement.

Do not launch before the private verifier finishes successfully. The original
assembly, prefix, suffix, snapshots, and all diagnostic/verification evidence
must remain retained. The initial PoH anchor, exact source-derived restart
provenance, canonical terminal blockhash, full scan, and current byte-consuming
plugin are independent required gates. An assembled file, a provenance hash,
runner exit status alone, or a sidecar is not a substitute.

## Admission and immutable plan

Freshly reconcile the fleet and authenticated R2 inventory at the normal cadence.
Never race another owner or republish a ready epoch. Require complete private
verification and resource evidence, protect older growth and the century floor,
and retain all compatibility gates. This operation moves only the additional
private verification copy; it must not make a third full-size copy.

Build, test, commit, push, and seal the binary with the Rust deployment sealer.
Seal a separate exact plan after the successful verification receipt and archive
digest/length are known:

```json
{
  "schema": "jetstreamer-private-epoch213-v4-publication-plan-v1",
  "verification": {"path": "/absolute/root-private/verification.json", "sha256": "EXACT_RECEIPT_SHA256"},
  "initial_anchor": {"path": "/absolute/sealed/rpc-evidence.json", "sha256": "fc635af1c740bd0a1a9a81b141631e49a43d625b0dffffc1d187d3106f2845e8"},
  "archive_sha256": "EXACT_VERIFIED_ARCHIVE_SHA256",
  "archive_bytes": 1,
  "publication_stage": "/var/lib/jetstreamer/horizon-213-publication-stage-UNIQUE",
  "receipt_directory": "/absolute/root-private/publication",
  "full_receipt_directory": "/absolute/root-private/full/receipts",
  "plugin_receipt_directory": "/absolute/root-private/plugin/receipts",
  "artifact_publication_authorized": true,
  "runtime_registry_promotion_authorized": false,
  "remote_mutations": false,
  "r2_mutations": false
}
```

Replace `archive_bytes` with the measured exact nonzero length, capped at 128 GiB.
All three receipt directories must already exist as distinct canonical,
root-owned mode-0700 directories. The publication stage must be absent. A
nonempty or previous attempt is never overwritten or silently repaired.

The publisher rehashes the bound private verification receipt, its plan, producer
outcome, independent provenance expectation, pinned verifier/pipeline executables,
and exact scan logs. It requires the strict full command including the initial
anchor, expected canonical terminal, and expected provenance, plus the exact
`213:213 --threads 8 --verify-only` plugin command. It checks the retained original
assembly identity and the verified private copy identity, complete epoch coverage,
and actual V4 header provenance before any namespace handoff.

## Privilege and transaction boundary

Run a persistent non-restarting root service with a bounded execution timeout and
minimal capabilities for the source traversal and UID/GID transition. It needs
effective `CAP_DAC_OVERRIDE`, `CAP_CHOWN`, `CAP_FOWNER`, `CAP_SETUID`, and
`CAP_SETGID` where the service sandbox otherwise removes them. Validate the exact
sandbox with the private capability probe below. Keep the original archive/logs
read-only except for the one authorized private verification copy and new stage;
grant writes to the named receipt directories and `/home/ubuntu/horizon` only.
No R2 credentials are needed. Invoke:

```text
jetstreamer-epoch213-publish PLAN --plan-sha256 HEX --self-sha256 HEX
```

The fixed destination must remain owned by UID/GID 1000 with mode 3770. Root
opens new root-only durable receipt descriptors, writes the exact admission
intent, assigns final archive permissions, and moves the private verification
copy no-clobber into a fresh owner-only stage for that archive identity. It
independently hashes that same open inode again and revalidates root evidence.
It then permanently drops all real/effective/saved UIDs/GIDs to 1000, clears
supplementary groups and permitted/effective/ambient capabilities, and calls the
existing recoverable absence-only batch transaction as the destination owner.
The publisher must remain single-threaded through the privilege transition.

The transaction binds the exact plan, verification, source-provenance and anchor
evidence in its durable context. It commits the canonical local checksum last.
The publisher fsyncs its root-owned `publication.json` through the pre-opened
descriptor, then fsyncs canonical full/plugin `.ok` receipts through separately
pre-opened root descriptors. These descriptors do not grant pathname access to
the root-private evidence directories. Finally it acknowledges the exact batch
outcome. Original assembly/prefix/suffix are never moved or deleted.

The full gate is `ARCHIVE_SHA256 FULL_VERIFIER_SHA256 PRIVATE_RUNNER_SHA256`, and
the plugin gate uses the current pipeline SHA-256 in the second field. The third
field in both is the actual receipt-producing private Rust verifier, not the
publisher. Configure a new receipt-gated progressive uploader to accept those
exact verifier/pipeline and private-runner hashes and the exact `receipts/`
directories. Audit that wrapper before arming it. The local sidecar is **not**
R2 completion: authenticated full upload, whole-object readback, source
revalidation, R2 sidecar creation/readback, and a durable R2 receipt still remain.
Adjacent-boundary receipts remain required independently for local retirement.

## Private capability probe

Before production launch, create an empty root-owned 0700 directory directly
under `/var/lib/jetstreamer` named `horizon-213-publication-capability-UNIQUE`.
Invoke the exact sealed publisher as root:

```text
jetstreamer-epoch213-publish --capability-probe DIRECTORY --self-sha256 HEX
```

This branch never opens the real Horizon directory, any campaign archive, or any
campaign receipt. It uses deliberately non-Horizon fixture bytes under that
distinct probe directory to exercise the same permanent credential drop,
destination-owner transaction, and root-receipt-descriptor fsync sequence. Its
root-only `receipts/capability.json` explicitly denies archive admission, runtime
promotion, and R2 mutation. This is filesystem capability evidence only; it
cannot replace actual full/plugin verification. Preserve its private fixture
and receipt for audit, outside all campaign scanners.

Probe-only setup also needs `CAP_FSETID` to set mode 3770 on its newly created
fixture destination after assigning group 1000. Without it, Linux can silently
strip the setgid bit to 1770 and the correct destination-policy check rejects
the probe. Preserve that failed attempt and retry in a new empty probe namespace
with this additional setup capability. Production does not create or chmod the
existing public directory and does not need that extra capability. The actual
permanent-drop check must still prove all permitted/effective/ambient
capabilities are zero before the transaction.

## Fail closed and recover explicitly

An existing archive, checksum, segment manifest, receipt, handoff stage, changed
source, missing scan, wrong provenance, failed privilege drop, or failed evidence
rehash stops publication. An interrupted attempt may leave empty root gate
placeholders; these are intentionally unparseable, not successful receipts.
Never fill them by hand or treat them as verification.

After a crash, preserve the intent, all receipt descriptors' files, the exact
private handoff, and the library's durable batch journal/outcome. Require a
separately reviewed exact-context transaction/receipt recovery using the library
recovery API, rather than bypassing admission with a generic import. The
publisher deliberately does not recover an arbitrary
batch it finds in the public directory. A committed pair without a completed
publisher receipt needs evidence-based receipt recovery, not another import or
an overwrite. No failure authorizes R2 deletion/replacement, generic V4 admission,
or exposing epoch 301.
