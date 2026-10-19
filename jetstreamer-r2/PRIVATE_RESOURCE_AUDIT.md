# Private ready-pair resource audits

`private-resource-audit` is a read-only R2 operation for a separately authorized
private century-floor sample. It does not restore producer completion state, issue
an ordinary R2 receipt, publish an archive, or authorize retirement. It must never
be substituted for ordinary generation, full/plugin verification, or delivery.

Invoke the sealed binary as root with an immutable, hash-bound plan:

```
jetstreamer-r2 private-resource-audit /absolute/sealed/plan.json \
  --plan-sha256 HEX --self-sha256 HEX
```

The strict `jetstreamer-horizon-private-resource-audit-plan-v1` plan names one
epoch in 200–300, the exact bucket, archive length, lowercase SHA-256, ETag,
multipart part size, concurrency (1–16), an existing root-owned owner-only private
directory, and its direct `resource-audit.json` receipt. The plan also supplies a
positive `minimum_free_after_restore_bytes` transfer reserve. This reserve is not
the campaign's century floor. All four authority fields
(`production_completion_authorized`, `publication_authorized`,
`remote_mutations`, `r2_mutations`) must be false.

The tool authenticates HEAD and canonical sidecar GET, requires matching SHA-256
metadata and part-size metadata, and conditionally reads every archive range under
the bound ETag. It hashes the entire streamed object, enforces actual free space
before and during transfer, fsyncs and publishes locally without clobbering, then
independently rereads the local archive to check SHA-256 and multipart ETag. Native
composite SHA-256, when present, is also required to match. The authenticated pair
is revalidated after the reread. A local sidecar is restored only inside the
root-private audit directory; no public Horizon path is changed.

The no-clobber `jetstreamer-horizon-private-resource-audit-receipt-v1` receipt
explicitly denies production completion, publication, local retirement and all
remote mutations. Ordinary restore and retirement reject this schema. An
interrupted conditional range request retries within the existing bounded reader;
a process restart may need to redownload its unpublished temporary file. A fully
published matching private archive may be rehashed and reused after interruption.
An existing audit receipt fails closed for operator inspection.

Independent full and current-plugin checks remain mandatory before using the
archive length as a canonical century-floor sample. Those checks and the
resource-audit receipt must be bound explicitly in the floor evidence. No receipt
from another host is copied into this host's producer completion ledger.

`private-resource-audit-verify PLAN --plan-sha256 HEX --self-sha256 HEX`
provides that separate verification stage. Its immutable plan binds the audit
receipt's digest, exact immutable full-verifier and current-plugin executables,
thread count (1–32), epoch, and an existing root-private output directory. It
hashes the archive before and after each independent full-PoH, ordered-coverage,
and `--verify-only` plugin scan, requires successful exit codes and exact
nonpartial success summaries, and preserves no-clobber logs and a private
verification receipt. No child receives R2 credentials.

Only after all three scans pass does it write a single-sample century-floor
receipt, with checked arithmetic and digest-bound references to both the private
remote readback audit and independent verification. The growth-claim consumer
accepts this separate audit schema only with that additional full/ordered/plugin
proof and all completion/publication/mutation authority explicitly false. The
ordinary R2 restore, controller completion, delivery and retirement gates continue
to reject the resource-audit receipt as production completion evidence.
