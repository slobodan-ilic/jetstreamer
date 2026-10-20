# Routine metadata child diagnostics

The routine-cycle coordinator remains a single, non-restarting metadata owner
for one already-completed 30-minute observation. It does not sample resources,
launch replay, upload archives, create sidecars, or delete objects. A failed
cycle still requires evidence-led recovery; child receipts do not authorize
automatic retry or a second owner.

Before accepting or rejecting each completed child process, the coordinator
fsyncs a private no-clobber JSON result:

- `child-sealer.json`
- `child-estimator.json`
- `child-status-N.json`, one per claimed production epoch
- `child-fleet.json`

Each result binds the executable path and digest, exit code or signal, and the
length, SHA-256, and first 1 MiB of each stdout/stderr stream. Oversized output
remains fatal and is explicitly marked truncated. Captured child output stays
inside the root-private cycle directory; neither inherited environment nor
storage credentials are serialized. A spawn failure is included in the cycle's
ordinary durable failure record. Existing result files are never replaced.

The privileged ignored regression
`tests::privileged_real_sealer_child_records_success_and_failures` exercises the
actual coordinator child path against a separately pinned immutable sealer. Run
only the sealed test binary in the production-equivalent non-restarting
systemd sandbox, including `UMask=0077`, with read/write access restricted to
the precreated root-private `/var/lib/jetstreamer/horizon-routine-child-probes`.
Bind `HORIZON_PROBE_SEALER` and `HORIZON_PROBE_SEALER_SHA256` to the reviewed
sealer; no R2 credentials are needed. It preserves its unique attempt directory
and checks wrong-plan rejection, successful local sealing, and no-clobber
rejection. No campaign archive or replay tree is opened.

The first real sandbox probe reproduced the previously opaque child failure:
creation mode `0444` was filtered to `0400` by the restrictive service umask,
and the sealer correctly rejected its generated receipt's final mode. The
sealer now explicitly sets `0444` through the open descriptor before fsync and
validation, as it already does for declared deployment members. Keep the
restrictive service umask. An isolated subprocess regression verifies both
generated files and the declared member retain exact immutable modes under
`0077`, without changing the test runner's process-wide umask.

Passing the probe is not a complete campaign-cycle result. Before rearming a
metadata owner, separately seal the corrected coordinator, corrected sealer,
fresh exact predecessor/model/fleet plan and service; run its check-only gate;
and preserve its real scheduled completion. Never replace live immutable
deployments, fork the fleet predecessor chain, or duplicate a manual cycle.
