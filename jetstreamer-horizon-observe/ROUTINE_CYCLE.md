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

## Explicit 101–200 profile (dormant until separately qualified)

The existing v1 plan remains restricted to 201–300. This host uses the separate
`jetstreamer-horizon-routine-cycle-101-200-plan-v2` schema and requires a
`scope_101_200` object containing `diagnostic_ranges`. The latter is empty or
contains the exact private epoch-144 loader unit, its range `144`, controller
and producer unit names, and both invocation IDs. Observed/configured census
lengths must equal production model ranges plus that explicit diagnostic set.
Missing, extra, restarted or identity-changing diagnostics fail closed; they
are never converted into production status claims or inactive cleanup evidence.
An optional `additional_tracked_units` list in `scope_101_200` may add up to 128
distinct constrained `horizon-`/`jetstreamer-` service names to the next fleet
observation. It cannot remove prior tracked units, start a service, or add an ETA
claim; all normal fleet identity/command/claim gates remain independent.

The service name is `horizon-routine-cycle-101-200-TIMESTAMP-v2.service`.
Cycle state belongs beneath
`/var/lib/jetstreamer/horizon-routine-cycles-101-200-v2/TIMESTAMP-v2`.
Fleet output and predecessor checks use only the existing root-private
`/var/lib/jetstreamer-horizon-fleet-101-200-20261019-v1/fleet-TIMESTAMP.json`
chain. A later same-sample recording also invalidates a pending cycle. The
model must bind the exact owner-only status receipt directory
`/home/sol/.jetstreamer-private/r2-status-receipts` with UID 1001; children still
run as the privileged reader/writer and their new receipts must be root-owned.
Do not change that directory's ownership or permissions to fit the other host.

The v2 derivation preserves all historical model evidence and appends the exact
previous estimates and new observer bindings rather than overwriting reserved
array positions. It retains the v1 constraints on immutable tool/model/fleet
bindings, exact predecessor hashes, ordinary production identities, terminal
slots, integer estimates, authenticated status readbacks, full fleet reconciliation,
bounded non-restarting service identity and no-clobber child results. Neither
profile samples resources, starts replay, uploads archives, creates sidecars,
deletes objects or automatically retries a failed/partially published cycle.

Keep this profile dormant until source tests, a sealed privileged child/sealer
probe (including actual `UMask=0077` behavior), exact local template check-only
and least-privilege sandbox access have passed. The current manual cycle and
scheduled observer remain the sole owners until an explicit successful handoff;
do not arm both metadata paths for the same sample.
