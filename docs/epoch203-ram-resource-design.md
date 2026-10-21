# Dormant RAM-backed epoch203 resource experiment

This is preparation, not a deployed supervisor or launch authorization.
The two real 86,831,488 snapshot integration tests passed on October 21.
Entry replay, IPC, resource behavior and all canonical/plugin gates remain
independent. Existing disk-backed comparison admission remains closed while
the healthy epoch203 root-prefix producer has unbounded future scratch growth.

`jetstreamer-epoch203-ram-resource-plan` performs an offline, hash-bound
geometry check. It reads only one immutable root-owned regular JSON input
and prints planning JSON; it never samples resources, mounts a filesystem,
starts a child, signals a producer, writes a receipt or accesses R2. Build
and test it independently of the existing snapshot supervisor:

```sh
cargo test -p jetstreamer-horizon-observe --bin jetstreamer-epoch203-ram-resource-plan
```

The provisional envelope has these separate budgets:

| Component | GiB |
| --- | ---: |
| Private RAM scratch | 192 |
| Private RAM archive | 16 |
| Worker anonymous memory / other charged working set | 96 |
| Supervisor, metadata and contingency | 16 |
| Aggregate cgroup hard maximum | 320 |
| Cgroup soft threshold | 304 |
| Private tmpfs capacity | 768 |
| Host startup available-memory minimum | 864 |
| Host stop reserve | 544 |
| Protected host reserve after a worst-case extra diagnostic cap | 224 |

The retained same-input store8 baseline used 172,458,995,712 physical scratch
bytes and 85,901,561,856 cgroup peak bytes on disk. The envelope is a bounded
experiment budget, not proof that replay fits: on RAM the file pages and
anonymous memory consume the **same** cgroup limit. It may reject or stop a
run, and its caps must never be presented as measured peaks. In particular,
reusing either the 128-GiB snapshot-test sandbox or the 512-GiB tmpfs with this
320-GiB cap fails the checker. The latter would leave only 192 GiB, below
the current century floor of 231,874,716,783 bytes. A 768-GiB tmpfs leaves
448 GiB even if the entire 320-GiB cap consists of RAM files. Startup reserves
the whole cap above the 544-GiB stop reserve; the guard reserve additionally
protects 224 GiB after a worst-case complete cap allocation.

Expected geometry input:

```json
{
  "schema": "jetstreamer-private-epoch203-ram-resource-geometry-v1",
  "tmpfs_bytes": 824633720832,
  "scratch_budget_bytes": 206158430208,
  "archive_budget_bytes": 17179869184,
  "anonymous_budget_bytes": 103079215104,
  "overhead_budget_bytes": 17179869184,
  "memory_high_bytes": 326417514496,
  "memory_max_bytes": 343597383680,
  "host_start_available_bytes": 927712935936,
  "host_stop_available_bytes": 584115552256,
  "protected_host_bytes": 240518168576,
  "century_floor_bytes": 231874716783,
  "persistent_mount_required": true,
  "swap_max_bytes": 0
}
```

Supply the sealed path and independently calculated digest as
`/absolute/geometry.json --plan-sha256 HEX`. A passing geometry report does
not bind a fleet, refreshed century census, stopped225 CPU allocation,
snapshot, worker, measured free memory, VMA limit or actual sandbox. It is
not fresh admission and has no runtime authority. Do not deploy this checker
as an admission service or reinterpret the old disk runner's free-space gate.

## Required implementation before any experiment

1. A distinct sealed Rust supervisor, exact sandbox capability probe and
   invocation-bound guard must authenticate the actual tmpfs mount, CPU and
   memory caps, no swap, UID/capability drop, input identities, and the complete
   three-producer fleet plus stopped225 evidence. Keep at most four entry
   replays. Use a fresh coordinated observation, not a new polling loop.
2. Bind the exact parent, generation-pinned 87,695,515 bootstrap, genesis,
   epoch hashes, 16-thread setting, bounded target 87,720,000 and underlying
   root 88,127,580. Compare baseline and shrink candidate **sequentially on
   equivalent RAM-backed environments**; comparing RAM throughput with the old
   disk result does not isolate the shrink change. If CPU settings differ from
   the old result, retain that distinction rather than normalizing it away.
3. Capture a baseline plus settled windows at the normal 30-minute cadence,
   own-cgroup counters, useful-work totals, physical/apparent scratch and VMA
   distributions, target stop and terminal result. Enforce component budgets,
   total memory, host reserve, tmpfs floor, VMA and time bounds. A runtime or
   resource stop is a failed bounded experiment, not canonical divergence.
4. Keep every generated archive, manifest and useful diagnostic input on a
   RAM mount whose lifetime is independent of the producer's mount namespace.
   A oneshot `TemporaryFileSystem=` that vanishes on exit is not sufficient.
   Seal required evidence on durable storage, and perform a separately
   qualified, reference-scanned retirement before unmounting. Budget evidence
   retention explicitly; do not copy partial archives onto root disk while its
   remaining-growth admission is closed. No deletion is authorized by this
   design or geometry checker.
5. Require all normal root, independent full archive, current-plugin, suffix,
   assembly and publication gates after performance evidence. A bounded
   comparison cannot promote a route, qualify a full cold-epoch peak, publish
   an archive or close the epoch203/225 repair incidents.

The geometry is intentionally separated from implementation and admission.
Leave existing replays, guards, metadata owners and sealed binaries unchanged.

## Persistent-storage capability probe

`jetstreamer-epoch203-ram-storage-probe` now implements the storage/sandbox
authentication component, not the replay supervisor or admission. It accepts
`PLAN --plan-sha256 HEX --self-sha256 HEX`, verifies its own immutable executable
and the root-owned immutable plan, and authenticates the actual unit/cgroup,
mount unit, mount ID, filesystem type/capacity, root inode device, child
directories, TMPDIR and exact before/after identities. Its only write is
`receipts/storage-capability.json` beneath the exact private RAM root, with
no-clobber creation, mode0400 and file/directory fsync. Seal that metadata onto
durable storage before treating it as retained evidence: fsync on tmpfs does
not make it survive reboot. It never launches replay, polls host memory or
the fleet, signals a process, mounts/unmounts, removes files or accesses R2.

The strict plan has these fields, with no others:

```json
{
  "schema": "jetstreamer-private-epoch203-ram-storage-probe-plan-v2",
  "unit": "horizon-203-ram-storage-probe-ATTEMPT.service",
  "run_root": "/home/ubuntu/.jetstreamer-private/ram-resource-203-ATTEMPT",
  "mount_unit": "EXACT_SYSTEMD_ESCAPED_PATH.mount",
  "mount_invocation_id": "EXACT_32_LOWERCASE_HEX",
  "host_mount_id": 123,
  "mount_device": [0, 67],
  "host_peer_group": 357
}
```

The mount must be a separately managed active `tmpfs` mount with
`StopWhenUnneeded=no`, empty `BindsTo=`/`PartOf=`, 768-GiB capacity,
`rw,nosuid,nodev` and executable files, root mode0700/UID1000/GID1000, and
empty mode0700 `scratch`, `output`, `ledger`, `tmp` and `receipts` children
on the same device. Do not substitute a bind-mounted subtree or a service's
`TemporaryFileSystem=` namespace. Probe plans bind its actual current
invocation, host device and propagation peer group. Mount IDs are namespace-local:
the probe pins its own current namespace's mount ID and peer across the read,
not the host's numeric mount ID. A changed or multiply mounted path fails closed.

For the future exact probe service require `Type=oneshot`, `Restart=no`,
`KillMode=control-group`, `Delegate=no`, `NoNewPrivileges=yes`,
`ProtectSystem=strict`, `ProtectHome=read-only`, `ProtectControlGroups=yes`,
`PrivateDevices=yes`, `RestrictSUIDSGID=yes`, `UMask=0077`, `PrivateNetwork=no`,
empty `TemporaryFileSystem=`, and only the exact RAM root in `ReadWritePaths=`.
The actual cgroup must have memory.high304GiB, memory.max320GiB, swap0,
groupOOM1, pids512 and an exact 16-core CPU quota. The probe makes no claim
that this CPU budget is available: stopped225 allocation and fresh fleet
admission remain separate gates before **any replay**.

`User=1000` alone retains ubuntu's NSS supplementary groups (including sudo
and lxd on this host). Instead the probe service starts a fixed setpriv exec
wrapper as `User=root`, `Group=root`, with only
`CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_SETPCAP` and the same exact
`AmbientCapabilities=` for the initial drop, with no added supplementary groups.
Invoke the immutable reviewed wrapper with
`--reuid=1000 --regid=1000 --clear-groups --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs`
and the sealed probe/plan/digests. The probe itself must observe all four
real/effective/saved/filesystem UID and GID values1000, no foreign supplementary
groups, all five process capability sets zero and effective NoNewPrivs1.
A real host read-only `/usr/bin/setpriv ... /usr/bin/cat /proc/self/status`
check confirmed that this drop mechanism works; that check was **not** an
actual sandbox or storage capability pass. No mount or replay is authorized
by it. Require a separately sealed actual probe invocation before deployment.

The first sealed real probe attempt (`horizon-203-ram-storage-probe-v1`,
invocation `c8a6527a5a604b8b86a686e2f1c9a1f0`) failed in setpriv with exit127:
`setresuid failed: Operation not permitted`. A bounding set alone did not
provide the required effective drop capabilities in this sandbox. Preserve that
failed unit/journal and package. The revised sandbox explicitly binds the same
minimal ambient set for the wrapper, clears inherited/ambient sets before exec,
and still requires the actual probe to prove all five capability sets zero.
This correction must use a distinct sealed binary/plan and service invocation;
the failed v1 attempt is not capability evidence. The independently managed
empty RAM mount remains preserved and bound to its original mount invocation.

The second sealed attempt (`horizon-203-ram-storage-probe-v2`, invocation
`7e9921fd148546a289137be90d43bde9`) successfully crossed the privilege-drop
gate, then rejected the host mount ID inside the service mount namespace.
A read-only same-sandbox mountinfo diagnostic confirmed the reason: host
mount322/device0:67/shared357 appears as mount471/device0:67/shared392/master357
inside the protected namespace. Preserve the failure. The v2 **plan schema**
separately records the host ID, binds device and propagation master, and requires
the service's actual mount ID/peer to remain stable before/after. This is an
explicit corrected identity model, not permission to accept arbitrary mounts.
