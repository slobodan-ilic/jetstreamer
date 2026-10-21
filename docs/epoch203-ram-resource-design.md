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
