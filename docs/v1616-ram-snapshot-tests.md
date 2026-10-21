# Isolated v1.6.16 snapshot tests

`jetstreamer-horizon-ram-snapshot-test` runs only the two existing ignored
86,831,488 snapshot load/verify and initialization/freeze tests. It pins the
default-feature test binary `bfa7aadf…`, snapshot `348cba57…` and mainnet genesis
`133f7eae…`. It does not replay entries, generate an archive, qualify a cold
epoch peak, promote a runtime or create a sidecar. The shrink-budget bounded
comparison and full canonical checkpoint/independent/plugin gates remain.

The root supervisor is sealed separately from its hash-bound plan. Use only
`CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID` and `CAP_KILL`, including their
effective/ambient set in the systemd sandbox. The supervisor reads existing
private observer/fleet receipts and writes only its exact pre-created root-only
receipt directory under `/var/lib/jetstreamer/horizon-ram-snapshot-tests/`.
The test and its listing command drop to UID/GID 1000 with no supplementary
groups; a real self-probe proves zero effective child capabilities and writable
private `/tmp`. No private receipt permissions are relaxed.

Require `Type=oneshot`, `Restart=no`, `KillMode=control-group`, `Delegate=no`,
`MemoryHigh=56G`, `MemoryMax=64G`, `MemorySwapMax=0`, `TasksMax=512`, and
`CPUQuota=200%`. Set `OOMScoreAdjust=1000` and `OOMPolicy=kill` so a resource
failure stays within this diagnostic. The runner independently requires the
actual cgroup `memory.oom.group` value to be `1`; the host's native
`OOMPolicy=kill` sets it. Do not use unsupported `MemoryOOMGroup=` assignments.
Use `TemporaryFileSystem=/tmp:rw,size=512G,nosuid,nodev,mode=1777`,
`TMPDIR=/tmp`, `ProtectSystem=strict`, `ProtectHome=read-only`,
`ProtectControlGroups=yes`, `PrivateNetwork=yes`, and `NoNewPrivileges=yes`.
Make only the exact receipt directory writable outside tmpfs. A 35-minute
oneshot timeout bounds the supervisor's maximum 30-minute child execution.

Every newly allocated tmpfs page is charged to the 64-GiB cgroup, with no swap.
Even at that cap, at least 448 GiB of the 512-GiB filesystem remains free,
above the current 231,874,716,783-byte century floor. This is not new root-disk
capacity or permission to spend another lane's disk reservations. Keep the
epoch-203 component-reserve correction and all existing guards intact.

`capability` mode verifies the exact sandbox, tmpfs geometry and credential
drop, fsyncs a private receipt and runs no snapshot test or host-memory poll.
It does not verify the fixture inputs. `snapshot-tests` mode additionally
requires a separately hash-bound, no-more-than-30-minute-old routine v2 sample
and matching complete fleet ledger: the exact four existing producer/controller
identities, ten active epoch claims and unchanged six canonical century
samples. It hashes every input, requires at least 512 GiB `MemAvailable`
before and after hashing, proves the exact two-test census, then launches the
unchanged test binary with `RUST_MIN_STACK=134217728`,
`SOLANA_RAYON_THREADS=16` and one libtest thread.

During these tests only, a 15-second safety guard checks the private tmpfs
floor and a 448-GiB host-memory reserve. It stops only its own child process
group, after a durable stop intent, on a trip, timeout or external signal.
An error path also reaps that owned group. Existing producers, controllers and
guards are never signaled. This diagnostic safety guard is not another replay
observation loop; the campaign keeps its single 30-minute cadence.

A successful child exit, unchanged input identities and no guard trip produce
a private result, never a publication receipt. Preserve a failing invocation
and its journal/intent; OOM or sandbox failure is not canonical divergence and
must not be called a passing snapshot test. Tmpfs cleanup is confined to the
service's private mount namespace. Do not relabel another snapshot as this
86,831,488 fixture, and do not use live AccountsDb scratch.
