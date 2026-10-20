# Epoch 203 bounded prefix resource measurement

`jetstreamer-epoch203-bounded-resource` is a separate private measurement binary,
not a complete-prefix replay or complete-epoch qualification. Historical attempts
stopped at 16.10% and 64.35%; their outputs were retired on October 9. No complete
reusable prefix has been established.

Its compile-time profile pins:

- epoch203/bootstrap `87,695,515`, snapshot SHA-256
  `e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4`,
  length `8,142,103,526`;
- unchanged v1.6.16 store8 worker SHA-256
  `3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a`,
  `SOLANA_RAYON_THREADS=16`;
- measurement target `87,720,000`, at most 1,000 observed slots of overshoot,
  and separately specified underlying canonical root `88,127,580`;
- maximum six-hour execution, 256-GiB captured physical scratch, and initial
  free space of at least `3,185,678,193,366` bytes. Fresh whole-host admission may
  require more; this constant is not proof that the work fits.

The immutable hash-bound plan uses
`jetstreamer-private-epoch203-bounded-resource-plan-v1`, with the strict fields
described for [epoch225](epoch225-bounded-resource-runner.md). It instead requires
`horizon-qualify-203-bounded-resource-*.service`, a direct private run root named
`bounded-resource-203-*`, and the exact epoch203 snapshot/target/root above. The
checkpoint file must contain exactly the bootstrap and root snapshot names.
This cannot borrow or shorten the existing complete-span epoch203 deployment.

The binaries share target-stop/capture mechanics, not scope. Epoch225's fixed
profile, optional upstream-comparison feature, receipts and runtime bounds stay
unchanged. There is no arbitrary epoch/profile option. The epoch203 binary
removes inherited v1.6.20/v1.6.25 worker overrides and selects only its exact
v1.6.16 worker.

Before launch: publish reviewed source, seal the runner/plan, bind parent,
snapshot, worker, genesis and checkpoint inputs, exercise the exact parent's
focused route and runner identity gate, and pass fresh CPU/memory/disk/VMA and
integrity admission. Use an isolated persistent non-restarting unit. A six-hour
bound cannot transfer another lane's memory reservation. Leave healthy replays
and already-sealed guards unchanged.

Use a separately sealed standalone guard's `bounded_canary` profile. It binds
the epoch203 unit to the epoch203 schema and target; an epoch225 receipt cannot
excuse a missing worker. Preserve the strict pre-target worker census, reserve/
VMA stops, bounded drainage, capture digest and nonrenewable receipt pin. Prove
the first real sandboxed guard fire before unattended operation.

Record restore baseline, multiple settled 30-minute resource/useful-work windows,
and pre-shutdown terminal capture. Do not add another polling loop. Use results
to qualify a conservative nonlinear full-prefix envelope or specify the next
bounded measurement; do not extrapolate one early value into a full-prefix bound.
Even success grants no full cold-epoch peak qualification, runtime promotion,
canonical sidecar, public import, R2 operation or scratch retirement. A canonical
prefix, separately qualified 419-slot suffix and complete anchored/plugin scans
remain necessary for the proposed two-stage publication path.

Fleet reconciliation accepts only the distinct
`jetstreamer-private-epoch203-bounded-resource-launch-v1` receipt for this run.
It pins the worker and runner digests, bootstrap/target/root, unchanged v1.6.16
semantics, live zero-restart invocation, and explicit false prefix/peak/promotion/
publication authorities. One same-sample admission report may use this profile's
exact newly sealed guard after its real sandboxed worker/maps proof. It still
must preserve all diagnostic history and cannot chain another event or authorize
another resource observation. Normal reconciliation must advance its observer.
