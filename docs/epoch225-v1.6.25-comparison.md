# Private epoch225 v1.6.25 comparison

The sealed vote audit brackets the reconstructed Bank divergence between slots
97,199,876 and 97,199,877. The latter contains a signed canonical transaction
that marks its invoked and passed SPL Token program writable. The exact signed
wire fixture is retained in `historical-runtime/fixtures/epoch225-writable-token-program.base58`.
Tests in both pinned workspaces demonstrate the difference: v1.6.20 treats that
program key as writable; v1.6.25 demotes it. This is not actual replay/root proof.

The explicit `epoch225-v1-6-25-diagnostic` feature selects the unchanged pinned
upstream v1.6.25 semantics in a separately built node and worker. Default builds,
ordinary registry bounds, active deployments and all publication gates remain
unchanged. The node requires only focused private epoch225, snapshot 97,199,617,
explicit verification, checkpoint input and the underlying canonical terminal
root 97,631,459. It rejects ordinary replay, cohorts, recovery and inherited leases
before destination setup. Combining unrelated diagnostic features is a build error.

The worker admits only the exact bootstrap and entries 97,199,618 through
97,202,599. It records frozen Bank/account-delta components at parent slots
97,199,876–97,199,878 for comparison with canonical votes. This is a hard bounded
diagnostic, not permission to execute a whole epoch or cross a runtime boundary.

The existing Rust bounded runner has the same opt-in feature. It pins the exact
new worker digest, selects only the v1.6.25 environment variable, removes the
other worker override and retains the original snapshot, genesis, private root,
target 97,202,500, underlying canonical root and resource limits. A controlled
target stop must still capture resources before shutdown. The worker's bound is
not a successful canonical-root checkpoint. Success must retain
`full_cold_epoch_peak_qualified: false`, `runtime_promotion_authorized: false`,
and every publication/sidecar/R2 authority as false.

Before any launch: pass source tests, publish the commits, seal exact parent,
worker, runner and inputs, exercise exact-package focused/identity capability,
and admit its full incremental budget from fresh coordinated evidence. Protect
all older remaining-growth claims, the complete epoch213 budget and century
floor. Install and prove the exact invocation's bounded reserve/VMA guard before
leaving it unattended. Keep earlier attempts and receipts; never restart or mutate
a healthy ordinary producer. Any mismatch remains fatal. Even a matching Bank at
the diagnostic boundary requires full checkpoint/plugin qualification before era
promotion or archive publication.
