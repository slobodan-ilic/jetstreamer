# Horizon delivery-stage census

`jetstreamer-r2 fleet-reconcile` observes delivery separately from replay and
private qualification. Keep full-verifier, current-plugin verifier and uploader
units in the complete campaign `tracked_units` list before their event-driven
handoff can start. Discovery fails closed on an unbound live delivery unit.

After the handoff, bind each live stage with its exact invocation ID, complete
effective `ExecStart`, immutable evidence and `post-replay-pipeline` epoch gate.
Supported claim phases are `full-verification`, `plugin-verification`,
`local-publication` and `upload-readback`. Independent full/plugin checks and the
receipt-waiting uploader may coexist for one epoch. Two live claims for the same
epoch and stage remain an error; a replacement must not masquerade as another
independent stage.

A legacy delivery unit may cover a range, such as
`horizon-plugin-verify-216-219-cached-v1.service`. Give each claimed epoch its own
entry with identical unit, invocation, command and evidence. The entire unit
range must fit the assigned campaign, and duplicate epoch/unit entries fail.
In particular, an uploader named for 298–301 cannot claim epoch 300 under a
201–300 campaign: the private verification tail is not upload authority.

These are observational claims, not launch, compatibility, verification,
publication or status-JSON authority. They do not replace any archive receipt or
make a ready pair. Use a separately supported, qualified status publisher for
the actual downstream phase; never relabel a terminated replay as live or use
this census extension to bypass that publisher's bindings. Keep all changes in
the existing coordinated 30-minute cycle, or an explicitly authorized event or
user-requested status cycle, rather than running another resource poll.
