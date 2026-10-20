# Native SST decoder capability

Run the explicitly enabled, pinned decoder test with:

```sh
JETSTREAMER_SST_DUMP_TEST_BIN=/absolute/sealed/sst_dump \
  cargo test --locked --release -p jetstreamer-utils \
  --features sst-capability-tests --test sst_decoder_capability \
  -- --ignored --nocapture
```

The optional feature keeps native RocksDB test dependencies out of ordinary
utility builds. The test uses isolated disposable databases only. It proves
uncompressed and LZ4 prefix decoding, internal versions, point deletion,
column-family identification, and range-deletion table properties against the
exact supplied executable. It does not qualify a production ledger generation
or prove support for other compression formats.

The fixture deliberately starts a covering range tombstone in the slot before
the queried prefix. A native logical database lookup returns no value, while
the point-prefix scan still exposes both old and newer point versions. Thus
even a complete scan of every SST followed by greatest-point-sequence selection
can incorrectly resurrect deleted data. A prefix iterator alone cannot establish
the full set of covering range tombstones.

The `native_readonly_resolves_manifest_and_wal` test separately exercises native
read-only logical resolution of a deliberately crash-shaped LZ4 database. Its
fixture process syncs unflushed WAL writes and exits without database destruction.
It requires the complete CF set and checks an outside-prefix range deletion,
point deletion, updated WAL value and WAL-only key. A second disposable copy omits
WALs: even when native open succeeds, that copy must not be treated as a complete
backup. This qualifies fixture behavior only, not an archived ledger or a shred
decoder. Run it with the same explicit feature and `--ignored` test flags above.
With the pinned native decoder, the omitted-WAL copy does open and resurrects old
SST values; a read-only subset-CF open also succeeds. Therefore authenticate the
complete generation-bound manifest/WAL/live-file census independently of native
open success. The test also rehashes CURRENT, MANIFEST, WAL and SST inputs after
the complete logical read to detect input mutation.

An archival recovery must either preserve CURRENT/MANIFEST, relevant WALs, and
the complete live file set for native read-only logical resolution, or use an
independently qualified range-aware reader that accounts for every covering
range tombstone as well as internal point versions and deletions. A bounded
one-SST-at-a-time scan may collect candidates, but must not label them live or
complete until those independent gates pass. Unknown column families, unknown
record types, unsupported compression, truncated scans, unresolved duplicate
versions, or missing manifest/WAL evidence are failed gates, never absence proof.

Even correctly resolved shred records remain diagnostic inputs until the exact
pinned historical layout, complete ordered entry/tick chain, independently
finalized parent and final PoH hashes, and ordinary checkpoint/plugin/publication
gates have all passed. Do not equate PoH hashes with Bank or SlotHashes hashes.

`horizon_ledger_tar::collect_rocksdb_tar` is the bounded diagnostic collection
core for a complete **flat** RocksDB tar. It retains every regular member, not
only selected SSTs: CURRENT, its nonempty MANIFEST, all archived WALs, all table
files, OPTIONS and ancillary files appear in a sorted length/SHA-256 census.
The caller explicitly supplies the archive root and independent file-count,
individual-file, total-output and zero-trailer limits. Unknown members are
preserved; links, devices, sparse/GNU/PAX extensions, nested/foreign paths,
duplicates, missing end markers and nonzero/excess trailers fail closed. New
files are no-clobber, read-only and individually fsynced, followed by directory
fsync. A failed partial tree is preserved and cannot be reused as a completed
collection.

This core accepts an already decompressed reader. It has **no production caller**
and does not authenticate a compressed cloud generation, bind an original
backup's completeness, provide a resumable download or perform fresh resource
admission. Those remain mandatory before actual ledger collection. Its result
explicitly denies source-completeness, live-state and publication authority.
The native read-only fixture test above also collects an entire crash-shaped
database tar, compares every source member byte-for-byte, verifies all native
CF/live-file references against the census, resolves outside-prefix range and
point deletions plus WAL-only updates, and rehashes every collected input after
native resolution. This is disposable-fixture qualification only, never evidence
for epoch141 or any real ledger generation.

`horizon_ledger_bzip::collect_bound_bzip2` adds a diagnostic local-input binding
layer. It accepts only a canonical absolute, singly linked, non-writable regular
file owned by root or the effective user, with independently supplied compressed
length and lowercase SHA-256. It hashes the entire bounded compressed input before
collection and again while decoding every bzip2 stream, then rechecks both the
descriptor and named path identity including ctime. The decompressed tar collector
still enforces every file, aggregate and trailer limit. Tests cover multistream
input, wrong digest/length/budget, unsafe inputs, truncation, corrupt checksums,
compressed garbage, concatenated tars, expansion bounds and preserved partial
diagnostics. The input is never modified.

This remains a library with no production caller. The expected digest is not its
own cloud-authentication evidence: a generation-bound download/verification
receipt, fresh resource admission, persistent guarded execution and durable
result receipt must still be supplied by a reviewed caller. Neither a successful
compressed binding nor a complete tar census proves original-backup completeness,
native live state, correct PoH boundaries or publication eligibility. No actual
epoch141 source has been collected by these fixture tests.

The native crash-shaped fixture also compares direct-tar and digest-bound
multistream-bzip2 collections byte-for-byte, then performs the complete-CF native
read-only resolution against the compressed collection. It checks live-file
references, range/point deletions and WAL-only values without modifying either
the retained compressed input or the collected member census.

`jetstreamer-epoch141-ledger-metadata` is a separate, read-only exact-generation
gate for `60911751/rocksdb.tar.bz2#1634789748052739` in the regional ledger
bucket. Its immutable plan and running executable require separate SHA-256
arguments. It pins the system GCloud script digest, clears supplementary groups
and drops to the configured operator UID/GID before an exact generation-bound
metadata lookup through the operator's login configuration. The 60-second child
and bounded stdout/stderr readers cannot turn into a bulk transfer. Normalized
and raw metadata must agree with the fixed object, generation, 189,943,475,031-byte
length, CRC32C, MD5 and versioned identity. Conflicting aliases fail closed.

Its root-private, fsynced, no-clobber receipt records the systemd invocation and
raw-response digest. It does not authenticate downloaded compressed bytes,
establish original-backup completeness or grant resource admission, collection,
replay, publication or R2 authority. Use a persistent non-restarting oneshot with
the operator configuration writable for token refresh, a 90-second start timeout
and the UID/GID-drop plus `CAP_KILL` capabilities. The latter lets the root parent
kill and reap its own unprivileged SDK child at the bound. An ignored root-only
sandbox test exercises the actual shared UID drop and timeout path with a
disposable sleep child, and proves no-clobber receipt writes beneath a valid
root-private directory. Do not apply the older metadata observer's
epoch203–212 capability assumptions to epoch141.

`jetstreamer-epoch141-ledger-download` provides a separate **fresh-attempt-only**
private transfer wrapper for that same fixed generation. It shares the existing
metadata, UID/GID-drop and receipt primitives with the metadata executable; the
previously sealed metadata deployment is unchanged. Require independent plan and
executable hashes, the exact passed metadata receipt and a passed performance
admission receipt whose file census binds this downloader and metadata receipt.
The admission filesystem must match the staging filesystem, and its free-byte
threshold must cover the complete compressed input plus 64 MiB of transfer slack
above the plan's protected older-growth/century-floor threshold.

The SDK is only the byte transporter. The wrapper pins its script before exec,
uses the operator's exact login configuration, reobserves the generation before
and after transfer, and independently streams the complete file through CRC32C,
MD5 and SHA-256 in Rust. SDK success alone is not verification. Transfer runs in
its own disposable UID1001/GID1003 process group with empty supplementary groups.
The wrapper explicitly disables sliced downloads and pins SDK process/thread
counts to one; operator configuration cannot silently enlarge the transfer's
temporary-file or process envelope. Check the current SDK's property definitions
and download selector before operational deployment.
`waitid(WNOWAIT)` retains the leader identity until group cleanup, avoiding a
reaped-PID/PGID reuse window. Every second the wrapper checks actual free space,
elapsed runtime, regular-file identities and bounded aggregate staging length.
A guard trip writes a durable stop intent before killing/reaping that owned
group, then writes completion. It never stops a replay or controller.
The first passing check writes a separate fsynced initial-guard receipt binding
the invocation, child PID and the exact free/staged byte sample that passed.
Require that receipt and its actual sandboxed service before unattended transfer.

Give the staging directory a canonical root-owned mode-0711 parent so the
unprivileged SDK can traverse it; keep receipt parents root-owned mode 0700.
The wrapper creates the staging leaf no-clobber and refuses an existing attempt,
including a failed partial. After SDK termination it freezes that leaf and the
completed compressed file as root before independent hashing. A successful
root-private no-clobber receipt binds the generation, three digests and file
identity. No retry may discard or overwrite a partial: reviewed SDK tracker or
same-generation resume support is still required before reusing a failed attempt.

Before operational use, seal the exact build, qualify the ignored root SDK-drop/
process-group test under the actual minimal sandbox, run fresh complete resource
admission and bind all older growth claims/guards. Use `Restart=no`,
`KillMode=control-group`, sufficient start timeout and only the capabilities needed
for traversal, UID/GID drop, ownership freeze and owned-child kill. The wrapper's
tests are not production download evidence. A compressed download receipt still
does not prove complete backup contents, native live state, recovered PoH hashes,
runtime compatibility or publication. Bounded complete tar collection and all
subsequent native/PoH/canonical gates remain independently required.

`horizon_legacy_shred::assemble_v1_4_25_padded_batches` provides bounded,
diagnostic-only data-shred assembly for revision
`893cc7647248a3536fb6e6d0b5e51c71446b862d`. It requires a complete contiguous
slot starting at shred zero, the independently resolved SlotMeta last index,
consistent parent/version metadata and the last-in-slot flag. Missing/coding
shards, ordering errors and oversized output fail closed; there is no FEC repair.

The pinned `Shredder::deshred` concatenates payload bytes 88 through 1138 of
every 1228-byte data shred, including padding. It does **not** clip each fragment
to `DataShredHeader.size`. The unit tests encode the fixed-int header layout and
protect this historical behavior, batch boundaries and allocation/identity gates.
They are not an upstream-runtime differential or real-ledger qualification.
Entry-vector decoding, padding checks, complete tick/PoH verification and all
canonical boundary gates still follow; no source completeness, runtime route,
publication or R2 authority is conferred by assembled bytes.

`horizon_legacy_entry::decode_v1_4_25_padded_entries` is the next diagnostic
stage. It bounds total bytes, entries, transactions and signatures; decodes
fixed-integer entry-vector framing and complete legacy transaction wire shapes;
rejects noncanonical ShortU16 lengths and nonzero trailing padding; and derives
the pinned signature Merkle root (leaf prefix zero, node prefix one, odd-leaf
duplication). It distinguishes tick entries from signature-free transactions.
It deliberately does not execute claimed PoH work, authenticate transaction
signatures, sanitize messages, verify tick ordinals, or establish any canonical
boundary. There is no production recovery caller. Complete generation collection,
native live-state resolution, chained entry/tick/PoH verification and the
independent canonical final blockhash checks remain required before recovery.

The pinned historical worker's test-only
`pinned_sdk_legacy_entry_wire_and_signature_merkle_fixture` checks synthetic
wire bytes with that SDK's actual Transaction/Message serialization and MerkleTree.
Run it from `historical-runtime/v1_4_25` with its pinned compiler and bounded build
jobs. Neither that synthetic fixture nor the modern decoder tests qualify a real
ledger, the upstream full Entry implementation, or a runtime route.
