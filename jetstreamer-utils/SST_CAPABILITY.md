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
