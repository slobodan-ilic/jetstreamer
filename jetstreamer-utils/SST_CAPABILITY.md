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
