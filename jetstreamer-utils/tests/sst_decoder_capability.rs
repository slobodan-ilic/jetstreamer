//! Proves why point-prefix scans cannot by themselves establish RocksDB live state.
use rocksdb::{ColumnFamilyDescriptor, DB, DBCompressionType, Options};
use std::{env, fs, process::Command};

#[test]
#[ignore = "requires separately pinned JETSTREAMER_SST_DUMP_TEST_BIN"]
fn native_sst_prefix_reader_exposes_versions_but_needs_range_tombstones() {
    let binary = env::var_os("JETSTREAMER_SST_DUMP_TEST_BIN")
        .expect("set the exact candidate sst_dump path");
    for compression in [DBCompressionType::None, DBCompressionType::Lz4] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("db");
        let mut options = Options::default();
        options.create_if_missing(true);
        options.create_missing_column_families(true);
        options.set_disable_auto_compactions(true);
        options.set_compression_type(compression);
        let families = [
            ColumnFamilyDescriptor::new("default", options.clone()),
            ColumnFamilyDescriptor::new("data_shred", options.clone()),
        ];
        let database = DB::open_cf_descriptors(&options, &path, families).unwrap();
        let cf = database.cf_handle("data_shred").unwrap();
        let slot = 60912004_u64;
        let key = |index: u64| [slot.to_be_bytes(), index.to_be_bytes()].concat();
        database.put_cf(cf, key(0), b"older").unwrap();
        database.flush_cf(cf).unwrap();
        database.put_cf(cf, key(0), b"latest").unwrap();
        database.put_cf(cf, key(1), b"point-delete").unwrap();
        database.flush_cf(cf).unwrap();
        database.delete_cf(cf, key(1)).unwrap();
        // Start outside the selected slot prefix: a prefix-only scan cannot
        // discover this covering range tombstone by its start key.
        let range_start = [(slot - 1).to_be_bytes(), 0_u64.to_be_bytes()].concat();
        database.delete_range_cf(cf, range_start, key(1)).unwrap();
        database.flush_cf(cf).unwrap();
        assert!(database.get_cf(cf, key(0)).unwrap().is_none());
        assert!(database.get_cf(cf, key(1)).unwrap().is_none());

        let mut scans = String::new();
        let mut properties = String::new();
        let mut ssts = 0;
        for entry in fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            if entry
                .path()
                .extension()
                .is_none_or(|extension| extension != "sst")
            {
                continue;
            }
            ssts += 1;
            let output = Command::new(&binary)
                .arg(format!("--file={}", entry.path().display()))
                .args(["--command=identify", "--show_properties"])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "identify failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            properties.push_str(&String::from_utf8(output.stdout).unwrap());
            properties.push_str(&String::from_utf8(output.stderr).unwrap());
            let output = Command::new(&binary)
                .arg(format!("--file={}", entry.path().display()))
                .arg(format!("--prefix=0x{slot:016X}"))
                .args([
                    "--command=scan",
                    "--input_key_hex",
                    "--output_hex",
                    "--verify_checksum",
                ])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "scan failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            scans.push_str(&String::from_utf8(output.stdout).unwrap());
        }
        assert!(
            ssts >= 3,
            "fixture needs separate internal versions and tombstones"
        );
        assert!(scans.contains("6F6C646572"), "old value absent: {scans}");
        assert!(
            scans.contains("6C6174657374"),
            "newer point value absent: {scans}"
        );
        assert!(scans.contains("type:0"), "point tombstone absent: {scans}");
        assert!(
            properties.contains("data_shred"),
            "column family absent: {properties}"
        );
        assert!(
            properties
                .lines()
                .any(|line| line.contains("range deletions")
                    && line.split(':').next_back().is_some_and(|v| v.trim() == "1")),
            "range tombstone property absent: {properties}"
        );
        // The greatest point version of key(0) exists in the scan while the native
        // logical read returns None: selecting point sequence numbers alone is wrong.
        println!(
            "{compression:?}: native decoding passed; range tombstone demonstrably overrides point-prefix results"
        );
    }
}
