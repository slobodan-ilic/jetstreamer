//! Proves why point-prefix scans cannot by themselves establish RocksDB live state.
use jetstreamer_utils::horizon_ledger_tar::{CollectionLimits, collect_rocksdb_tar};
use rocksdb::{ColumnFamilyDescriptor, DB, DBCompressionType, Options};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Cursor, os::unix::fs::PermissionsExt, path::Path, process::Command};

// A separate process exits without dropping DB, leaving acknowledged, synced
// writes in the WAL rather than turning the fixture into an SST-only test.
#[test]
#[ignore = "fixture subprocess for native_readonly_resolves_manifest_and_wal"]
fn native_readonly_wal_fixture_child() {
    let Some(path) = env::var_os("JETSTREAMER_NATIVE_WAL_FIXTURE") else {
        return;
    };
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options.set_disable_auto_compactions(true);
    options.set_compression_type(DBCompressionType::Lz4);
    let families = ["default", "data_shred", "meta"]
        .map(|name| ColumnFamilyDescriptor::new(name, options.clone()));
    let database = DB::open_cf_descriptors(&options, path, families).unwrap();
    let cf = database.cf_handle("data_shred").unwrap();
    let slot = 60912004_u64;
    let key = |index: u64| [slot.to_be_bytes(), index.to_be_bytes()].concat();
    for index in 0..=2 {
        database.put_cf(cf, key(index), b"old-sst-value").unwrap();
    }
    database.flush_cf(cf).unwrap();
    let before_slot = [(slot - 1).to_be_bytes(), 0_u64.to_be_bytes()].concat();
    database.delete_range_cf(cf, before_slot, key(1)).unwrap();
    database.delete_cf(cf, key(1)).unwrap();
    database.put_cf(cf, key(2), b"new-wal-value").unwrap();
    database.put_cf(cf, key(3), b"wal-only-value").unwrap();
    database.flush_wal(true).unwrap();
    // Do not run DB's Drop/close: that could flush the memtable and invalidate
    // the deliberately crash-shaped, generation-stable backup fixture.
    std::process::exit(0);
}

#[test]
#[ignore = "explicit native RocksDB qualification; isolated disposable databases only"]
fn native_readonly_resolves_manifest_and_wal() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("complete-db");
    let child = Command::new(env::current_exe().unwrap())
        .args(["--ignored", "--exact", "native_readonly_wal_fixture_child"])
        .env("JETSTREAMER_NATIVE_WAL_FIXTURE", &path)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "fixture failed: {}",
        String::from_utf8_lossy(&child.stderr)
    );
    let files: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(files.iter().any(|p| p.file_name().unwrap() == "CURRENT"));
    assert!(files.iter().any(|p| {
        p.file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("MANIFEST-")
    }));
    assert!(
        files
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "sst"))
    );
    assert!(
        files
            .iter()
            .any(|p| p.extension().is_some_and(|e| e == "log"))
    );
    let input_hashes: Vec<_> = files
        .iter()
        .filter(|p| {
            let name = p.file_name().unwrap().to_string_lossy();
            name == "CURRENT"
                || name.starts_with("MANIFEST-")
                || p.extension().is_some_and(|e| e == "sst" || e == "log")
        })
        .map(|p| (p, Sha256::digest(fs::read(p).unwrap())))
        .collect();
    let options = Options::default();
    let families = DB::list_cf(&options, &path).unwrap();
    assert_eq!(families.len(), 3);
    // Read-only RocksDB may permit a subset; the recovery policy must compare
    // its requested families against the full authenticated manifest census.
    if let Ok(partial) = DB::open_cf_for_read_only(&options, &path, ["data_shred"], false) {
        assert!(partial.cf_handle("meta").is_none());
        assert!(families.iter().any(|family| family == "meta"));
        println!("native read-only subset open is possible: complete CF census is a separate gate");
    }
    // Strict log rejection cannot substitute for recovery of the present WAL.
    assert!(DB::open_cf_for_read_only(&options, &path, &families, true).is_err());
    let database = DB::open_cf_for_read_only(&options, &path, &families, false).unwrap();
    let cf = database.cf_handle("data_shred").unwrap();
    let slot = 60912004_u64;
    let key = |index: u64| [slot.to_be_bytes(), index.to_be_bytes()].concat();
    assert_eq!(database.get_cf(cf, key(0)).unwrap(), None);
    assert_eq!(database.get_cf(cf, key(1)).unwrap(), None);
    assert_eq!(
        database.get_cf(cf, key(2)).unwrap().as_deref(),
        Some(b"new-wal-value".as_slice())
    );
    assert_eq!(
        database.get_cf(cf, key(3)).unwrap().as_deref(),
        Some(b"wal-only-value".as_slice())
    );
    drop(database);
    for (path, before) in input_hashes {
        assert_eq!(
            before,
            Sha256::digest(fs::read(path).unwrap()),
            "native read-only open changed a manifest/WAL/SST input"
        );
    }

    // Exercise the bounded collector against the entire real native fixture,
    // not selected SSTs. Its census retains WALs and every CF's table files.
    // This is still a disposable fixture, not a historical ledger generation.
    let mut archive = tar::Builder::new(Vec::new());
    let mut source_files: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|item| item.unwrap().path())
        .collect();
    source_files.sort();
    for source in &source_files {
        assert!(source.is_file());
        archive
            .append_file(
                Path::new("rocksdb").join(source.file_name().unwrap()),
                &mut fs::File::open(source).unwrap(),
            )
            .unwrap();
    }
    let bytes = archive.into_inner().unwrap();
    let collected = root.path().join("collected-db");
    fs::create_dir(&collected).unwrap();
    fs::set_permissions(&collected, fs::Permissions::from_mode(0o700)).unwrap();
    let census = collect_rocksdb_tar(
        Cursor::new(bytes),
        Path::new("rocksdb"),
        &collected,
        CollectionLimits {
            maximum_files: 128,
            maximum_file_bytes: 16 * 1024 * 1024,
            maximum_total_bytes: 64 * 1024 * 1024,
            maximum_trailer_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    assert_eq!(census.files.len(), source_files.len());
    assert!(!census.wal_files.is_empty());
    assert!(!census.source_completeness_proven && !census.live_state_resolved);
    assert!(!census.publication_authorized);
    for source in &source_files {
        assert_eq!(
            fs::read(source).unwrap(),
            fs::read(collected.join(source.file_name().unwrap())).unwrap()
        );
    }
    // Isolate any native diagnostic log output from the immutable input census.
    let log_path = root.path().join("collected-readonly-logs");
    fs::create_dir(&log_path).unwrap();
    let mut collected_options = Options::default();
    collected_options.set_db_log_dir(&log_path);
    let collected_families = DB::list_cf(&collected_options, &collected).unwrap();
    assert_eq!(collected_families, families);
    let collected_db =
        DB::open_cf_for_read_only(&collected_options, &collected, &collected_families, false)
            .unwrap();
    let collected_cf = collected_db.cf_handle("data_shred").unwrap();
    assert_eq!(collected_db.get_cf(collected_cf, key(0)).unwrap(), None);
    assert_eq!(collected_db.get_cf(collected_cf, key(1)).unwrap(), None);
    assert_eq!(
        collected_db
            .get_cf(collected_cf, key(2))
            .unwrap()
            .as_deref(),
        Some(b"new-wal-value".as_slice())
    );
    assert_eq!(
        collected_db
            .get_cf(collected_cf, key(3))
            .unwrap()
            .as_deref(),
        Some(b"wal-only-value".as_slice())
    );
    let live_files = collected_db.live_files().unwrap();
    assert!(!live_files.is_empty());
    for live in live_files {
        let name = live.name.trim_start_matches('/');
        assert!(
            census
                .files
                .iter()
                .any(|file| file.name == name && file.bytes == live.size as u64)
        );
        assert!(collected_families.contains(&live.column_family_name));
    }
    drop(collected_db);
    for member in &census.files {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(fs::read(collected.join(&member.name)).unwrap())
            ),
            member.sha256,
            "native resolution changed collected input {}",
            member.name
        );
    }
    let mut after_names: Vec<_> = fs::read_dir(&collected)
        .unwrap()
        .map(|item| item.unwrap().file_name().into_string().unwrap())
        .collect();
    after_names.sort();
    assert_eq!(
        after_names,
        census
            .files
            .iter()
            .map(|file| file.name.clone())
            .collect::<Vec<_>>()
    );

    // A successful native open is not by itself proof that a backup is complete.
    // Preserve every file except WALs in a second disposable database and show
    // that omitted-WAL evidence must be rejected, even if RocksDB can open it.
    let incomplete = root.path().join("missing-wal-db");
    fs::create_dir(&incomplete).unwrap();
    for file in &files {
        if file.is_file() && file.extension().is_none_or(|e| e != "log") {
            fs::copy(file, incomplete.join(file.file_name().unwrap())).unwrap();
        }
    }
    match DB::open_cf_for_read_only(&options, &incomplete, &families, false) {
        Ok(incomplete_db) => {
            let incomplete_cf = incomplete_db.cf_handle("data_shred").unwrap();
            assert_eq!(
                incomplete_db
                    .get_cf(incomplete_cf, key(0))
                    .unwrap()
                    .as_deref(),
                Some(b"old-sst-value".as_slice())
            );
            assert_eq!(
                incomplete_db
                    .get_cf(incomplete_cf, key(2))
                    .unwrap()
                    .as_deref(),
                Some(b"old-sst-value".as_slice())
            );
            assert_eq!(incomplete_db.get_cf(incomplete_cf, key(3)).unwrap(), None);
            println!(
                "missing WAL silently resurrects SST values: authenticated complete file census is mandatory"
            );
        }
        Err(error) => println!("native decoder rejected incomplete WAL set: {error}"),
    }
    println!(
        "native read-only resolution honored outside-prefix range tombstone, point deletion, latest WAL version, WAL-only value, and the complete CF set"
    );
}

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
