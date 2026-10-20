//! Private exact-target native candidates, never trusted boundaries/publication.
#[allow(dead_code)]
mod epoch141_ledger_common;

use {
    anyhow::{Context, Result, ensure},
    base64::{Engine, engine::general_purpose::STANDARD},
    epoch141_ledger_common::{
        FROZEN_INPUT, FROZEN_SHA, GENERATION, SIZE, URI, bound_file, identity, is_sha,
        validate_reverification, write_receipt,
    },
    jetstreamer_utils::{
        horizon_ledger_bzip::BoundBzipCollection,
        horizon_ledger_native::{NativeQuery, NativeResolution, resolve_native_candidates},
        horizon_legacy_recovery::{
            LegacySlotScope, ResolvedLegacyRecord, plan_v1_4_25_scope_queries,
        },
    },
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs::{self, File},
        os::unix::fs::{DirBuilderExt, MetadataExt},
        path::{Path, PathBuf},
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

const AUDIT_SHA: &str = "0dd1f9d3148752ca7cc91fcda66e5c7838558318b5749b7a252022536b16c986";
const OUTPUT_RESERVATION: u64 = 256 * 1024 * 1024;
const MAX_OUTPUT: usize = 224 * 1024 * 1024;
const PAIRS: [(u64, u64); 11] = [
    (60911771, 60911776),
    (60911791, 60911796),
    (60911831, 60911833),
    (60911835, 60911840),
    (60911847, 60911852),
    (60911887, 60911892),
    (60911931, 60911936),
    (60911964, 60911969),
    (60911987, 60911990),
    (60911992, 60911995),
    (60911999, 60912004),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bound {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    source_verification: Bound,
    collection_receipt: Bound,
    complete_census: Bound,
    gap_audit: Bound,
    admission_manifest: Bound,
    admission_receipt: PathBuf,
    database_directory: PathBuf,
    expected_families: Vec<String>,
    log_directory: PathBuf,
    initial_guard_receipt: PathBuf,
    metadata_receipt: PathBuf,
    output_receipt: PathBuf,
    minimum_free_bytes: u64,
    maximum_runtime_seconds: u64,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn read_json(e: &Bound, max: u64, immutable: bool) -> Result<Value> {
    Ok(serde_json::from_slice(&bound_file(
        &e.path, &e.sha256, max, immutable,
    )?)?)
}

fn collection(plan: &Plan, receipt: &Value, prior: &Value) -> Result<BoundBzipCollection> {
    ensure!(
        receipt["schema"] == "jetstreamer-epoch141-ledger-collection-receipt-v1"
            && receipt["epoch"] == 141
            && receipt["input"] == FROZEN_INPUT
            && receipt["uri"] == URI
            && receipt["generation"] == GENERATION
            && receipt["source_verification_sha256"] == plan.source_verification.sha256
            && receipt["prior_complete_census_sha256"] == plan.complete_census.sha256
            && receipt["retained_directory"].as_str() == plan.database_directory.to_str()
            && receipt["files_retained"] == true
            && receipt["source_modified"] == false
            && receipt["download_performed"] == false
            && receipt["source_completeness_proven"] == false
            && receipt["live_state_proven"] == false
            && receipt["replay_launch_authorized"] == false
            && receipt["publication_authorized"] == false
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false
            && receipt["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| plan.minimum_free_bytes >= n),
        "wrong complete collection binding or weakened protected floor"
    );
    ensure!(
        prior["schema"] == "jetstreamer-epoch141-ledger-census-receipt-v1"
            && prior["epoch"] == 141
            && prior["input"] == FROZEN_INPUT
            && prior["uri"] == URI
            && prior["generation"] == GENERATION
            && prior["source_verification_sha256"] == plan.source_verification.sha256
            && prior["files_retained"] == false,
        "wrong independent complete census binding"
    );
    let mut compared = receipt["census"].clone();
    compared["collection"]["files_retained"] = false.into();
    ensure!(
        compared == prior["census"],
        "retention differs from independent complete census"
    );
    let bound: BoundBzipCollection = serde_json::from_value(receipt["census"].clone())?;
    ensure!(
        bound.compressed_bytes == SIZE
            && bound.compressed_sha256 == FROZEN_SHA
            && !bound.cloud_generation_authenticated
            && !bound.resource_admission_proven
            && !bound.publication_authorized
            && bound.collection.files_retained
            && bound.collection.archive_root == "rocksdb"
            && !bound.collection.files.is_empty()
            && bound.collection.files.len() <= 100_000
            && !bound.collection.source_completeness_proven
            && !bound.collection.live_state_resolved
            && !bound.collection.publication_authorized,
        "wrong bound compressed collection/profile"
    );
    Ok(bound)
}

fn targets(audit: &Value) -> Result<Vec<LegacySlotScope>> {
    ensure!(
        audit["schema"] == "jetstreamer-horizon-finalized-gap-audit-v1"
            && audit["first_slot"] == 60911751u64
            && audit["last_slot"] == 60912005u64
            && audit["post_gap_targets"] == 11
            && audit["skipped_slots"] == 37
            && audit["expected_tick_boundaries"] == 48
            && audit["hidden_poh_hashes_recovered"] == false
            && audit["publication_authorized"] == false
            && audit["replay_launch_authorized"] == false
            && audit["runtime_promotion_authorized"] == false
            && audit["r2_mutations"] == false,
        "wrong exact epoch141 gap audit"
    );
    let gaps = audit["gaps"].as_array().context("missing target census")?;
    ensure!(gaps.len() == PAIRS.len(), "incomplete target census");
    gaps.iter()
        .zip(PAIRS)
        .map(|(gap, (parent_slot, slot))| {
            ensure!(
                gap["parent_slot"] == parent_slot
                    && gap["slot"] == slot
                    && gap["expected_tick_boundaries"] == slot - parent_slot
                    && gap["skipped_slots"] == slot - parent_slot - 1,
                "substituted target topology"
            );
            for key in ["previous_poh_hash", "final_poh_hash"] {
                let text = gap[key].as_str().context("missing canonical anchor")?;
                let bytes = bs58::decode(text)
                    .into_vec()
                    .map_err(|e| anyhow::anyhow!("invalid canonical anchor: {e}"))?;
                ensure!(
                    bytes.len() == 32 && bs58::encode(bytes).into_string() == text,
                    "invalid anchor encoding"
                );
            }
            Ok(LegacySlotScope { slot, parent_slot })
        })
        .collect()
}

fn admission(plan: &Plan, receipt: &Value, manifest: &Value, exe: &Path, sha: &str) -> Result<()> {
    let required = plan
        .minimum_free_bytes
        .checked_add(OUTPUT_RESERVATION)
        .context("peak overflow")?;
    ensure!(
        receipt["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && receipt["admitted"] == true
            && receipt["manifest"].as_str() == plan.admission_manifest.path.to_str()
            && receipt["manifest_sha256"] == plan.admission_manifest.sha256
            && receipt["services_started"] == false
            && receipt["services_installed"] == false
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false
            && manifest["schema"] == "jetstreamer-historical-performance-admission-v1"
            && manifest["filesystem"] == "/home/sol"
            && manifest["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= required)
            && receipt["evidence"]["minimum_free_bytes"] == manifest["minimum_free_bytes"]
            && receipt["evidence"]["filesystem"] == "/home/sol",
        "wrong native admission envelope"
    );
    for (files, strict) in [
        (&manifest["files"], true),
        (&receipt["evidence"]["files"], false),
    ] {
        ensure!(
            files
                .as_array()
                .context("missing admitted file census")?
                .iter()
                .any(|f| f["path"].as_str() == exe.to_str()
                    && f["sha256"] == sha
                    && (!strict || (f["uid"] == 0 && f["mode"] == "0555"))),
            "admission lacks exact native executable"
        );
    }
    Ok(())
}

fn private_directory(path: &Path) -> Result<fs::Metadata> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == 0
            && m.gid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe private directory"
    );
    Ok(m)
}
fn paths(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-epoch141-ledger-native-plan-v1"
            && plan.minimum_free_bytes > 0
            && (60..=43200).contains(&plan.maximum_runtime_seconds)
            && plan.gap_audit.sha256 == AUDIT_SHA,
        "wrong native plan/bounds/audit"
    );
    let database = private_directory(&plan.database_directory)?;
    let logs = private_directory(&plan.log_directory)?;
    ensure!(
        fs::read_dir(&plan.log_directory)?.next().is_none(),
        "logs are not a fresh attempt"
    );
    let result = plan
        .output_receipt
        .parent()
        .context("missing output parent")?;
    let output = private_directory(result)?;
    ensure!(
        database.dev() == fs::metadata("/home/sol")?.dev()
            && logs.dev() == database.dev()
            && output.dev() == database.dev(),
        "native admission/output filesystem mismatch"
    );
    ensure!(
        !plan.log_directory.starts_with(&plan.database_directory)
            && !plan.database_directory.starts_with(&plan.log_directory)
            && !result.starts_with(&plan.database_directory)
            && !plan.database_directory.starts_with(result)
            && result != plan.log_directory
            && !plan
                .log_directory
                .starts_with(Path::new(FROZEN_INPUT).parent().unwrap())
            && !result.starts_with(Path::new(FROZEN_INPUT).parent().unwrap()),
        "overlapping input/output/log paths"
    );
    let mut outputs = std::collections::BTreeSet::new();
    for output in [
        &plan.initial_guard_receipt,
        &plan.metadata_receipt,
        &plan.output_receipt,
    ] {
        ensure!(
            output.is_absolute()
                && output.parent() == Some(result)
                && outputs.insert(output)
                && fs::symlink_metadata(output)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "unsafe, duplicated or existing output"
        );
    }
    let families: std::collections::BTreeSet<_> = plan.expected_families.iter().collect();
    ensure!(
        families.len() == plan.expected_families.len()
            && families.len() <= 64
            && ["default", "meta", "data_shred"]
                .iter()
                .all(|name| plan.expected_families.iter().any(|f| f == name)),
        "missing/duplicate independent family policy"
    );
    Ok(())
}

fn guard(plan: &Plan, start: Instant) -> Result<u64> {
    ensure!(
        start.elapsed().as_secs() < plan.maximum_runtime_seconds,
        "native runtime exceeded"
    );
    let path = CString::new(plan.database_directory.as_os_str().as_encoded_bytes())?;
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), state.as_mut_ptr()) } == 0,
        "native statvfs failed"
    );
    let state = unsafe { state.assume_init() };
    let free = state
        .f_bavail
        .checked_mul(state.f_frsize)
        .context("available byte overflow")?;
    ensure!(
        free >= plan.minimum_free_bytes,
        "native protected-space floor crossed"
    );
    Ok(free)
}

fn records(resolution: &NativeResolution) -> Vec<ResolvedLegacyRecord<'_>> {
    resolution
        .candidates
        .iter()
        .map(|r| ResolvedLegacyRecord {
            family: &r.family,
            key: &r.key,
            value: r.value.as_deref(),
        })
        .collect()
}
fn encoded(resolution: &NativeResolution) -> Value {
    json!({"families":resolution.families,"live_sst_references":resolution.live_sst_references,
        "complete_census_revalidated":resolution.complete_census_revalidated,
        "records":resolution.candidates.iter().map(|r|json!({"family":r.family,
            "key_base64":STANDARD.encode(&r.key),"value_base64":r.value.as_ref().map(|v|STANDARD.encode(v))})).collect::<Vec<_>>()})
}
fn bounded_write(path: &Path, value: &Value) -> Result<usize> {
    let bytes = serde_json::to_vec_pretty(value)?.len() + 1;
    ensure!(bytes < MAX_OUTPUT, "native result output bound exceeded");
    write_receipt(path, value)?;
    Ok(bytes)
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "native runner requires root"
    );
    let mut args = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        ensure!(
            [
                "--plan",
                "--plan-sha256",
                "--self-sha256",
                "--admission-sha256",
                "--check-only"
            ]
            .contains(&key.as_str()),
            "unknown argument"
        );
        let value = if key == "--check-only" {
            "true".into()
        } else {
            args.next().context("missing argument value")?
        };
        ensure!(values.insert(key, value).is_none(), "duplicate argument");
    }
    for key in [
        "--plan",
        "--plan-sha256",
        "--self-sha256",
        "--admission-sha256",
    ] {
        ensure!(values.contains_key(key), "missing {key}");
    }
    let exe = fs::read_link("/proc/self/exe")?;
    bound_file(&exe, &values["--self-sha256"], 64 * 1024 * 1024, true)?;
    let plan_path = Path::new(&values["--plan"]);
    let plan: Plan = serde_json::from_slice(&bound_file(
        plan_path,
        &values["--plan-sha256"],
        65536,
        true,
    )?)?;
    paths(&plan)?;
    let source = read_json(&plan.source_verification, 65536, false)?;
    validate_reverification(&source)?;
    let source_identity = fs::symlink_metadata(FROZEN_INPUT)?;
    ensure!(
        serde_json::to_value(identity(&source_identity))? == source["identity"],
        "frozen source identity changed"
    );
    let retained = read_json(&plan.collection_receipt, 32 * 1024 * 1024, false)?;
    let prior = read_json(&plan.complete_census, 32 * 1024 * 1024, false)?;
    let bound = collection(&plan, &retained, &prior)?;
    ensure!(
        bound.input_device == source_identity.dev() && bound.input_inode == source_identity.ino(),
        "collection compressed inode differs from verified source"
    );
    let audit = read_json(&plan.gap_audit, 4 * 1024 * 1024, false)?;
    let scopes = targets(&audit)?;
    let manifest = read_json(&plan.admission_manifest, 4 * 1024 * 1024, true)?;
    ensure!(
        fs::symlink_metadata(&plan.admission_manifest.path)?.mode() & 0o077 == 0,
        "admission manifest must be owner-only"
    );
    let admitted: Value = serde_json::from_slice(&bound_file(
        &plan.admission_receipt,
        &values["--admission-sha256"],
        4 * 1024 * 1024,
        false,
    )?)?;
    admission(&plan, &admitted, &manifest, &exe, &values["--self-sha256"])?;
    let age = now()?
        .checked_sub(u64::try_from(
            fs::symlink_metadata(&plan.admission_receipt)?.mtime(),
        )?)
        .context("future admission")?;
    ensure!(age <= 300, "native admission older than300seconds");
    let start = Instant::now();
    let free = guard(&plan, start)?;
    if values.contains_key("--check-only") {
        println!("native local bindings passed; no native open, output or mutation");
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("systemd invocation required")?;
    ensure!(
        invocation.len() == 32 && is_sha(&format!("{invocation}{invocation}")),
        "invalid invocation"
    );
    bounded_write(
        &plan.initial_guard_receipt,
        &json!({"schema":"jetstreamer-epoch141-native-initial-guard-v1",
        "epoch":141,"invocation_id":invocation,"self_sha256":values["--self-sha256"],
        "plan_sha256":values["--plan-sha256"],"admission_sha256":values["--admission-sha256"],
        "available_bytes":free,"minimum_free_bytes":plan.minimum_free_bytes,"trip":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    let mut last = Instant::now();
    let mut callback = || {
        if last.elapsed().as_secs() >= 1 {
            guard(&plan, start)?;
            last = Instant::now();
        }
        Ok(())
    };
    let resolve = |queries: &[NativeQuery],
                   name: &str,
                   callback: &mut dyn FnMut() -> Result<()>|
     -> Result<NativeResolution> {
        let logs = plan.log_directory.join(name);
        fs::DirBuilder::new().mode(0o700).create(&logs)?;
        File::open(&plan.log_directory)?.sync_all()?;
        resolve_native_candidates(
            &plan.database_directory,
            &bound.collection,
            &logs,
            &plan.expected_families,
            queries,
            callback,
        )
    };
    let queries: Vec<_> = scopes
        .iter()
        .map(|s| NativeQuery {
            family: "meta".into(),
            key: s.slot.to_be_bytes().to_vec(),
        })
        .collect();
    let first = resolve(&queries, "metadata", &mut callback)?;
    guard(&plan, start)?;
    let metadata_all_present = first.candidates.iter().all(|c| c.value.is_some());
    let metadata_bytes = bounded_write(
        &plan.metadata_receipt,
        &json!({"schema":"jetstreamer-epoch141-native-metadata-candidates-v1",
        "epoch":141,"invocation_id":invocation,"plan_sha256":values["--plan-sha256"],
        "self_sha256":values["--self-sha256"],"collection_sha256":plan.collection_receipt.sha256,
        "gap_audit_sha256":plan.gap_audit.sha256,"all_records_present":metadata_all_present,"resolution":encoded(&first),
        "source_completeness_proven":false,"live_state_proven":false,"runtime_clock_authenticated":false,
        "hidden_poh_hashes_recovered":false,"runtime_promotion_authorized":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false}),
    )?;
    let first_records = records(&first);
    let query_plan =
        plan_v1_4_25_scope_queries(&first_records, &scopes).map_err(anyhow::Error::msg)?;
    let queries: Vec<_> = query_plan
        .iter()
        .map(|q| NativeQuery {
            family: q.family.into(),
            key: q.key.clone(),
        })
        .collect();
    let complete = resolve(&queries, "complete-targets", &mut callback)?;
    let unchanged = first.candidates.iter().all(|m| {
        complete
            .candidates
            .iter()
            .any(|c| c.family == m.family && c.key == m.key && c.value == m.value)
    });
    let present = complete.candidates.iter().all(|c| c.value.is_some());
    let after = guard(&plan, start)?;
    for evidence in [
        &plan.source_verification,
        &plan.collection_receipt,
        &plan.complete_census,
        &plan.gap_audit,
    ] {
        read_json(evidence, 32 * 1024 * 1024, false)?;
    }
    bound_file(plan_path, &values["--plan-sha256"], 65536, true)?;
    let output = json!({"schema":"jetstreamer-epoch141-native-candidates-v1","epoch":141,
        "recorded_unix_seconds":now()?,"invocation_id":invocation,"self_sha256":values["--self-sha256"],
        "plan_sha256":values["--plan-sha256"],"source_verification_sha256":plan.source_verification.sha256,
        "collection_sha256":plan.collection_receipt.sha256,"complete_census_sha256":plan.complete_census.sha256,
        "gap_audit_sha256":plan.gap_audit.sha256,"admission_sha256":values["--admission-sha256"],
        "all_records_present":present,"metadata_unchanged":unchanged,"target_count":scopes.len(),
        "available_bytes_before":free,"available_bytes_before_result":after,"minimum_free_bytes":plan.minimum_free_bytes,
        "elapsed_seconds":start.elapsed().as_secs(),"resolution":encoded(&complete),
        "source_completeness_proven":false,"live_state_proven":false,"runtime_clock_authenticated":false,
        "hidden_poh_hashes_recovered":false,"runtime_promotion_authorized":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false});
    ensure!(
        metadata_bytes + serde_json::to_vec_pretty(&output)?.len() + 8192
            <= OUTPUT_RESERVATION as usize - 64 * 1024 * 1024,
        "combined native outputs exceed admitted allowance"
    );
    bounded_write(&plan.output_receipt, &output)?;
    ensure!(
        present && unchanged,
        "diagnostic candidate receipt preserves missing values or changed metadata; not complete recovery"
    );
    println!("complete planned native candidates durable; no PoH/replay/publication authority");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> Plan {
        serde_json::from_value(
            json!({"schema":"jetstreamer-epoch141-ledger-native-plan-v1",
            "source_verification":{"path":"/proof/source.json","sha256":"1".repeat(64)},
            "collection_receipt":{"path":"/proof/collection.json","sha256":"2".repeat(64)},
            "complete_census":{"path":"/proof/census.json","sha256":"3".repeat(64)},
            "gap_audit":{"path":"/proof/gaps.json","sha256":AUDIT_SHA},
            "admission_manifest":{"path":"/proof/admission.json","sha256":"4".repeat(64)},
            "admission_receipt":"/proof/admitted.json","database_directory":"/private/db",
            "expected_families":["default","meta","data_shred"],"log_directory":"/result/logs",
            "initial_guard_receipt":"/result/initial.json","metadata_receipt":"/result/meta.json",
            "output_receipt":"/result/candidates.json","minimum_free_bytes":1000000,
            "maximum_runtime_seconds":60}),
        )
        .unwrap()
    }
    fn collection_fixture(p: &Plan) -> (Value, Value) {
        let census = json!({"compressed_sha256":FROZEN_SHA,"compressed_bytes":SIZE,
            "input_device":1,"input_inode":2,"cloud_generation_authenticated":false,
            "resource_admission_proven":false,"publication_authorized":false,
            "collection":{"files_retained":true,"archive_root":"rocksdb",
                "files":[{"name":"CURRENT","bytes":11,"sha256":"5".repeat(64)}],
                "total_bytes":11,"current_manifest":"MANIFEST-1","wal_files":[],
                "source_completeness_proven":false,"live_state_resolved":false,"publication_authorized":false}});
        let receipt = json!({"schema":"jetstreamer-epoch141-ledger-collection-receipt-v1",
            "epoch":141,"input":FROZEN_INPUT,"uri":URI,"generation":GENERATION,
            "source_verification_sha256":p.source_verification.sha256,
            "prior_complete_census_sha256":p.complete_census.sha256,"retained_directory":p.database_directory,
            "files_retained":true,"source_modified":false,"download_performed":false,
            "source_completeness_proven":false,"live_state_proven":false,"replay_launch_authorized":false,
            "publication_authorized":false,"remote_mutations":false,"r2_mutations":false,
            "minimum_free_bytes":p.minimum_free_bytes,"census":census});
        let mut prior = receipt.clone();
        prior["schema"] = "jetstreamer-epoch141-ledger-census-receipt-v1".into();
        prior["files_retained"] = false.into();
        prior["census"]["collection"]["files_retained"] = false.into();
        (receipt, prior)
    }
    #[test]
    fn collection_requires_exact_source_retention_and_independent_census() {
        let p = plan();
        let (good, prior) = collection_fixture(&p);
        collection(&p, &good, &prior).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(
                collection(&p, &changed, &prior).is_err(),
                "accepted missing {key}"
            );
        }
        for (pointer, value) in [
            ("/census/compressed_sha256", json!("6".repeat(64))),
            ("/census/collection/files_retained", json!(false)),
            ("/census/collection/live_state_resolved", json!(true)),
            ("/census/collection/files/0/bytes", json!(12)),
        ] {
            let mut changed = good.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                collection(&p, &changed, &prior).is_err(),
                "accepted {pointer}"
            );
        }
        let mut changed = prior.clone();
        changed["census"]["compressed_bytes"] = 1.into();
        assert!(collection(&p, &good, &changed).is_err());
        let mut changed = good;
        changed["census"]["extra_field"] = true.into();
        let mut prior = prior;
        prior["census"]["extra_field"] = true.into();
        assert!(collection(&p, &changed, &prior).is_err());
    }
    fn audit() -> Value {
        json!({"schema":"jetstreamer-horizon-finalized-gap-audit-v1","first_slot":60911751u64,
            "last_slot":60912005u64,"post_gap_targets":11,"skipped_slots":37,
            "expected_tick_boundaries":48,"hidden_poh_hashes_recovered":false,
            "publication_authorized":false,"replay_launch_authorized":false,
            "runtime_promotion_authorized":false,"r2_mutations":false,
            "gaps":PAIRS.iter().map(|&(parent,slot)|json!({"parent_slot":parent,"slot":slot,
                "expected_tick_boundaries":slot-parent,"skipped_slots":slot-parent-1,
                "previous_poh_hash":bs58::encode([1u8;32]).into_string(),
                "final_poh_hash":bs58::encode([2u8;32]).into_string()})).collect::<Vec<_>>()})
    }
    #[test]
    fn exact_eleven_target_topology_cannot_be_dropped_changed_or_reordered() {
        let good = audit();
        assert_eq!(targets(&good).unwrap().len(), 11);
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(targets(&changed).is_err(), "accepted missing {key}");
        }
        let mut changed = good.clone();
        changed["gaps"].as_array_mut().unwrap().swap(0, 1);
        assert!(targets(&changed).is_err());
        let mut changed = good.clone();
        changed["gaps"][0]["slot"] = 60911777u64.into();
        assert!(targets(&changed).is_err());
        let mut changed = good;
        changed["gaps"][0]["final_poh_hash"] = "bad".into();
        assert!(targets(&changed).is_err());
    }
    #[test]
    fn native_admission_requires_full_output_peak_and_exact_executable() {
        let p = plan();
        let exe = Path::new("/sealed/native");
        let sha = "5".repeat(64);
        let required = p.minimum_free_bytes + OUTPUT_RESERVATION;
        let files = json!([{"path":exe,"sha256":sha,"uid":0,"mode":"0555"}]);
        let manifest = json!({"schema":"jetstreamer-historical-performance-admission-v1",
            "filesystem":"/home/sol","minimum_free_bytes":required,"files":files});
        let good = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1",
            "admitted":true,"manifest":p.admission_manifest.path,"manifest_sha256":p.admission_manifest.sha256,
            "services_started":false,"services_installed":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"minimum_free_bytes":required,"filesystem":"/home/sol","files":files}});
        admission(&p, &good, &manifest, exe, &sha).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(
                admission(&p, &changed, &manifest, exe, &sha).is_err(),
                "accepted missing {key}"
            );
        }
        let mut less = manifest.clone();
        less["minimum_free_bytes"] = (required - 1).into();
        let mut receipt = good.clone();
        receipt["evidence"]["minimum_free_bytes"] = (required - 1).into();
        assert!(admission(&p, &receipt, &less, exe, &sha).is_err());
        assert!(admission(&p, &good, &manifest, exe, &"6".repeat(64)).is_err());
        let mut timed = plan();
        timed.maximum_runtime_seconds = 0;
        assert!(
            guard(&timed, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("runtime")
        );
    }
    #[test]
    #[ignore = "root-only disposable private receipt qualification, not actual-source native sandbox"]
    fn native_candidate_receipts_are_private_durable_and_no_clobber() {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("candidates.json");
        let value = json!({"publication_authorized":false,"records":[]});
        assert!(bounded_write(&path, &value).unwrap() > 0);
        let original = fs::read(&path).unwrap();
        assert!(bounded_write(&path, &json!({"changed":true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o777, 0o600);
    }
}
