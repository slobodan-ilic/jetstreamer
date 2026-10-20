//! Private complete census of the already verified frozen epoch141 ledger.
//! No extracted files, download, replay, native liveness or publication authority.
// The shared module includes SDK helpers used by the download/reverify siblings;
// this offline census deliberately never calls those helpers.
#[allow(dead_code)]
mod epoch141_ledger_common;

use {
    anyhow::{Context, Result, ensure},
    epoch141_ledger_common::{
        CRC, GENERATION, MD5, SIZE, URI, bound_file, identity, is_sha, write_receipt,
    },
    jetstreamer_utils::{
        horizon_ledger_bzip::census_bound_bzip2_guarded, horizon_ledger_tar::CollectionLimits,
    },
    serde::Deserialize,
    serde_json::{Value, json},
    std::{
        collections::BTreeMap,
        env,
        ffi::CString,
        fs,
        os::unix::fs::MetadataExt,
        path::{Path, PathBuf},
        time::{Instant, SystemTime, UNIX_EPOCH},
    },
};

const INPUT: &str =
    "/home/sol/.jetstreamer-private/epoch141-ledger-source-20261020-v1/download/rocksdb.tar.bz2";
const SOURCE_SHA: &str = "7af478aec31809cebdeae761d44c19bb90bf06e15d2430813b3b0fe691e6a70b";

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
    admission_manifest: Bound,
    admission_receipt: PathBuf,
    initial_guard_receipt: PathBuf,
    output_receipt: PathBuf,
    archive_root: PathBuf,
    minimum_free_bytes: u64,
    maximum_runtime_seconds: u64,
    maximum_files: usize,
    maximum_file_bytes: u64,
    maximum_total_bytes: u64,
    maximum_trailer_bytes: u64,
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn validate_source(receipt: &Value) -> Result<()> {
    ensure!(
        receipt["schema"] == "jetstreamer-epoch141-ledger-reverification-receipt-v1"
            && receipt["epoch"] == 141
            && receipt["compressed_input_verified"] == true
            && receipt["path"] == INPUT
            && receipt["bytes"] == SIZE
            && receipt["sha256"] == SOURCE_SHA
            && receipt["uri"] == URI
            && receipt["generation"] == GENERATION
            && receipt["crc32c_base64"] == CRC
            && receipt["md5_base64"] == MD5
            && receipt["source_modified"] == false
            && receipt["download_performed"] == false,
        "wrong compressed-source verification"
    );
    Ok(())
}

fn validate_bounds(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-epoch141-ledger-census-plan-v1",
        "wrong plan schema"
    );
    ensure!(
        plan.minimum_free_bytes >= 5_153_013_784_006
            && (60..=43200).contains(&plan.maximum_runtime_seconds)
            && (1..=100_000).contains(&plan.maximum_files)
            && (1..=512 * 1024 * 1024 * 1024).contains(&plan.maximum_file_bytes)
            && (1..=16 * 1024 * 1024 * 1024 * 1024).contains(&plan.maximum_total_bytes)
            && (512..=16 * 1024 * 1024).contains(&plan.maximum_trailer_bytes),
        "unsafe census bounds"
    );
    ensure!(
        plan.archive_root == Path::new("rocksdb"),
        "unqualified archive root"
    );
    ensure!(
        plan.output_receipt.is_absolute()
            && plan.admission_receipt.is_absolute()
            && plan.output_receipt != plan.admission_receipt
            && !plan
                .output_receipt
                .starts_with(Path::new(INPUT).parent().unwrap()),
        "unsafe output scope"
    );
    ensure!(
        plan.initial_guard_receipt != plan.output_receipt
            && plan.initial_guard_receipt != plan.admission_receipt
            && plan.initial_guard_receipt.parent() == plan.output_receipt.parent(),
        "unsafe initial guard path"
    );
    let parent = plan
        .output_receipt
        .parent()
        .context("missing output parent")?;
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        parent.canonicalize()? == parent
            && m.is_dir()
            && m.uid() == 0
            && m.mode() & 0o7777 == 0o700,
        "unsafe output parent"
    );
    ensure!(
        fs::symlink_metadata(&plan.output_receipt)
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "output already exists"
    );
    Ok(())
}

fn validate_admission(
    plan: &Plan,
    receipt: &Value,
    manifest: &Value,
    executable: &Path,
    executable_sha: &str,
) -> Result<()> {
    ensure!(
        receipt["schema"] == "jetstreamer-historical-performance-admission-receipt-v1"
            && receipt["admitted"] == true
            && receipt["manifest"].as_str() == plan.admission_manifest.path.to_str()
            && receipt["manifest_sha256"] == plan.admission_manifest.sha256
            && receipt["services_started"] == false
            && receipt["services_installed"] == false
            && receipt["remote_mutations"] == false
            && receipt["r2_mutations"] == false,
        "wrong exact admission binding"
    );
    ensure!(
        manifest["schema"] == "jetstreamer-historical-performance-admission-v1"
            && manifest["filesystem"] == "/home/sol"
            && manifest["minimum_free_bytes"]
                .as_u64()
                .is_some_and(|n| n >= plan.minimum_free_bytes)
            && receipt["evidence"]["minimum_free_bytes"] == manifest["minimum_free_bytes"]
            && receipt["evidence"]["filesystem"] == "/home/sol",
        "wrong admission envelope"
    );
    let files = manifest["files"]
        .as_array()
        .context("missing admission file census")?;
    ensure!(
        files
            .iter()
            .any(|f| f["path"].as_str() == executable.to_str()
                && f["sha256"] == executable_sha
                && f["uid"] == 0
                && f["mode"] == "0555"),
        "admission lacks exact census executable"
    );
    ensure!(
        receipt["evidence"]["files"]
            .as_array()
            .context("missing admitted file census")?
            .iter()
            .any(|f| f["path"].as_str() == executable.to_str() && f["sha256"] == executable_sha),
        "admission did not observe exact executable"
    );
    Ok(())
}

fn guard(plan: &Plan, start: Instant) -> Result<u64> {
    ensure!(
        start.elapsed().as_secs() < plan.maximum_runtime_seconds,
        "census runtime exceeded"
    );
    let path = CString::new(INPUT)?;
    let mut state = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), state.as_mut_ptr()) } == 0,
        "cannot read available bytes"
    );
    let state = unsafe { state.assume_init() };
    let free = state
        .f_bavail
        .checked_mul(state.f_frsize)
        .context("free byte overflow")?;
    ensure!(
        free >= plan.minimum_free_bytes,
        "census protected-space floor crossed"
    );
    Ok(free)
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "census requires root");
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
            "unknown option"
        );
        let value = if key == "--check-only" {
            "true".into()
        } else {
            args.next().context("missing value")?
        };
        ensure!(values.insert(key, value).is_none(), "duplicate argument");
    }
    for key in [
        "--plan",
        "--plan-sha256",
        "--self-sha256",
        "--admission-sha256",
    ] {
        ensure!(values.contains_key(key), "missing argument {key}");
    }
    let executable = fs::read_link("/proc/self/exe")?;
    bound_file(
        &executable,
        &values["--self-sha256"],
        64 * 1024 * 1024,
        true,
    )?;
    let plan_bytes = bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    validate_bounds(&plan)?;
    let source: Value = serde_json::from_slice(&bound_file(
        &plan.source_verification.path,
        &plan.source_verification.sha256,
        65536,
        false,
    )?)?;
    validate_source(&source)?;
    ensure!(
        source["minimum_free_bytes"]
            .as_u64()
            .is_some_and(|n| plan.minimum_free_bytes >= n),
        "weakened source protected floor"
    );
    let input = Path::new(INPUT);
    let before = fs::symlink_metadata(input)?;
    ensure!(
        serde_json::to_value(identity(&before))? == source["identity"]
            && before.gid() == 0
            && input.canonicalize()? == input,
        "source identity differs from verification"
    );
    let manifest: Value = serde_json::from_slice(&bound_file(
        &plan.admission_manifest.path,
        &plan.admission_manifest.sha256,
        4 * 1024 * 1024,
        true,
    )?)?;
    let admission: Value = serde_json::from_slice(&bound_file(
        &plan.admission_receipt,
        &values["--admission-sha256"],
        4 * 1024 * 1024,
        false,
    )?)?;
    validate_admission(
        &plan,
        &admission,
        &manifest,
        &executable,
        &values["--self-sha256"],
    )?;
    let m = fs::symlink_metadata(&plan.admission_receipt)?;
    let age = now()?
        .checked_sub(u64::try_from(m.mtime())?)
        .context("future admission timestamp")?;
    ensure!(age <= 300, "admission is older than300seconds");
    let start = Instant::now();
    let free_before = guard(&plan, start)?;
    if values.contains_key("--check-only") {
        println!("census local bindings passed; no scan, output or mutation");
        return Ok(());
    }
    let invocation = env::var("INVOCATION_ID").context("systemd invocation required")?;
    ensure!(
        invocation.len() == 32 && is_sha(&format!("{invocation}{invocation}")),
        "invalid invocation"
    );
    write_receipt(
        &plan.initial_guard_receipt,
        &json!({
            "schema":"jetstreamer-epoch141-ledger-census-initial-guard-v1", "epoch":141,
            "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],
            "self_sha256":values["--self-sha256"],"admission_receipt_sha256":values["--admission-sha256"],
            "available_bytes":free_before,"minimum_free_bytes":plan.minimum_free_bytes,
            "trip":false,"files_retained":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    let mut last_guard = Instant::now();
    let census = census_bound_bzip2_guarded(
        input,
        SIZE,
        SOURCE_SHA,
        SIZE,
        &plan.archive_root,
        CollectionLimits {
            maximum_files: plan.maximum_files,
            maximum_file_bytes: plan.maximum_file_bytes,
            maximum_total_bytes: plan.maximum_total_bytes,
            maximum_trailer_bytes: plan.maximum_trailer_bytes,
        },
        || {
            if last_guard.elapsed().as_secs() >= 1 {
                guard(&plan, start)?;
                last_guard = Instant::now();
            }
            Ok(())
        },
    )?;
    let free_after = guard(&plan, start)?;
    ensure!(
        identity(&before) == identity(&fs::symlink_metadata(input)?),
        "source identity changed"
    );
    ensure!(
        !census.collection.files_retained,
        "unexpected file retention"
    );
    bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    validate_bounds(&plan)?;
    write_receipt(
        &plan.output_receipt,
        &json!({
            "schema":"jetstreamer-epoch141-ledger-census-receipt-v1", "epoch":141,
            "recorded_unix_seconds":now()?, "invocation_id":invocation,
            "self_sha256":values["--self-sha256"], "plan_sha256":values["--plan-sha256"],
            "source_verification_sha256":plan.source_verification.sha256,
            "admission_manifest_sha256":plan.admission_manifest.sha256,
            "admission_receipt_sha256":values["--admission-sha256"], "input":INPUT,
            "uri":URI, "generation":GENERATION, "census":census,
            "available_bytes_before":free_before,"available_bytes_after":free_after,
            "minimum_free_bytes":plan.minimum_free_bytes,"elapsed_seconds":start.elapsed().as_secs(),
            "source_modified":false,"download_performed":false,"files_retained":false,
            "source_completeness_proven":false,"live_state_proven":false,
            "replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("complete private ledger census durable; no extraction or recovery authority");
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
        Plan {
            schema: "jetstreamer-epoch141-ledger-census-plan-v1".into(),
            source_verification: Bound {
                path: "/proof/source.json".into(),
                sha256: "1".repeat(64),
            },
            admission_manifest: Bound {
                path: "/proof/admission.json".into(),
                sha256: "2".repeat(64),
            },
            admission_receipt: "/proof/admitted.json".into(),
            initial_guard_receipt: "/result/initial-guard.json".into(),
            output_receipt: "/result/census.json".into(),
            archive_root: "rocksdb".into(),
            minimum_free_bytes: 5_153_013_784_006,
            maximum_runtime_seconds: 60,
            maximum_files: 100,
            maximum_file_bytes: 1024,
            maximum_total_bytes: 4096,
            maximum_trailer_bytes: 4096,
        }
    }

    #[test]
    fn rejects_source_transport_identity_or_digest_mismatch() {
        let good = json!({"schema":"jetstreamer-epoch141-ledger-reverification-receipt-v1",
            "epoch":141,"compressed_input_verified":true,"path":INPUT,"bytes":SIZE,
            "sha256":SOURCE_SHA,"uri":URI,"generation":GENERATION,"crc32c_base64":CRC,
            "md5_base64":MD5,"source_modified":false,"download_performed":false});
        validate_source(&good).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(validate_source(&changed).is_err(), "accepted missing {key}");
        }
        let mut changed = good;
        changed["generation"] = "1634789748052740".into();
        assert!(validate_source(&changed).is_err());
    }

    #[test]
    fn admission_requires_exact_manifest_binary_and_envelope() {
        let plan = plan();
        let executable = Path::new("/sealed/census");
        let hash = "3".repeat(64);
        let files = json!([{"path":executable,"sha256":hash,"uid":0,"mode":"0555"}]);
        let manifest = json!({"schema":"jetstreamer-historical-performance-admission-v1",
            "filesystem":"/home/sol","minimum_free_bytes":plan.minimum_free_bytes,"files":files});
        let good = json!({"schema":"jetstreamer-historical-performance-admission-receipt-v1",
            "admitted":true,"manifest":plan.admission_manifest.path,
            "manifest_sha256":plan.admission_manifest.sha256,"services_started":false,
            "services_installed":false,"remote_mutations":false,"r2_mutations":false,
            "evidence":{"filesystem":"/home/sol","minimum_free_bytes":plan.minimum_free_bytes,"files":files}});
        validate_admission(&plan, &good, &manifest, executable, &hash).unwrap();
        for key in good.as_object().unwrap().keys() {
            let mut changed = good.clone();
            changed[key] = Value::Null;
            assert!(
                validate_admission(&plan, &changed, &manifest, executable, &hash).is_err(),
                "accepted missing {key}"
            );
        }
        for key in ["files", "minimum_free_bytes", "filesystem", "schema"] {
            let mut changed = manifest.clone();
            changed[key] = Value::Null;
            assert!(validate_admission(&plan, &good, &changed, executable, &hash).is_err());
        }
        assert!(validate_admission(&plan, &good, &manifest, executable, &"4".repeat(64)).is_err());
        assert!(validate_admission(&plan, &good, &manifest, Path::new("/wrong"), &hash).is_err());
    }

    #[test]
    fn limits_fail_before_any_source_or_output_access() {
        let mut p = plan();
        p.maximum_runtime_seconds = 0;
        assert!(
            validate_bounds(&p)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        let mut p = plan();
        p.maximum_files = 100_001;
        assert!(
            validate_bounds(&p)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        let mut p = plan();
        p.minimum_free_bytes -= 1;
        assert!(
            validate_bounds(&p)
                .unwrap_err()
                .to_string()
                .contains("bounds")
        );
        let mut p = plan();
        p.maximum_runtime_seconds = 0;
        assert!(
            guard(&p, Instant::now())
                .unwrap_err()
                .to_string()
                .contains("runtime")
        );
    }
}
