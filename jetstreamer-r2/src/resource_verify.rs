//! Independent full/coverage/current-plugin verification of a private audit restore.
use super::*;
use serde_json::json;
use std::process::{Command as ProcessCommand, Stdio};

const SCHEMA: &str = "jetstreamer-horizon-private-resource-verification-v1";

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
    epoch: u64,
    resource_audit: Bound,
    full_verifier: Bound,
    current_plugin: Bound,
    threads: u64,
    output_directory: PathBuf,
    publication_authorized: bool,
    production_completion_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

fn bound_bytes(bound: &Bound) -> Result<Vec<u8>> {
    ensure!(
        bound.path.is_absolute() && fs::canonicalize(&bound.path)? == bound.path,
        "noncanonical evidence path"
    );
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        meta.is_file() && meta.nlink() == 1 && meta.uid() == 0 && meta.mode() & 0o022 == 0,
        "unsafe audit evidence owner or mode"
    );
    let bytes = read_stable_bounded(&bound.path, 128 * 1024 * 1024, "private audit evidence")?;
    ensure!(
        is_lower_hex(&bound.sha256, 64) && hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "private audit evidence hash mismatch"
    );
    Ok(bytes)
}

fn verify_executable(bound: &Bound) -> Result<()> {
    bound_bytes(bound)?;
    let meta = fs::symlink_metadata(&bound.path)?;
    ensure!(
        meta.mode() & 0o222 == 0 && meta.mode() & 0o111 != 0,
        "verifier must be immutable and executable"
    );
    Ok(())
}

fn validate_audit(value: &Value, epoch: u64) -> Result<()> {
    ensure!(
        value["schema"] == "jetstreamer-horizon-private-resource-audit-receipt-v1"
            && value["purpose"] == "century-floor-resource-audit-only"
            && value["epoch"] == epoch
            && value["remote_sha256_readback"] == true
            && value["local_sha256_and_etag_verified"] == true
            && value["authenticated_ready_pair_revalidated"] == true
            && value["production_completion_authorized"] == false
            && value["publication_authorized"] == false
            && value["local_retirement_authorized"] == false
            && value["remote_mutations"] == false
            && value["r2_mutations"] == false,
        "invalid or authorizing private audit receipt"
    );
    Ok(())
}

fn run_child(tool: &Bound, args: &[String], output: &Path) -> Result<Value> {
    verify_executable(tool)?;
    let log = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(output)?;
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let status = ProcessCommand::new(&tool.path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .status()?;
    log.sync_all()?;
    File::open(output.parent().context("log parent missing")?)?.sync_all()?;
    ensure!(
        status.success(),
        "private audit verification failed: {} ({status})",
        output.display()
    );
    verify_executable(tool)?;
    let identity = regular_identity(output)?;
    ensure!(
        identity.length <= 64 * 1024 * 1024,
        "audit verifier log too large"
    );
    let bytes = read_stable_bounded(output, 64 * 1024 * 1024, "audit verifier log")?;
    validate_result(&bytes, args)?;
    Ok(
        json!({"path": tool.path, "sha256":tool.sha256, "arguments": args,
        "status":"passed", "exit_code":0, "log":output,
        "log_sha256":hex_lower(&Sha256::digest(&bytes)), "started_unix_seconds":started,
        "completed_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()}),
    )
}

fn validate_result(bytes: &[u8], args: &[String]) -> Result<()> {
    let text = std::str::from_utf8(bytes)?;
    if args.iter().any(|arg| arg == "--verify-only") {
        let epoch = args
            .first()
            .context("plugin epoch missing")?
            .split(':')
            .next()
            .unwrap();
        ensure!(
            text.contains("verification-only mode; ClickHouse is disabled")
                && text.contains(&format!("horizon pipeline: epoch {epoch} complete")),
            "plugin log lacks exact verification completion"
        );
    } else {
        let results: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("RESULT:"))
            .collect();
        ensure!(
            results.len() == 1
                && (results[0].starts_with("RESULT: OK:")
                    || results[0].starts_with("RESULT: OK (internal only):"))
                && text.contains("=== verify summary ("),
            "full/ordered audit result missing or ambiguous"
        );
        if args.iter().any(|arg| arg == "--full") {
            ensure!(
                text.contains("=== full PoH verification ==="),
                "full PoH summary missing"
            );
        }
    }
    Ok(())
}

pub(super) fn run() -> Result<()> {
    let args: Vec<_> = env::args().skip(2).collect();
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: private-resource-audit-verify PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "private audit verifier requires root"
    );
    let mut executable = File::open("/proc/self/exe")?;
    let mut digest = Sha256::new();
    std::io::copy(&mut executable, &mut digest)?;
    ensure!(
        is_lower_hex(&args[4], 64) && hex_lower(&digest.finalize()) == args[4],
        "verifier self hash mismatch"
    );
    let bound_plan = Bound {
        path: args[0].clone().into(),
        sha256: args[2].clone(),
    };
    let bytes = bound_bytes(&bound_plan)?;
    ensure!(
        fs::symlink_metadata(&bound_plan.path)?.mode() & 0o222 == 0,
        "plan must be immutable"
    );
    let plan: Plan = serde_json::from_slice(&bytes)?;
    ensure!(
        plan.schema == "jetstreamer-horizon-private-resource-verification-plan-v1"
            && (200..=300).contains(&plan.epoch)
            && (1..=32).contains(&plan.threads)
            && !plan.publication_authorized
            && !plan.production_completion_authorized
            && !plan.remote_mutations
            && !plan.r2_mutations,
        "invalid verification plan bounds or authority"
    );
    resource_audit::private_directory(&plan.output_directory)?;
    let receipt = plan.output_directory.join("verification.json");
    ensure!(
        !receipt.try_exists()?,
        "private verification receipt already exists"
    );
    let audit_bytes = bound_bytes(&plan.resource_audit)?;
    let audit: Value = serde_json::from_slice(&audit_bytes)?;
    validate_audit(&audit, plan.epoch)?;
    let archive = PathBuf::from(
        audit["archive_path"]
            .as_str()
            .context("audit archive path missing")?,
    );
    let parent = archive.parent().context("audit archive parent missing")?;
    resource_audit::private_directory(parent)?;
    ensure!(
        archive
            .file_name()
            .context("archive name missing")?
            .to_str()
            == Some(format!("epoch-{}.jet", plan.epoch).as_str()),
        "noncanonical audit archive name"
    );
    ensure!(
        fs::canonicalize(&archive)? == archive,
        "noncanonical archive path"
    );
    let identity = regular_identity(&archive)?;
    ensure!(
        identity.device
            == audit["archive_device"]
                .as_u64()
                .context("audit device missing")?
            && identity.inode
                == audit["archive_inode"]
                    .as_u64()
                    .context("audit inode missing")?
            && identity.length
                == audit["archive_length"]
                    .as_u64()
                    .context("audit length missing")?,
        "restored audit archive identity changed"
    );
    let part_size = audit["multipart_part_size"]
        .as_u64()
        .context("audit part size missing")?;
    ensure!(part_size >= 5 * 1024 * 1024, "invalid audit part size");
    let expected_sha = audit["archive_sha256"]
        .as_str()
        .context("audit SHA missing")?;
    let expected_etag = audit["archive_etag"]
        .as_str()
        .context("audit ETag missing")?;
    let check_hash = || -> Result<()> {
        ensure!(
            regular_identity(&archive)? == identity,
            "archive identity changed"
        );
        let proof = hash_and_etag(&archive, identity, part_size)?;
        ensure!(
            proof.sha256_hex == expected_sha && proof.multipart_etag == expected_etag,
            "private verifier archive hash mismatch"
        );
        validate_restored_sidecar(
            &parent.join(format!("epoch-{}.jet.sha256", plan.epoch)),
            format!("{expected_sha}  epoch-{}.jet\n", plan.epoch).as_bytes(),
        )?;
        Ok(())
    };
    check_hash()?;
    let path = archive
        .to_str()
        .context("archive path not UTF-8")?
        .to_owned();
    let threads = plan.threads.to_string();
    eprintln!("epoch {}: private full PoH verification", plan.epoch);
    let full = run_child(
        &plan.full_verifier,
        &[
            path.clone(),
            "--full".into(),
            "--internal-full".into(),
            "--threads".into(),
            threads.clone(),
        ],
        &plan.output_directory.join("full.log"),
    )?;
    check_hash()?;
    eprintln!(
        "epoch {}: private ordered coverage/link verification",
        plan.epoch
    );
    let ordered = run_child(
        &plan.full_verifier,
        &[path, "--threads".into(), threads.clone()],
        &plan.output_directory.join("ordered.log"),
    )?;
    check_hash()?;
    eprintln!("epoch {}: private current-plugin verification", plan.epoch);
    let plugin = run_child(
        &plan.current_plugin,
        &[
            format!("{}:{}", plan.epoch, plan.epoch),
            parent.to_str().context("archive parent not UTF-8")?.into(),
            "--threads".into(),
            threads,
            "--verify-only".into(),
        ],
        &plan.output_directory.join("plugin.log"),
    )?;
    check_hash()?;
    ensure!(
        bound_bytes(&plan.resource_audit)? == audit_bytes,
        "resource audit receipt changed"
    );
    let verification = json!({"schema":SCHEMA,"status":"passed", "epoch":plan.epoch,
        "archive_path":archive,"archive_sha256":expected_sha,"archive_length":identity.length,
        "archive_device":identity.device,"archive_inode":identity.inode,
        "resource_audit":plan.resource_audit.path,"resource_audit_sha256":plan.resource_audit.sha256,
        "full_verifier":full,"ordered_verifier":ordered,"current_plugin":plugin,
        "archive_sha256_before_after_verified":true,"plan":bound_plan.path,"plan_sha256":bound_plan.sha256,
        "tool_sha256":args[4],"publication_authorized":false,"production_completion_authorized":false,
        "local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
    fleet::persist(&receipt, &verification)?;
    let verified_bytes =
        read_stable_bounded(&receipt, 1024 * 1024, "resource verification receipt")?;
    let floor = identity
        .length
        .checked_mul(2)
        .context("century floor overflow")?;
    fleet::persist(
        &plan.output_directory.join("century-floor.json"),
        &json!({
        "schema":"jetstreamer-horizon-century-jet-floor-v1",
        "century":{"first_epoch":200,"last_epoch":300},
        "selection_policy":"one canonical complete jet per epoch with normal full/plugin evidence and an authenticated R2 ready-pair receipt; exclude partial, diagnostic, verification-tail, archive-only, and growing files",
        "samples":[{"epoch":plan.epoch,"jet_size_bytes":identity.length,"archive_sha256":expected_sha,
            "r2_receipt":plan.resource_audit.path,"r2_receipt_sha256":plan.resource_audit.sha256,
            "private_resource_verification":receipt,
            "private_resource_verification_sha256":hex_lower(&Sha256::digest(&verified_bytes))}],
        "arithmetic":{"sample_count":1,"sum_jet_size_bytes":identity.length,"floor_bytes":floor},
        "production_completion_authorized":false,"publication_authorized":false,
        "remote_mutations":false,"r2_mutations":false}),
    )?;
    eprintln!(
        "private full/plugin resource verification passed: {}",
        receipt.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn audit_evidence_requires_all_integrity_gates_and_denies_completion() {
        let good = json!({"schema":"jetstreamer-horizon-private-resource-audit-receipt-v1",
            "purpose":"century-floor-resource-audit-only","epoch":201,
            "remote_sha256_readback":true,"local_sha256_and_etag_verified":true,
            "authenticated_ready_pair_revalidated":true,"production_completion_authorized":false,
            "publication_authorized":false,"local_retirement_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_audit(&good, 201).unwrap();
        for field in [
            "remote_sha256_readback",
            "authenticated_ready_pair_revalidated",
            "local_sha256_and_etag_verified",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(false);
            assert!(validate_audit(&bad, 201).is_err());
        }
        for field in [
            "production_completion_authorized",
            "publication_authorized",
            "local_retirement_authorized",
            "r2_mutations",
            "remote_mutations",
        ] {
            let mut bad = good.clone();
            bad[field] = json!(true);
            assert!(validate_audit(&bad, 201).is_err());
        }
        assert!(validate_audit(&good, 202).is_err());
    }

    #[test]
    fn verifier_logs_must_prove_exact_nonpartial_success() {
        let args = vec!["epoch-201.jet".into(), "--full".into()];
        let good = b"=== verify summary (1s) ===\n=== full PoH verification ===\nRESULT: OK (internal only): all stored links verify\n";
        validate_result(good, &args).unwrap();
        assert!(validate_result(b"", &args).is_err());
        assert!(
            validate_result(
                b"=== verify summary (1s) ===\nRESULT: OK (partial read of 1 slots).\n",
                &args
            )
            .is_err()
        );
        let mut ambiguous = good.to_vec();
        ambiguous.extend_from_slice(b"RESULT: FAIL: mismatch\n");
        assert!(validate_result(&ambiguous, &args).is_err());
        let plugin = vec!["201:201".into(), "--verify-only".into()];
        validate_result(b"verification-only mode; ClickHouse is disabled\nhorizon pipeline: epoch 201 complete\n", &plugin).unwrap();
        assert!(validate_result(b"verification-only mode; ClickHouse is disabled\nhorizon pipeline: epoch 202 complete\n", &plugin).is_err());
    }
}
