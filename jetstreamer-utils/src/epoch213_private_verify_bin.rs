//! Exact, non-authorizing verification of the retained epoch-213 V4 assembly.
//! Creates one private canonical-name copy, never a checksum or public file.
//! Requires a sealed plan and terminal producer; independent full and plugin
//! scans must bind the same unchanged bytes. No replay or R2 operations exist.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Instant,
};

const UNIT: &str = "horizon-qualify-213-checkpoint-continuation-ae43646-v1.service";
const INVOCATION: &str = "1dfd29e7ced140b3ba407359cbdc0ee1";
const SOURCE: &str = "/home/ubuntu/.jetstreamer-private/checkpoint-continuation-213-ae43646-v1/output/epoch-213-checkpoint-restart-v4.jet";
const PROVENANCE: &str = "a85a2df80f7d6ca8720e597f372661df65fd0d891e41d420a3db6f866ab4121b";
const EXPECTATION: &str = "f7bb330186a8fbcc438b0fa49e903af5be5a1c30092f7cd434a86f6b2916bea5";
const FULL: &str = "067ca3124a47cdbff4545918c65ff070df80f96ee0caf648873036ed1f11fcb9";
const PLUGIN: &str = "167954ad8087a4214dbdd65c8f72690bd66d7aa6637179ddf85db85b9a03a547";
const PREFIX: &str = "e9b0fa7bbad1fdbf86d9d564baa0c377003ec20e40709dae249fac8ba0cb91d9";
const SUFFIX: &str = "3360ba3da029865522511a821c30851447a7a6eca5e9fe28cd536181edf07d03";
const SNAPSHOT: &str = "bae33ebaeaa7bfb3c4c9230ef9f7aabb2e68628ac2fc0a8d435b7e2e976bbe08";
const NODE: &str = "83398ece0317a6ab3b321f9e1eb8d0c7f76f21f1cb5997cd07899ba19f2992f3";
const PRODUCER_PLAN: &str = "83eeb441502e39510ad7610ae6dac9165d9f5a6f32afaeab1f19205e9ab6f144";
// Older measured growth + four-epoch century floor, plus the entire 225 budget.
// Fresh admission may require more, never less than this reviewed baseline.
const MIN_PROTECTED: u64 = 2_498_483_426_006 + 256 * 1024 * 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    producer_outcome: Evidence,
    provenance_expectation: Evidence,
    full_verifier: Evidence,
    plugin: Evidence,
    // Pre-created root-private directory, outside HORIZON_DIR and all packages.
    private_directory: PathBuf,
    // Protects older growth, century floor, and all remaining diagnostic budgets.
    protected_free_bytes: u64,
    maximum_archive_bytes: u64,
    threads: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Identity {
    dev: u64,
    ino: u64,
    len: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}

fn identity(m: &fs::Metadata) -> Identity {
    Identity {
        dev: m.dev(),
        ino: m.ino(),
        len: m.len(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        mtime: m.mtime(),
        mtime_ns: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_ns: m.ctime_nsec(),
    }
}

fn hex(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical digest"
    );
    Ok(())
}

fn open_file(path: &Path, root_only: bool) -> Result<File> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical file path"
    );
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.mode() & 0o022 == 0,
        "unsafe file identity"
    );
    if root_only {
        ensure!(m.uid() == 0, "evidence must be root-owned");
    }
    ensure!(
        identity(&fs::symlink_metadata(path)?) == identity(&m),
        "file changed while opening"
    );
    Ok(file)
}

fn unchanged(path: &Path, file: &File, before: &Identity) -> Result<()> {
    ensure!(
        &identity(&file.metadata()?) == before && &identity(&fs::symlink_metadata(path)?) == before,
        "file identity changed"
    );
    Ok(())
}

fn measure(path: &Path, root_only: bool) -> Result<(String, Identity)> {
    let mut file = open_file(path, root_only)?;
    let before = identity(&file.metadata()?);
    let digest = hash_open(&mut file)?;
    unchanged(path, &file, &before)?;
    Ok((digest, before))
}

fn hash_open(file: &mut File) -> Result<String> {
    let mut sha = Sha256::new();
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        sha.update(&buffer[..n]);
    }
    Ok(format!("{:x}", sha.finalize()))
}

fn checked(evidence: &Evidence) -> Result<()> {
    hex(&evidence.sha256)?;
    ensure!(
        measure(&evidence.path, true)?.0 == evidence.sha256,
        "evidence digest mismatch: {}",
        evidence.path.display()
    );
    Ok(())
}

fn read_json(evidence: &Evidence) -> Result<Value> {
    hex(&evidence.sha256)?;
    let mut file = open_file(&evidence.path, true)?;
    let before = identity(&file.metadata()?);
    ensure!(before.len <= 4 * 1024 * 1024, "JSON too large");
    let mut bytes = Vec::new();
    (&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    unchanged(&evidence.path, &file, &before)?;
    ensure!(
        format!("{:x}", Sha256::digest(&bytes)) == evidence.sha256,
        "JSON digest mismatch"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(
        plan.schema == "jetstreamer-private-epoch213-verification-plan-v1",
        "wrong plan schema"
    );
    ensure!(
        plan.provenance_expectation.sha256 == EXPECTATION
            && plan.full_verifier.sha256 == FULL
            && plan.plugin.sha256 == PLUGIN,
        "unreviewed verifier or provenance expectation"
    );
    ensure!(
        plan.threads == 8
            && plan.protected_free_bytes >= MIN_PROTECTED
            && plan.maximum_archive_bytes > 0
            && plan.maximum_archive_bytes <= 128 * 1024 * 1024 * 1024,
        "invalid resource bounds"
    );
    ensure!(
        plan.private_directory.parent() == Some(Path::new("/var/lib/jetstreamer"))
            && plan
                .private_directory
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("horizon-213-private-scan-")),
        "not the exact private scan namespace"
    );
    Ok(())
}

fn validate_outcome(value: &Value) -> Result<()> {
    ensure!(
        value["schema"] == "jetstreamer-private-epoch213-checkpoint-continuation-v1"
            && value["producer_unit"] == UNIT
            && value["producer_invocation_id"] == INVOCATION
            && value["private_output"] == SOURCE
            && value["node_sha256"] == NODE
            && value["plan"]["sha256"] == PRODUCER_PLAN
            && value["prefix_archive_sha256"] == PREFIX
            && value["suffix_archive_sha256"] == SUFFIX
            && value["restart_snapshot_sha256"] == SNAPSHOT
            && value["assembly"]["source_archives"] == 2
            && value["assembly"]["slots_merged"] == 432_000
            && value["assembly"]["provenance_version"] == 4
            && value["fresh_prefix_full_validation_passed"] == true
            && value["fresh_native_checkpoint_matches"] == true
            && value["canonical_root_slot"] == 92_447_542,
        "producer outcome does not bind the exact complete assembly"
    );
    for field in [
        "canonical_sidecar_authorized",
        "publication_authorized",
        "retirement_authorized",
        "r2_mutations",
    ] {
        ensure!(
            value[field] == false,
            "producer outcome must remain non-authorizing"
        );
    }
    Ok(())
}

fn validate_terminal(text: &str) -> Result<()> {
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').context("invalid service state")?;
        ensure!(
            fields.insert(key, value).is_none(),
            "duplicate service field"
        );
    }
    for (key, expected) in [
        ("InvocationID", INVOCATION),
        ("MainPID", "0"),
        ("NRestarts", "0"),
        ("Restart", "no"),
        ("Result", "success"),
        ("ExecMainStatus", "0"),
        ("ExecMainCode", "1"),
    ] {
        ensure!(
            fields.get(key) == Some(&expected),
            "producer not clean terminal: {key}"
        );
    }
    ensure!(
        matches!(
            fields.get("ActiveState"),
            Some(&"inactive") | Some(&"active")
        ) && matches!(fields.get("SubState"), Some(&"dead") | Some(&"exited")),
        "producer remains live"
    );
    Ok(())
}

fn terminal() -> Result<String> {
    let output = Command::new("/usr/bin/systemctl").args(["show", UNIT, "--property=InvocationID,MainPID,NRestarts,Restart,Result,ExecMainStatus,ExecMainCode,ActiveState,SubState"]).output()?;
    ensure!(output.status.success(), "service observation failed");
    let text = String::from_utf8(output.stdout)?;
    validate_terminal(&text)?;
    Ok(text)
}

fn require_absent(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "path must be absent: {}",
        path.display()
    );
    Ok(())
}

fn private_dir(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && fs::canonicalize(path)? == path,
        "noncanonical directory"
    );
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o777 == 0o700,
        "directory must be root-private 0700"
    );
    Ok(())
}

fn write_new(path: &Path, value: &Value) -> Result<()> {
    private_dir(path.parent().context("no receipt parent")?)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

fn free_bytes(path: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), stat.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stat = unsafe { stat.assume_init() };
    stat.f_bavail
        .checked_mul(stat.f_frsize)
        .context("free-space overflow")
}

fn full_args(archive: &Path) -> Vec<String> {
    [
        archive.to_string_lossy().into_owned(),
        "--full".into(),
        "--anchor".into(),
        "92015999".into(),
        "9xdazt5sEpSUzwYi9nTRMmXJDuP4kLdcY9ZXAM5oQVi7".into(),
        "--expected-terminal".into(),
        "92447999".into(),
        "2SMgef3T3X5aeHZy1USrSR5qEJqwQbsz2yVr3tRs25Ki".into(),
        "--threads".into(),
        "8".into(),
        "--expected-provenance-sha256".into(),
        PROVENANCE.into(),
    ]
    .into()
}

fn plugin_args(directory: &Path) -> Vec<String> {
    vec![
        "213:213".into(),
        directory.to_string_lossy().into_owned(),
        "--threads".into(),
        "8".into(),
        "--verify-only".into(),
    ]
}

fn scan(binary: &Evidence, args: &[String], log_path: &Path) -> Result<Value> {
    checked(binary)?;
    let log = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(log_path)?;
    let started = Instant::now();
    let status = Command::new(&binary.path)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log.try_clone()?)
        .status()?;
    log.sync_all()?;
    File::open(log_path.parent().unwrap())?.sync_all()?;
    checked(binary)?;
    ensure!(
        status.success(),
        "private scan failed; retained log {}: {status}",
        log_path.display()
    );
    let (sha256, identity) = measure(log_path, true)?;
    Ok(
        json!({"binary":binary,"arguments":args,"exit_code":0,"elapsed_millis":u64::try_from(started.elapsed().as_millis())?,"log":{"path":log_path,"sha256":sha256,"identity":identity}}),
    )
}

fn run(plan_binding: Evidence, self_sha256: &str) -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    hex(self_sha256)?;
    let mut executable = File::open("/proc/self/exe")?;
    let executable_identity = identity(&executable.metadata()?);
    ensure!(
        executable_identity.uid == 0
            && executable_identity.links == 1
            && executable_identity.mode & 0o022 == 0,
        "unsafe running executable"
    );
    ensure!(
        hash_open(&mut executable)? == self_sha256
            && identity(&executable.metadata()?) == executable_identity,
        "self digest mismatch"
    );
    let plan: Plan = serde_json::from_value(read_json(&plan_binding)?)?;
    validate_plan(&plan)?;
    let dir = &plan.private_directory;
    private_dir(dir)?;
    ensure!(
        fs::read_dir(dir)?.next().is_none(),
        "private directory must be empty; preserve prior attempts"
    );
    let before_terminal = terminal()?;
    let outcome = read_json(&plan.producer_outcome)?;
    validate_outcome(&outcome)?;
    let expected = read_json(&plan.provenance_expectation)?;
    ensure!(
        expected["schema"] == "jetstreamer-private-epoch213-provenance-expectation-v1"
            && expected["expected_provenance_sha256"] == PROVENANCE
            && expected["source_manifest_scope_validated"] == true
            && expected["assembled_target_opened"] == false,
        "invalid independent provenance expectation"
    );
    checked(&plan.full_verifier)?;
    checked(&plan.plugin)?;
    let source_path = Path::new(SOURCE);
    let mut source = open_file(source_path, false)?;
    let source_identity = identity(&source.metadata()?);
    ensure!(
        source_identity.len > 0 && source_identity.len <= plan.maximum_archive_bytes,
        "source length outside bound"
    );
    ensure!(
        free_bytes(dir)?
            .checked_sub(source_identity.len)
            .is_some_and(|remaining| remaining >= plan.protected_free_bytes),
        "copy would violate protected free space"
    );
    let archive = dir.join("epoch-213.jet");
    require_absent(&source_path.with_extension("jet.sha256"))?;
    require_absent(&archive.with_extension("jet.sha256"))?;
    write_new(
        &dir.join("intent.json"),
        &json!({"schema":"jetstreamer-private-epoch213-verification-intent-v1","plan":plan_binding,"runner_sha256":self_sha256,"source_identity":source_identity,"producer_terminal":before_terminal,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let copy_started = Instant::now();
    let mut staged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&archive)?;
    ensure!(
        std::io::copy(&mut source, &mut staged)? == source_identity.len,
        "source copy length changed"
    );
    staged.sync_all()?;
    staged.set_permissions(fs::Permissions::from_mode(0o400))?;
    staged.sync_all()?;
    File::open(dir)?.sync_all()?;
    unchanged(source_path, &source, &source_identity)?;
    ensure!(
        free_bytes(dir)? >= plan.protected_free_bytes,
        "protected free space changed"
    );
    let (digest, stage_identity) = measure(&archive, true)?;
    // Independently hash the retained source, not only the copied output.
    ensure!(
        measure(source_path, false)?.0 == digest,
        "source and copy digests differ"
    );
    let copy_millis = u64::try_from(copy_started.elapsed().as_millis())?;
    let full = scan(
        &plan.full_verifier,
        &full_args(&archive),
        &dir.join("full.log"),
    )?;
    ensure!(
        measure(&archive, true)? == (digest.clone(), stage_identity.clone()),
        "archive changed during full scan"
    );
    write_new(
        &dir.join("full.json"),
        &json!({"schema":"jetstreamer-private-epoch213-full-scan-v1","archive_sha256":digest,"archive_identity":stage_identity,"full":full,"publication_authorized":false,"r2_mutations":false}),
    )?;
    let args = plugin_args(dir);
    let plugin = scan(&plan.plugin, &args, &dir.join("plugin.log"))?;
    ensure!(
        measure(&archive, true)? == (digest.clone(), stage_identity.clone()),
        "archive changed during plugin scan"
    );
    unchanged(source_path, &source, &source_identity)?;
    require_absent(&archive.with_extension("jet.sha256"))?;
    require_absent(&source_path.with_extension("jet.sha256"))?;
    terminal()?;
    checked(&plan.producer_outcome)?;
    checked(&plan.provenance_expectation)?;
    write_new(
        &dir.join("verification.json"),
        &json!({"schema":"jetstreamer-private-epoch213-verification-v1","epoch":213,"plan":plan_binding,"runner_sha256":self_sha256,"producer_outcome":plan.producer_outcome,"provenance_expectation":plan.provenance_expectation,"expected_provenance_sha256":PROVENANCE,"source_path":source_path,"source_identity":source_identity,"archive_path":archive,"archive_sha256":digest,"archive_identity":stage_identity,"copy_and_hash_millis":copy_millis,"full":full,"plugin":plugin,"independent_final_archive_verification_passed":true,"current_plugin_verification_passed":true,"runtime_admission_authorized":false,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false}),
    )?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 5 && args[1] == "--plan-sha256" && args[3] == "--self-sha256",
        "usage: jetstreamer-epoch213-private-verify PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    run(
        Evidence {
            path: args[0].clone().into(),
            sha256: args[2].clone(),
        },
        &args[4],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good_outcome() -> Value {
        json!({"schema":"jetstreamer-private-epoch213-checkpoint-continuation-v1","producer_unit":UNIT,"producer_invocation_id":INVOCATION,"node_sha256":NODE,"plan":{"sha256":PRODUCER_PLAN},"private_output":SOURCE,"prefix_archive_sha256":PREFIX,"suffix_archive_sha256":SUFFIX,"restart_snapshot_sha256":SNAPSHOT,"assembly":{"source_archives":2,"slots_merged":432000,"provenance_version":4},"fresh_prefix_full_validation_passed":true,"fresh_native_checkpoint_matches":true,"canonical_root_slot":92447542,"canonical_sidecar_authorized":false,"publication_authorized":false,"retirement_authorized":false,"r2_mutations":false})
    }

    #[test]
    fn outcome_is_exact_and_never_authorizing() {
        validate_outcome(&good_outcome()).unwrap();
        for (pointer, value) in [
            ("/producer_invocation_id", json!("wrong")),
            ("/private_output", json!("/tmp/epoch-213.jet")),
            ("/assembly/slots_merged", json!(431999)),
            ("/assembly/provenance_version", json!(2)),
            ("/canonical_root_slot", json!(92447999)),
            ("/fresh_native_checkpoint_matches", json!(false)),
            ("/publication_authorized", json!(true)),
            ("/suffix_archive_sha256", json!(PREFIX)),
        ] {
            let mut changed = good_outcome();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(validate_outcome(&changed).is_err(), "{pointer}");
        }
    }

    #[test]
    fn terminal_identity_and_exit_are_mandatory() {
        let good = format!(
            "InvocationID={INVOCATION}\nMainPID=0\nNRestarts=0\nRestart=no\nResult=success\nExecMainStatus=0\nExecMainCode=1\nActiveState=inactive\nSubState=dead\n"
        );
        validate_terminal(&good).unwrap();
        for (old, new) in [
            (INVOCATION, "different"),
            ("MainPID=0", "MainPID=42"),
            ("NRestarts=0", "NRestarts=1"),
            ("ExecMainStatus=0", "ExecMainStatus=1"),
            ("SubState=dead", "SubState=running"),
            ("ExecMainCode=1", "ExecMainCode=2"),
        ] {
            assert!(validate_terminal(&good.replace(old, new)).is_err());
        }
        assert!(validate_terminal(&(good + "Result=success\n")).is_err());
    }

    #[test]
    fn commands_cannot_downgrade_strict_validation() {
        let args = full_args(Path::new("/private/epoch-213.jet"));
        assert_eq!(args.len(), 12);
        assert_eq!(
            &args[1..5],
            [
                "--full",
                "--anchor",
                "92015999",
                "9xdazt5sEpSUzwYi9nTRMmXJDuP4kLdcY9ZXAM5oQVi7"
            ]
        );
        assert_eq!(args[5], "--expected-terminal");
        assert_eq!(args[10], "--expected-provenance-sha256");
        assert_eq!(args[11], PROVENANCE);
        assert!(
            !args
                .iter()
                .any(|v| v == "--internal-full" || v == "--bench")
        );
        assert_eq!(
            plugin_args(Path::new("/private")),
            ["213:213", "/private", "--threads", "8", "--verify-only"]
        );
    }

    fn good_plan() -> Value {
        json!({"schema":"jetstreamer-private-epoch213-verification-plan-v1",
            "producer_outcome":{"path":"/sealed/outcome.json","sha256":"a".repeat(64)},
            "provenance_expectation":{"path":"/sealed/expectation.json","sha256":EXPECTATION},
            "full_verifier":{"path":"/sealed/verify_archive","sha256":FULL},
            "plugin":{"path":"/sealed/horizon-pipeline","sha256":PLUGIN},
            "private_directory":"/var/lib/jetstreamer/horizon-213-private-scan-test-v1",
            "protected_free_bytes":MIN_PROTECTED,"maximum_archive_bytes":128u64*1024*1024*1024,"threads":8})
    }

    #[test]
    fn plan_pins_tools_private_namespace_and_resource_bounds() {
        validate_plan(&serde_json::from_value(good_plan()).unwrap()).unwrap();
        for (pointer, value) in [
            ("/schema", json!("other")),
            ("/full_verifier/sha256", json!(PLUGIN)),
            ("/plugin/sha256", json!(FULL)),
            ("/provenance_expectation/sha256", json!(FULL)),
            ("/protected_free_bytes", json!(MIN_PROTECTED - 1)),
            ("/maximum_archive_bytes", json!(129u64 * 1024 * 1024 * 1024)),
            ("/threads", json!(16)),
            (
                "/private_directory",
                json!("/var/lib/jetstreamer/nested/horizon-213-private-scan-v1"),
            ),
            ("/private_directory", json!("/home/ubuntu/horizon")),
        ] {
            let mut changed = good_plan();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                validate_plan(&serde_json::from_value(changed).unwrap()).is_err(),
                "{pointer}"
            );
        }
        let mut unknown = good_plan();
        unknown["publication_authorized"] = json!(true);
        assert!(serde_json::from_value::<Plan>(unknown).is_err());
    }

    #[test]
    fn digest_and_absence_gates_reject_ambiguous_inputs() {
        assert!(hex(&"a".repeat(64)).is_ok());
        for value in ["A".repeat(64), "a".repeat(63), "g".repeat(64)] {
            assert!(hex(&value).is_err());
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("epoch-213.jet.sha256");
        require_absent(&path).unwrap();
        std::os::unix::fs::symlink("/does-not-exist", &path).unwrap();
        assert!(require_absent(&path).is_err());
    }

    #[test]
    fn root_scan_requires_success_and_preserves_failed_log() {
        // Repeated under sudo as part of release qualification.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        for (binary, succeeds) in [("/usr/bin/true", true), ("/usr/bin/false", false)] {
            // The host's system coreutils may be hardlinked. Make a distinct
            // root-owned inode, just like a sealed deployment member.
            let path = dir
                .path()
                .join(if succeeds { "scan-true" } else { "scan-false" });
            fs::copy(binary, &path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o500)).unwrap();
            let evidence = Evidence {
                sha256: measure(&path, true).unwrap().0,
                path,
            };
            let log = dir.path().join(if succeeds {
                "success.log"
            } else {
                "failure.log"
            });
            assert_eq!(scan(&evidence, &[], &log).is_ok(), succeeds);
            assert!(log.exists());
            assert!(
                scan(&evidence, &[], &log).is_err(),
                "existing log must never be overwritten"
            );
        }
    }

    #[test]
    fn changed_inode_symlink_and_hardlink_fail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        fs::write(&path, b"original").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let (sha, _) = measure(&path, false).unwrap();
        assert_eq!(sha, format!("{:x}", Sha256::digest(b"original")));
        let file = open_file(&path, false).unwrap();
        let before = identity(&file.metadata().unwrap());
        fs::write(&path, b"modified").unwrap();
        assert!(unchanged(&path, &file, &before).is_err());
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(open_file(&link, false).is_err());
        fs::remove_file(link).unwrap();
        fs::hard_link(&path, dir.path().join("hard")).unwrap();
        assert!(open_file(&path, false).is_err());
    }
}
