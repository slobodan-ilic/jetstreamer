//! Plan-bound retirement of reproducible state from one failed Horizon diagnostic.
//!
//! The tool accepts only the two known disposable subtrees of a retained run root,
//! proves the bound producer is terminal, revalidates sealed outcome evidence, and
//! performs a complete command/maps/cwd/root/exe/fd reference scan before deletion.

use {
    anyhow::{Context, Result, anyhow, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest as _, Sha256},
    std::{
        collections::{BTreeMap, BTreeSet},
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            ffi::OsStrExt as _,
            fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
        },
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

const PLAN_SCHEMA: &str = "jetstreamer-horizon-failed-diagnostic-retirement-plan-v1";
const RECEIPT_SCHEMA: &str = "jetstreamer-horizon-failed-diagnostic-retirement-receipt-v1";
const OUTCOME_SCHEMA: &str = "jetstreamer-horizon-epoch224-singleton-diagnostic-outcome-v1";
const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    private_root: PathBuf,
    run_root: PathBuf,
    targets: Vec<PathBuf>,
    producer: UnitExpectation,
    guard: UnitExpectation,
    inactive_units: Vec<String>,
    outcome: Evidence,
    evidence: Vec<Evidence>,
    intent_receipt: PathBuf,
    completion_receipt: PathBuf,
    authority: Authority,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Evidence {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnitExpectation {
    unit: String,
    invocation_id: String,
    active_state: String,
    sub_state: String,
    result: String,
    exec_main_status: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    local_failed_diagnostic_retirement_authorized: bool,
    preserve_run_root: bool,
    archive_publication_authorized: bool,
    remote_mutations: bool,
    r2_mutations: bool,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct UnitState {
    unit: String,
    invocation_id: String,
    load_state: String,
    active_state: String,
    sub_state: String,
    result: String,
    main_pid: u64,
    restarts: u64,
    exec_main_code: i64,
    exec_main_status: i64,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
struct TreeIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: String,
    physical_bytes: u64,
    apparent_bytes: u64,
    regular_files: u64,
    directories: u64,
}

fn usage() -> ! {
    eprintln!(
        "usage: jetstreamer-horizon-retire-failed-diagnostic --plan PATH --plan-sha256 HEX --self-sha256 HEX [--check-only]"
    );
    std::process::exit(2);
}

fn parse_args() -> (PathBuf, String, String, bool) {
    let mut args = env::args_os().skip(1);
    let mut plan = None;
    let mut plan_sha256 = None;
    let mut self_sha256 = None;
    let mut check_only = false;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--plan") => plan = args.next().map(PathBuf::from),
            Some("--plan-sha256") => {
                plan_sha256 = args.next().and_then(|value| value.into_string().ok())
            }
            Some("--self-sha256") => {
                self_sha256 = args.next().and_then(|value| value.into_string().ok())
            }
            Some("--check-only") if !check_only => check_only = true,
            _ => usage(),
        }
    }
    (
        plan.unwrap_or_else(|| usage()),
        plan_sha256.unwrap_or_else(|| usage()),
        self_sha256.unwrap_or_else(|| usage()),
        check_only,
    )
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_reader(mut reader: impl Read) -> Result<String> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn file_sha256(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    sha256_reader(file)
}

fn read_secure(path: &Path, maximum: u64, required_uid: u32) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "path is not absolute: {}",
        path.display()
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.nlink() == 1,
        "unsafe file identity"
    );
    ensure!(before.uid() == required_uid, "unexpected file owner");
    ensure!(
        before.permissions().mode() & 0o022 == 0,
        "writable evidence file"
    );
    ensure!(before.len() <= maximum, "evidence file exceeds size limit");
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "evidence file exceeds size limit"
    );
    let after = file.metadata()?;
    ensure!(
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "evidence changed while reading"
    );
    Ok(bytes)
}

fn verify_self(expected: &str) -> Result<()> {
    ensure!(valid_sha256(expected), "invalid self SHA-256");
    ensure!(
        sha256_reader(File::open("/proc/self/exe")?)? == expected,
        "running executable SHA-256 mismatch"
    );
    Ok(())
}

fn valid_unit_name(value: &str) -> bool {
    (value.ends_with(".service") || value.ends_with(".timer"))
        && !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'@' | b'-'))
}

fn path_or_descendant(candidate: &Path, root: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

fn validate_plan(plan: &Plan) -> Result<()> {
    ensure!(plan.schema == PLAN_SCHEMA, "plan schema mismatch");
    ensure!(
        plan.private_root == Path::new("/home/ubuntu/.jetstreamer-private"),
        "unexpected private root"
    );
    ensure!(plan.run_root.is_absolute(), "run root is not absolute");
    ensure!(
        plan.run_root.starts_with(&plan.private_root),
        "run root escapes private root"
    );
    let expected = BTreeSet::from([
        plan.run_root.join("output/compact-indexes"),
        plan.run_root.join("replay-state"),
    ]);
    let actual = plan.targets.iter().cloned().collect::<BTreeSet<_>>();
    ensure!(
        plan.targets.len() == 2 && actual == expected,
        "target set is not the exact disposable diagnostic set"
    );
    ensure!(
        plan.intent_receipt != plan.completion_receipt,
        "receipt paths collide"
    );
    for receipt in [&plan.intent_receipt, &plan.completion_receipt] {
        ensure!(
            receipt.is_absolute() && receipt.starts_with(&plan.private_root),
            "receipt path escapes private root"
        );
        ensure!(
            !plan
                .targets
                .iter()
                .any(|target| path_or_descendant(receipt, target)),
            "receipt is beneath a deletion target"
        );
    }
    ensure!(
        valid_unit_name(&plan.producer.unit) && valid_unit_name(&plan.guard.unit),
        "invalid bound unit name"
    );
    ensure!(
        plan.producer.invocation_id.len() == 32 && plan.guard.invocation_id.len() == 32,
        "invalid invocation ID"
    );
    ensure!(
        plan.inactive_units.iter().all(|unit| valid_unit_name(unit)),
        "invalid inactive unit name"
    );
    ensure!(
        valid_sha256(&plan.outcome.sha256),
        "invalid outcome SHA-256"
    );
    for item in std::iter::once(&plan.outcome).chain(plan.evidence.iter()) {
        ensure!(
            item.path.is_absolute()
                && item.path.starts_with(&plan.private_root)
                && valid_sha256(&item.sha256),
            "invalid evidence binding"
        );
        ensure!(
            !plan
                .targets
                .iter()
                .any(|target| path_or_descendant(&item.path, target)),
            "evidence is beneath a deletion target"
        );
    }
    ensure!(
        plan.authority.local_failed_diagnostic_retirement_authorized,
        "retirement is not authorized"
    );
    ensure!(
        plan.authority.preserve_run_root,
        "run root preservation is not required"
    );
    ensure!(
        !plan.authority.archive_publication_authorized,
        "plan authorizes archive publication"
    );
    ensure!(
        !plan.authority.remote_mutations && !plan.authority.r2_mutations,
        "plan authorizes remote mutation"
    );
    Ok(())
}

fn parse_systemctl(stdout: &[u8]) -> Result<BTreeMap<String, String>> {
    let mut fields = BTreeMap::new();
    for line in std::str::from_utf8(stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow!("malformed systemctl output"))?;
        ensure!(
            fields.insert(key.to_string(), value.to_string()).is_none(),
            "duplicate systemctl field"
        );
    }
    Ok(fields)
}

fn sample_unit(expectation: &UnitExpectation) -> Result<UnitState> {
    let output = Command::new("systemctl")
        .args(["show", &expectation.unit, "--property=LoadState,ActiveState,SubState,Result,MainPID,InvocationID,NRestarts,ExecMainCode,ExecMainStatus"])
        .output()?;
    ensure!(
        output.status.success(),
        "systemctl failed for {}",
        expectation.unit
    );
    let fields = parse_systemctl(&output.stdout)?;
    let number = |key: &str| -> Result<u64> {
        Ok(fields
            .get(key)
            .ok_or_else(|| anyhow!("missing {key}"))?
            .parse()?)
    };
    let signed = |key: &str| -> Result<i64> {
        Ok(fields
            .get(key)
            .ok_or_else(|| anyhow!("missing {key}"))?
            .parse()?)
    };
    let state = UnitState {
        unit: expectation.unit.clone(),
        invocation_id: fields.get("InvocationID").cloned().unwrap_or_default(),
        load_state: fields.get("LoadState").cloned().unwrap_or_default(),
        active_state: fields.get("ActiveState").cloned().unwrap_or_default(),
        sub_state: fields.get("SubState").cloned().unwrap_or_default(),
        result: fields.get("Result").cloned().unwrap_or_default(),
        main_pid: number("MainPID")?,
        restarts: number("NRestarts")?,
        exec_main_code: signed("ExecMainCode")?,
        exec_main_status: signed("ExecMainStatus")?,
    };
    ensure!(state.load_state == "loaded", "bound unit is not loaded");
    ensure!(
        state.invocation_id == expectation.invocation_id,
        "bound invocation changed"
    );
    ensure!(
        state.active_state == expectation.active_state && state.sub_state == expectation.sub_state,
        "bound unit is not in the expected terminal state"
    );
    ensure!(
        state.result == expectation.result
            && state.exec_main_status == expectation.exec_main_status,
        "bound unit result changed"
    );
    ensure!(
        state.main_pid == 0 && state.restarts == 0,
        "bound unit has a process or restart"
    );
    Ok(state)
}

fn require_inactive_unit(unit: &str) -> Result<Value> {
    let output = Command::new("systemctl")
        .args([
            "show",
            unit,
            "--property=LoadState,ActiveState,SubState,Result,MainPID",
        ])
        .output()?;
    ensure!(
        output.status.success(),
        "cannot inspect inactive unit {unit}"
    );
    let fields = parse_systemctl(&output.stdout)?;
    ensure!(
        fields.get("ActiveState").map(String::as_str) == Some("inactive"),
        "unit {unit} is active"
    );
    ensure!(
        fields
            .get("MainPID")
            .is_none_or(|value| value.is_empty() || value == "0"),
        "unit {unit} has a process"
    );
    Ok(
        json!({"unit": unit, "load_state": fields.get("LoadState"), "active_state": fields.get("ActiveState"), "sub_state": fields.get("SubState"), "result": fields.get("Result")}),
    )
}

fn require_no_jobs(units: &BTreeSet<String>) -> Result<()> {
    let output = Command::new("systemctl")
        .args(["list-jobs", "--no-legend", "--plain"])
        .output()?;
    ensure!(output.status.success(), "cannot inspect systemd jobs");
    let text = std::str::from_utf8(&output.stdout)?;
    for line in text.lines() {
        ensure!(
            !units
                .iter()
                .any(|unit| line.split_whitespace().any(|field| field == unit)),
            "a bound unit has a pending systemd job"
        );
    }
    Ok(())
}

fn tree_identity(path: &Path) -> Result<TreeIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "target is not an exact directory"
    );
    ensure!(
        fs::canonicalize(path)? == path,
        "target path is not canonical"
    );
    let device = metadata.dev();
    let mut physical_bytes = metadata.blocks().saturating_mul(512);
    let mut apparent_bytes = metadata.len();
    let mut regular_files = 0_u64;
    let mut directories = 1_u64;
    let mut pending = vec![path.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let child = entry.path();
            let child_metadata = fs::symlink_metadata(&child)?;
            ensure!(
                !child_metadata.file_type().is_symlink(),
                "symlink found beneath target: {}",
                child.display()
            );
            ensure!(
                child_metadata.dev() == device,
                "target crosses a filesystem boundary"
            );
            physical_bytes =
                physical_bytes.saturating_add(child_metadata.blocks().saturating_mul(512));
            apparent_bytes = apparent_bytes.saturating_add(child_metadata.len());
            if child_metadata.is_dir() {
                directories += 1;
                pending.push(child);
            } else {
                ensure!(
                    child_metadata.is_file(),
                    "unsupported member beneath target: {}",
                    child.display()
                );
                regular_files += 1;
            }
        }
    }
    Ok(TreeIdentity {
        path: path.to_path_buf(),
        device,
        inode: metadata.ino(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        mode: format!("{:04o}", metadata.permissions().mode() & 0o7777),
        physical_bytes,
        apparent_bytes,
        regular_files,
        directories,
    })
}

fn encoded_reference(content: &[u8], needle: &[u8]) -> bool {
    let boundaries = b"/\0\n\r\t '\";|&()<>[]{}";
    let mut start = 0;
    while start <= content.len() {
        let Some(relative) = content[start..]
            .windows(needle.len())
            .position(|window| window == needle)
        else {
            return false;
        };
        let end = start + relative + needle.len();
        if end == content.len() || boundaries.contains(&content[end]) {
            return true;
        }
        start += relative + 1;
    }
    false
}

fn read_proc_file(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn read_proc_link(path: &Path) -> Result<Option<PathBuf>> {
    match fs::read_link(path) {
        Ok(target) => {
            let rendered = target.to_string_lossy();
            Ok(Some(PathBuf::from(
                rendered.strip_suffix(" (deleted)").unwrap_or(&rendered),
            )))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

fn process_references(targets: &[PathBuf]) -> Result<Vec<String>> {
    let mut references = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
            .map(str::to_string)
        else {
            continue;
        };
        if pid.parse::<u32>().ok() == Some(std::process::id()) {
            continue;
        }
        let process = entry.path();
        for target in targets {
            let needle = target.as_os_str().as_bytes();
            for (name, label) in [("cmdline", "command"), ("maps", "maps")] {
                if read_proc_file(&process.join(name))?
                    .is_some_and(|bytes| encoded_reference(&bytes, needle))
                {
                    references.push(format!("pid {pid} {label} {}", target.display()));
                }
            }
            for name in ["cwd", "root", "exe"] {
                if read_proc_link(&process.join(name))?
                    .is_some_and(|value| path_or_descendant(&value, target))
                {
                    references.push(format!("pid {pid} {name} {}", target.display()));
                }
            }
            match fs::read_dir(process.join("fd")) {
                Ok(descriptors) => {
                    for descriptor in descriptors {
                        let descriptor = descriptor?;
                        if read_proc_link(&descriptor.path())?
                            .is_some_and(|value| path_or_descendant(&value, target))
                        {
                            references.push(format!(
                                "pid {pid} fd {} {}",
                                descriptor.file_name().to_string_lossy(),
                                target.display()
                            ));
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("cannot inspect pid {pid} descriptors"));
                }
            }
        }
    }
    Ok(references)
}

fn fsync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn write_noclobber(path: &Path, value: &Value) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("receipt has no parent"))?;
    let metadata = fs::metadata(parent)?;
    ensure!(
        fs::canonicalize(parent)? == parent
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o077 == 0,
        "unsafe receipt directory"
    );
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    fsync_directory(parent)
}

fn available_bytes(path: &Path) -> Result<u64> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let stats = unsafe { stats.assume_init() };
    Ok(stats.f_bavail.saturating_mul(stats.f_frsize))
}

fn now_millis() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis())
}

fn stable_evidence(plan: &Plan) -> Result<Value> {
    let run_metadata = fs::symlink_metadata(&plan.run_root)?;
    ensure!(
        run_metadata.is_dir()
            && !run_metadata.file_type().is_symlink()
            && fs::canonicalize(&plan.run_root)? == plan.run_root,
        "unsafe run root"
    );
    let outcome_bytes = read_secure(&plan.outcome.path, MAX_JSON_BYTES, 0)?;
    ensure!(
        format!("{:x}", Sha256::digest(&outcome_bytes)) == plan.outcome.sha256,
        "outcome SHA-256 mismatch"
    );
    let outcome: Value = serde_json::from_slice(&outcome_bytes)?;
    ensure!(
        outcome.pointer("/schema").and_then(Value::as_str) == Some(OUTCOME_SCHEMA),
        "outcome schema mismatch"
    );
    ensure!(
        outcome
            .pointer("/authority/scratch_retirement_authorized_after_clean_process_reference_scan")
            .and_then(Value::as_bool)
            == Some(true),
        "outcome does not authorize cleanup"
    );
    ensure!(
        outcome
            .pointer("/authority/r2_mutations")
            .and_then(Value::as_bool)
            == Some(false),
        "outcome permits R2 mutation"
    );
    ensure!(
        outcome
            .pointer("/producer/invocation_id")
            .and_then(Value::as_str)
            == Some(&plan.producer.invocation_id),
        "outcome producer mismatch"
    );
    let mut evidence = Vec::new();
    let mut seen = BTreeSet::new();
    for item in std::iter::once(&plan.outcome).chain(plan.evidence.iter()) {
        ensure!(seen.insert(item.path.clone()), "duplicate evidence path");
        let bytes = read_secure(&item.path, MAX_JSON_BYTES, 0)?;
        let observed = format!("{:x}", Sha256::digest(&bytes));
        ensure!(
            observed == item.sha256,
            "evidence SHA-256 mismatch: {}",
            item.path.display()
        );
        evidence.push(json!({"path": item.path, "sha256": observed}));
    }
    let producer = sample_unit(&plan.producer)?;
    let guard = sample_unit(&plan.guard)?;
    let mut inactive = Vec::new();
    for unit in &plan.inactive_units {
        inactive.push(require_inactive_unit(unit)?);
    }
    let units = std::iter::once(plan.producer.unit.clone())
        .chain(std::iter::once(plan.guard.unit.clone()))
        .chain(plan.inactive_units.iter().cloned())
        .collect::<BTreeSet<_>>();
    require_no_jobs(&units)?;
    let targets = plan
        .targets
        .iter()
        .map(|path| tree_identity(path))
        .collect::<Result<Vec<_>>>()?;
    let references = process_references(&plan.targets)?;
    ensure!(
        references.is_empty(),
        "live process references cleanup targets: {references:?}"
    );
    Ok(json!({
        "run_root": plan.run_root,
        "run_root_device": run_metadata.dev(),
        "run_root_inode": run_metadata.ino(),
        "targets": targets,
        "producer": producer,
        "guard": guard,
        "inactive_units": inactive,
        "evidence": evidence,
        "process_reference_scan": {"coverage": ["command", "maps", "cwd", "root", "exe", "file-descriptors"], "references": []},
        "pending_systemd_jobs": []
    }))
}

fn main() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "must run as root");
    let (plan_path, expected_plan_sha256, expected_self_sha256, check_only) = parse_args();
    verify_self(&expected_self_sha256)?;
    ensure!(valid_sha256(&expected_plan_sha256), "invalid plan SHA-256");
    let plan_bytes = read_secure(&plan_path, MAX_JSON_BYTES, 0)?;
    ensure!(
        format!("{:x}", Sha256::digest(&plan_bytes)) == expected_plan_sha256,
        "plan SHA-256 mismatch"
    );
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    validate_plan(&plan)?;
    ensure!(
        !plan.intent_receipt.exists() && !plan.completion_receipt.exists(),
        "fresh receipt paths are required"
    );
    let evidence = stable_evidence(&plan)?;
    let tool_sha256 = expected_self_sha256.clone();
    let common = json!({
        "schema": RECEIPT_SCHEMA,
        "plan": plan_path,
        "plan_sha256": expected_plan_sha256,
        "tool_sha256": tool_sha256,
        "evidence": evidence,
        "run_root_preserved": true,
        "archive_publication_authorized": false,
        "remote_mutations": false,
        "r2_mutations": false
    });
    if check_only {
        println!(
            "{}",
            serde_json::to_string(&json!({"status": "check-passed", "receipt": common}))?
        );
        return Ok(());
    }
    let before = available_bytes(&plan.run_root)?;
    let intent = json!({"status": "intent-fsynced", "recorded_unix_millis": now_millis()?, "available_bytes_before": before, "receipt": common});
    write_noclobber(&plan.intent_receipt, &intent)?;
    let second = stable_evidence(&plan)?;
    ensure!(second == evidence, "cleanup evidence changed after intent");
    for target in &plan.targets {
        fs::remove_dir_all(target)
            .with_context(|| format!("cannot remove {}", target.display()))?;
        fsync_directory(
            target
                .parent()
                .ok_or_else(|| anyhow!("target lacks parent"))?,
        )?;
    }
    ensure!(plan.run_root.exists(), "run root was not preserved");
    ensure!(
        plan.targets.iter().all(|target| !target.exists()),
        "a cleanup target remains"
    );
    let completion = json!({
        "status": "complete",
        "recorded_unix_millis": now_millis()?,
        "available_bytes_before": before,
        "available_bytes_after": available_bytes(&plan.run_root)?,
        "intent_receipt": plan.intent_receipt,
        "intent_receipt_sha256": file_sha256(&plan.intent_receipt)?,
        "targets_absent": true,
        "receipt": common
    });
    write_noclobber(&plan.completion_receipt, &completion)?;
    println!("{}", serde_json::to_string(&completion)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_boundary_reference_does_not_match_sibling() {
        let needle = b"/tmp/replay-state";
        assert!(encoded_reference(b"/tmp/replay-state/file", needle));
        assert!(encoded_reference(b"/tmp/replay-state\0", needle));
        assert!(!encoded_reference(b"/tmp/replay-state-old/file", needle));
    }

    #[test]
    fn sha256_requires_lowercase_hex() {
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert!(!valid_sha256(&"a".repeat(63)));
    }

    #[test]
    fn unit_names_are_constrained() {
        assert!(valid_unit_name("horizon-example.service"));
        assert!(valid_unit_name("horizon-example.timer"));
        assert!(!valid_unit_name("horizon example.service"));
        assert!(!valid_unit_name("horizon-example.path"));
    }
}
