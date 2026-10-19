//! Invocation-bound disk/VMA stop guard for a non-restarting standalone replay.
//! Not an adaptive-controller guard: it never launches, restarts, or deletes work.
use {
    anyhow::{Context, Result, ensure},
    serde::{Deserialize, Serialize},
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    },
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    invocation_id: String,
    filesystem: PathBuf,
    minimum_free_bytes: u64,
    worker_root: PathBuf,
    maximum_worker_vmas: u64,
    receipt_directory: PathBuf,
    #[serde(default)]
    bounded_canary: Option<BoundedCanary>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundedCanary {
    expected_uid: u32,
    target_stop_intent: PathBuf,
    maximum_drainage_seconds: u64,
}

fn read_canary_evidence(path: &Path, uid: u32, maximum: u64) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical canary evidence"
    );
    let parent = path.parent().context("canary evidence parent")?;
    let directory = fs::symlink_metadata(parent)?;
    ensure!(
        directory.is_dir() && directory.uid() == uid && directory.mode() & 0o077 == 0,
        "unsafe canary evidence directory"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == uid
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "unsafe canary evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "canary evidence replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "canary evidence changed"
    );
    Ok(bytes)
}

fn validate_canary_target(
    intent: &Value,
    capture: &Value,
    invocation: &str,
    root: &Path,
    now: u64,
    maximum_age: u64,
) -> Result<()> {
    ensure!(
        intent["schema"] == "jetstreamer-private-epoch225-canary-target-stop-v1"
            && intent["invocation_id"] == invocation
            && intent["target_slot"] == 97_202_500u64
            && intent["observed_slot"]
                .as_u64()
                .is_some_and(|s| (97_202_500..=97_203_500).contains(&s))
            && intent["child_pid"]
                .as_u64()
                .is_some_and(|p| p > 1 && p <= i32::MAX as u64)
            && intent["scratch_snapshot_captured"] == true
            && intent["external_signal"] == 0,
        "invalid canary target-stop scope"
    );
    let written = intent["written_unix_seconds"]
        .as_u64()
        .context("target-stop time")?;
    ensure!(
        written <= now && now - written <= maximum_age,
        "canary drainage interval expired or future-dated"
    );
    let capture_path = root.join("receipts/target-capture.json");
    ensure!(
        intent["capture_path"].as_str() == capture_path.to_str(),
        "wrong canary capture path"
    );
    let expected = intent["capture_canonical_json_sha256"]
        .as_str()
        .context("capture digest")?;
    ensure!(
        digest(expected) && sha(&serde_json::to_vec(capture)?) == expected,
        "canary capture digest mismatch"
    );
    let scratch = root.join("scratch");
    let accounts = Path::new(
        capture["accounts_state"]["path"]
            .as_str()
            .context("accounts-state path")?,
    );
    ensure!(
        capture["scratch"]["path"].as_str() == scratch.to_str()
            && accounts.starts_with(&scratch)
            && accounts.file_name().is_some_and(|n| n == "accounts-state")
            && !accounts.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            ))
            && capture["scratch"]["physical_bytes"]
                .as_u64()
                .is_some_and(|b| b <= 256u64 << 30)
            && capture["accounts_state"]["regular_files"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && capture["cgroup"].as_object().is_some_and(|m| !m.is_empty()),
        "invalid captured canary resources"
    );
    Ok(())
}

fn canary_target(p: &Plan, c: &BoundedCanary, now: u64) -> Result<Option<Value>> {
    match fs::symlink_metadata(&c.target_stop_intent) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
        Ok(_) => {}
    }
    let intent: Value = serde_json::from_slice(&read_canary_evidence(
        &c.target_stop_intent,
        c.expected_uid,
        64 << 10,
    )?)?;
    let capture: Value = serde_json::from_slice(&read_canary_evidence(
        &p.worker_root.join("receipts/target-capture.json"),
        c.expected_uid,
        64 << 20,
    )?)?;
    validate_canary_target(
        &intent,
        &capture,
        &p.invocation_id,
        &p.worker_root,
        now,
        c.maximum_drainage_seconds,
    )?;
    Ok(Some(intent))
}

fn canary_trip_reason(
    workers: usize,
    valid_target: bool,
    evidence_error: bool,
) -> Option<&'static str> {
    if evidence_error {
        Some("canary-target-evidence-failed")
    } else if workers == 0 && !valid_target {
        Some("zero-workers-before-target")
    } else {
        None
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct Unit {
    load_state: String,
    invocation_id: String,
    active: String,
    sub: String,
    result: String,
    restarts: u64,
    restart_policy: String,
    kill_mode: String,
    delegated: bool,
    cgroup: String,
    pid: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical evidence path"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o022 == 0
            && before.len() <= 1024 * 1024,
        "unsafe guard evidence"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "evidence replaced"
    );
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes.len() as u64 == before.len()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "guard evidence changed"
    );
    Ok(bytes)
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        parent.is_absolute()
            && parent.canonicalize()? == parent
            && metadata.is_dir()
            && metadata.uid() == 0
            && metadata.mode() & 0o077 == 0,
        "receipts require a canonical root-private directory"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| anyhow::anyhow!("receipt exists or cannot publish: {error}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn sample(unit: &str) -> Result<Unit> {
    let output = Command::new("systemctl").args(["show", unit, "--property=Id,LoadState,InvocationID,ActiveState,SubState,Result,NRestarts,Restart,KillMode,Delegate,ControlGroup,MainPID"]).output()?;
    ensure!(output.status.success(), "cannot observe guarded unit");
    let fields: BTreeMap<_, _> = std::str::from_utf8(&output.stdout)?
        .lines()
        .map(|line| line.split_once('=').context("malformed unit state"))
        .collect::<Result<_>>()?;
    let get = |key| {
        fields
            .get(key)
            .copied()
            .with_context(|| format!("missing {key}"))
    };
    ensure!(
        get("Id")? == unit && matches!(get("LoadState")?, "loaded" | "not-found"),
        "unit state unavailable or mismatched"
    );
    Ok(Unit {
        load_state: get("LoadState")?.into(),
        invocation_id: get("InvocationID")?.into(),
        active: get("ActiveState")?.into(),
        sub: get("SubState")?.into(),
        result: get("Result")?.into(),
        restarts: get("NRestarts")?.parse()?,
        restart_policy: get("Restart")?.into(),
        kill_mode: get("KillMode")?.into(),
        delegated: get("Delegate")? != "no",
        cgroup: get("ControlGroup")?.into(),
        pid: get("MainPID")?.parse()?,
    })
}

fn bound(unit: &Unit, expected: &str) -> Result<()> {
    ensure!(
        unit.load_state == "loaded"
            && unit.invocation_id == expected
            && unit.restarts == 0
            && unit.restart_policy == "no"
            && unit.kill_mode == "control-group"
            && !unit.delegated,
        "invocation, restart count, or standalone restart policy changed"
    );
    Ok(())
}

fn active(unit: &Unit) -> bool {
    matches!(
        unit.active.as_str(),
        "active" | "activating" | "deactivating"
    ) && unit.pid != 0
}

fn collected(unit: &Unit) -> bool {
    unit.load_state == "not-found"
        && unit.active == "inactive"
        && unit.sub == "dead"
        && unit.pid == 0
        && unit.cgroup.is_empty()
        && unit.invocation_id.is_empty()
        && unit.restarts == 0
}

fn cgroup_pids(root: &Path) -> Result<Vec<u32>> {
    let metadata = fs::symlink_metadata(root)?;
    ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "unsafe cgroup"
    );
    let mut pids = Vec::new();
    for line in fs::read_to_string(root.join("cgroup.procs"))?.lines() {
        pids.push(line.parse()?);
    }
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            pids.extend(cgroup_pids(&entry.path())?);
        }
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn workers(unit: &Unit, worker_root: &Path) -> Result<Vec<(u32, u64)>> {
    ensure!(
        unit.cgroup.starts_with('/')
            && unit.cgroup != "/"
            && !unit
                .cgroup
                .split('/')
                .any(|part| part == ".." || part == "."),
        "unsafe cgroup path"
    );
    workers_from_pids(
        &cgroup_pids(&Path::new("/sys/fs/cgroup").join(&unit.cgroup[1..]))?,
        worker_root,
    )
}

fn workers_from_pids(pids: &[u32], worker_root: &Path) -> Result<Vec<(u32, u64)>> {
    let mut workers = Vec::new();
    for &pid in pids {
        let executable = match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(path) => path,
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        let name = executable.file_name().unwrap_or_default().to_string_lossy();
        if executable.starts_with(worker_root)
            || name.starts_with("historical-worker")
            || name.starts_with("jetstreamer-historical-worker")
        {
            ensure!(
                name == "historical-worker",
                "unexpected worker executable name"
            );
            ensure!(
                executable.starts_with(worker_root),
                "worker escaped the bound generation"
            );
            let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
            workers.push((pid, maps.lines().count() as u64));
        }
    }
    Ok(workers)
}

fn trip_reason(
    free: u64,
    floor: u64,
    workers: &[(u32, u64)],
    max_vmas: u64,
) -> Option<&'static str> {
    if free < floor {
        Some("filesystem-floor")
    } else if workers.len() > 1 {
        Some("multiple-workers")
    } else if workers.iter().any(|(_, vmas)| *vmas > max_vmas) {
        Some("worker-vma-ceiling")
    } else {
        None
    }
}

fn intent_matches(intent: &Value, plan_sha: &str, invocation: &str) -> bool {
    intent["schema"] == "jetstreamer-horizon-standalone-stop-intent-v1"
        && intent["plan_sha256"] == plan_sha
        && intent["producer_invocation_id"] == invocation
}

fn run() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } == 0, "guard requires root");
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: guard PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(digest(&args[3]) && digest(&args[5]), "invalid digest");
    let executable = fs::read("/proc/self/exe")?;
    ensure!(
        sha(&executable) == args[5],
        "guard executable digest mismatch"
    );
    let bytes = read_private(Path::new(&args[1]))?;
    ensure!(sha(&bytes) == args[3], "guard plan digest mismatch");
    let plan: Plan = serde_json::from_slice(&bytes)?;
    if let Some(c) = &plan.bounded_canary {
        ensure!(
            plan.unit
                .starts_with("horizon-qualify-225-bounded-resource-")
                && c.expected_uid == 1000
                && c.target_stop_intent == plan.worker_root.join("receipts/target-stop.json")
                && (60..=180).contains(&c.maximum_drainage_seconds),
            "invalid bounded-canary guard scope"
        );
    }
    ensure!(
        plan.schema == "jetstreamer-horizon-standalone-guard-plan-v1"
            && plan.unit.starts_with("horizon-qualify-")
            && plan.unit.ends_with(".service")
            && plan
                .unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b))
            && identity(&plan.invocation_id)
            && plan.minimum_free_bytes > 0
            && plan.maximum_worker_vmas > 0,
        "invalid standalone guard plan"
    );
    for path in [&plan.filesystem, &plan.worker_root, &plan.receipt_directory] {
        ensure!(
            path.is_absolute() && path.canonicalize()? == *path && path.is_dir(),
            "guard path must be canonical directory"
        );
    }
    ensure!(
        plan.worker_root != Path::new("/") && plan.worker_root != plan.filesystem,
        "worker root must name an isolated generation"
    );
    let invocation = env::var("INVOCATION_ID").context("guard must run in systemd")?;
    ensure!(identity(&invocation), "invalid guard invocation");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let intent_path = plan.receipt_directory.join("stop-intent.json");
    let completion_path = plan.receipt_directory.join("stop-completion.json");
    let intent = match fs::symlink_metadata(&intent_path) {
        Ok(_) => {
            let intent: Value = serde_json::from_slice(&read_private(&intent_path)?)?;
            ensure!(
                intent_matches(&intent, &args[3], &plan.invocation_id),
                "foreign stop intent"
            );
            Some(intent)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let before = sample(&plan.unit)?;
    // systemd may collect a successfully stopped transient unit before the next
    // timer fire. Absence is accepted only for a previously authenticated stop
    // intent, with the exact old cgroup now absent. Never apply this exception
    // to a new live invocation under the same unit name.
    if collected(&before) {
        let intent = intent
            .as_ref()
            .context("guarded producer disappeared without a stop intent")?;
        let cgroup = intent
            .pointer("/sample/producer/cgroup")
            .and_then(Value::as_str)
            .context("stop intent omits original cgroup")?;
        ensure!(
            cgroup.starts_with('/')
                && cgroup != "/"
                && !cgroup.split('/').any(|p| p == "." || p == ".."),
            "unsafe prior cgroup"
        );
        match fs::symlink_metadata(Path::new("/sys/fs/cgroup").join(&cgroup[1..])) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("original cgroup still present or unreadable"),
        }
        match fs::symlink_metadata(&completion_path) {
            Ok(_) => {
                let completion: Value = serde_json::from_slice(&read_private(&completion_path)?)?;
                ensure!(
                    completion["schema"] == "jetstreamer-horizon-standalone-stop-completion-v1"
                        && completion["plan_sha256"] == args[3]
                        && completion["producer_invocation_id"] == plan.invocation_id,
                    "foreign stop completion"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist(
                &completion_path,
                &json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1","plan_sha256":args[3],
                    "producer_invocation_id":plan.invocation_id,"terminal":before,"intent":intent_path,
                    "prior_cgroup_verified_absent":cgroup,"scratch_deleted":false,"remote_mutations":false,"r2_mutations":false}),
            )?,
            Err(error) => return Err(error.into()),
        }
        let receipt = json!({"schema":"jetstreamer-horizon-standalone-stop-revalidated-v1","plan_sha256":args[3],
            "producer_invocation_id":plan.invocation_id,"guard_invocation_id":invocation,"terminal":before,
            "prior_cgroup_verified_absent":cgroup,"completion":completion_path,"remote_mutations":false,"r2_mutations":false});
        persist(
            &plan
                .receipt_directory
                .join(format!("sample-{invocation}.json")),
            &receipt,
        )?;
        println!("{receipt}");
        return Ok(());
    }
    bound(&before, &plan.invocation_id)?;
    let filesystem = std::ffi::CString::new(plan.filesystem.as_os_str().as_encoded_bytes())?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { libc::statvfs(filesystem.as_ptr(), &mut stat) } == 0,
        "statvfs failed"
    );
    let available = stat
        .f_bavail
        .checked_mul(stat.f_frsize)
        .context("free bytes overflow")?;
    let observed_workers = if active(&before) {
        workers(&before, &plan.worker_root)
    } else {
        Ok(Vec::new())
    };
    // Unreadable maps, escaped workers, and cgroup failures are reasons to stop,
    // never evidence that the unit has no worker.
    let error = observed_workers.as_ref().err().map(ToString::to_string);
    let worker_list = observed_workers.unwrap_or_default();
    let target_observation = if active(&before) {
        plan.bounded_canary
            .as_ref()
            .map(|c| canary_target(&plan, c, now))
    } else {
        None
    };
    let target_error = target_observation
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .map(ToString::to_string);
    let valid_target = target_observation
        .as_ref()
        .is_some_and(|r| matches!(r, Ok(Some(_))));
    let reason = if intent.is_some() {
        Some("resume-stop-intent")
    } else if error.is_some() {
        Some("worker-observation-failed")
    } else if active(&before) {
        trip_reason(
            available,
            plan.minimum_free_bytes,
            &worker_list,
            plan.maximum_worker_vmas,
        )
        .or_else(|| {
            plan.bounded_canary.as_ref().and_then(|_| {
                canary_trip_reason(worker_list.len(), valid_target, target_error.is_some())
            })
        })
    } else {
        None
    };
    let after = sample(&plan.unit)?;
    bound(&after, &plan.invocation_id)?;
    ensure!(
        before == after,
        "producer identity or state changed during guard sample"
    );
    let evidence = json!({"schema":"jetstreamer-horizon-standalone-guard-sample-v1", "recorded_unix_seconds":now,
        "plan":args[1],"plan_sha256":args[3],"guard_sha256":args[5],"guard_invocation_id":invocation,
        "producer":after,"producer_invocation_id":plan.invocation_id,"available_bytes":available,
        "minimum_free_bytes":plan.minimum_free_bytes,"maximum_worker_vmas":plan.maximum_worker_vmas,
        "workers":worker_list,"worker_observation_error":error,"trip_reason":reason,
        "bounded_canary":plan.bounded_canary,"canary_target_stop_valid":valid_target,"canary_target_error":target_error,
        "remote_mutations":false,"r2_mutations":false,"scratch_deleted":false});
    persist(
        &plan
            .receipt_directory
            .join(format!("sample-{invocation}.json")),
        &evidence,
    )?;
    if let Some(reason) = reason {
        if intent.is_none() {
            persist(
                &intent_path,
                &json!({"schema":"jetstreamer-horizon-standalone-stop-intent-v1",
                "plan_sha256":args[3],"producer_invocation_id":plan.invocation_id,"reason":reason,"sample":evidence}),
            )?;
        }
        let current = sample(&plan.unit)?;
        bound(&current, &plan.invocation_id)?;
        if active(&current) {
            let stopped = Command::new("systemctl")
                .args(["stop", &plan.unit])
                .output()?;
            ensure!(
                stopped.status.success(),
                "guard could not stop producer: {}",
                String::from_utf8_lossy(&stopped.stderr)
            );
        }
        let terminal = sample(&plan.unit)?;
        if collected(&terminal) {
            ensure!(
                current.cgroup.starts_with('/')
                    && current.cgroup != "/"
                    && !current.cgroup.split('/').any(|p| p == "." || p == ".."),
                "unsafe stopped cgroup"
            );
            match fs::symlink_metadata(Path::new("/sys/fs/cgroup").join(&current.cgroup[1..])) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                _ => anyhow::bail!("stopped producer cgroup remains present or unreadable"),
            }
        } else {
            bound(&terminal, &plan.invocation_id)?;
        }
        ensure!(
            !active(&terminal) && terminal.pid == 0,
            "producer remains live after stop"
        );
        match fs::symlink_metadata(&completion_path) {
            Ok(_) => {
                let completion: Value = serde_json::from_slice(&read_private(&completion_path)?)?;
                ensure!(
                    completion["plan_sha256"] == args[3]
                        && completion["producer_invocation_id"] == plan.invocation_id,
                    "foreign stop completion"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => persist(
                &completion_path,
                &json!({"schema":"jetstreamer-horizon-standalone-stop-completion-v1","plan_sha256":args[3],
                    "producer_invocation_id":plan.invocation_id,"terminal":terminal,"intent":intent_path,
                    "scratch_deleted":false,"remote_mutations":false,"r2_mutations":false}),
            )?,
            Err(error) => return Err(error.into()),
        }
    }
    println!("{evidence}");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn unit() -> Unit {
        Unit {
            load_state: "loaded".into(),
            invocation_id: "a".repeat(32),
            active: "active".into(),
            sub: "running".into(),
            result: "success".into(),
            restarts: 0,
            restart_policy: "no".into(),
            kill_mode: "control-group".into(),
            delegated: false,
            cgroup: "/system.slice/test.service".into(),
            pid: 1,
        }
    }
    #[test]
    fn changed_invocation_or_restart_policy_is_never_stopped() {
        let mut state = unit();
        assert!(bound(&state, &"a".repeat(32)).is_ok());
        assert!(bound(&state, &"b".repeat(32)).is_err());
        state.restarts = 1;
        assert!(bound(&state, &"a".repeat(32)).is_err());
        state.restarts = 0;
        state.restart_policy = "on-failure".into();
        assert!(bound(&state, &"a".repeat(32)).is_err());
        state.restart_policy = "no".into();
        state.kill_mode = "process".into();
        assert!(bound(&state, &"a".repeat(32)).is_err());
        state.kill_mode = "control-group".into();
        state.delegated = true;
        assert!(bound(&state, &"a".repeat(32)).is_err());
    }
    #[test]
    fn collected_exception_cannot_match_a_replacement_or_live_process() {
        let mut state = unit();
        state.load_state = "not-found".into();
        state.active = "inactive".into();
        state.sub = "dead".into();
        state.pid = 0;
        state.cgroup.clear();
        state.invocation_id.clear();
        assert!(collected(&state));
        state.load_state = "loaded".into();
        assert!(!collected(&state));
        state.load_state = "not-found".into();
        state.pid = 1;
        assert!(!collected(&state));
    }
    #[test]
    fn reserve_vma_and_multiple_worker_trips() {
        assert_eq!(trip_reason(99, 100, &[], 500), Some("filesystem-floor"));
        assert_eq!(
            trip_reason(100, 100, &[(1, 501)], 500),
            Some("worker-vma-ceiling")
        );
        assert_eq!(
            trip_reason(100, 100, &[(1, 1), (2, 1)], 500),
            Some("multiple-workers")
        );
        assert_eq!(trip_reason(100, 100, &[], 500), None);
        assert_eq!(trip_reason(100, 100, &[(1, 500)], 500), None);
    }
    #[test]
    fn canary_zero_worker_exception_requires_fresh_valid_target_evidence() {
        assert_eq!(canary_trip_reason(1, false, false), None);
        assert_eq!(
            canary_trip_reason(0, false, false),
            Some("zero-workers-before-target")
        );
        assert_eq!(canary_trip_reason(0, true, false), None);
        assert_eq!(
            canary_trip_reason(0, true, true),
            Some("canary-target-evidence-failed")
        );
        assert_eq!(
            canary_trip_reason(1, false, true),
            Some("canary-target-evidence-failed")
        );
        assert_eq!(
            trip_reason(100, 100, &[(1, 1), (2, 1)], 500),
            Some("multiple-workers")
        );
    }
    fn target_fixture(root: &Path) -> (Value, Value) {
        let capture = json!({"scratch":{"path":root.join("scratch"),"physical_bytes":4096},"accounts_state":{"path":root.join("scratch/runtime/accounts-state"),"regular_files":1},"cgroup":{"memory.current":"100\n"}});
        let intent = json!({"schema":"jetstreamer-private-epoch225-canary-target-stop-v1","invocation_id":"a".repeat(32),"target_slot":97202500,"observed_slot":97202505,"child_pid":123,"written_unix_seconds":1000,"scratch_snapshot_captured":true,"external_signal":0,"capture_path":root.join("receipts/target-capture.json"),"capture_canonical_json_sha256":sha(&serde_json::to_vec(&capture).unwrap())});
        (intent, capture)
    }
    #[test]
    fn canary_target_binds_scope_time_capture_and_absence_of_external_signal() {
        let root = Path::new("/private/canary");
        let (intent, capture) = target_fixture(root);
        validate_canary_target(&intent, &capture, &"a".repeat(32), root, 1100, 180).unwrap();
        assert!(
            validate_canary_target(&intent, &capture, &"b".repeat(32), root, 1100, 180).is_err()
        );
        assert!(
            validate_canary_target(&intent, &capture, &"a".repeat(32), root, 999, 180).is_err()
        );
        assert!(
            validate_canary_target(&intent, &capture, &"a".repeat(32), root, 1181, 180).is_err()
        );
        for (key, value) in [
            ("target_slot", json!(97202501)),
            ("observed_slot", json!(97202500 - 1)),
            ("external_signal", json!(2)),
            ("scratch_snapshot_captured", json!(false)),
            ("child_pid", json!(1)),
            ("capture_path", json!("/other")),
            ("capture_canonical_json_sha256", json!("0".repeat(64))),
        ] {
            let mut bad = intent.clone();
            bad[key] = value;
            assert!(
                validate_canary_target(&bad, &capture, &"a".repeat(32), root, 1100, 180).is_err(),
                "{key}"
            );
        }
        let mut substituted = capture.clone();
        substituted["accounts_state"]["regular_files"] = json!(2);
        assert!(
            validate_canary_target(&intent, &substituted, &"a".repeat(32), root, 1100, 180)
                .is_err()
        );
        let mut escaped = capture.clone();
        escaped["accounts_state"]["path"] = json!("/other/accounts-state");
        let mut forged = intent.clone();
        forged["capture_canonical_json_sha256"] =
            json!(sha(&serde_json::to_vec(&escaped).unwrap()));
        assert!(
            validate_canary_target(&forged, &escaped, &"a".repeat(32), root, 1100, 180).is_err()
        );
    }
    #[test]
    fn canary_evidence_is_private_readonly_and_never_a_symlink() {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = t.path().join("intent.json");
        fs::write(&path, b"{}").unwrap();
        let uid = unsafe { libc::geteuid() };
        assert!(read_canary_evidence(&path, uid, 100).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(read_canary_evidence(&path, uid, 100).unwrap(), b"{}");
        assert!(read_canary_evidence(&path, uid + 1, 100).is_err());
        assert!(read_canary_evidence(&path, uid, 1).is_err());
        let alias = t.path().join("alias");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert!(read_canary_evidence(&alias, uid, 100).is_err());
    }
    #[test]
    fn canary_capture_then_intent_handoff_is_atomic_and_substitution_fails() {
        let t = tempfile::tempdir().unwrap();
        let receipts = t.path().join("receipts");
        fs::create_dir(&receipts).unwrap();
        fs::set_permissions(&receipts, fs::Permissions::from_mode(0o700)).unwrap();
        let (intent, capture) = target_fixture(t.path());
        let p:Plan=serde_json::from_value(json!({"schema":"jetstreamer-horizon-standalone-guard-plan-v1","unit":"horizon-qualify-225-bounded-resource-test.service","invocation_id":"a".repeat(32),"filesystem":"/","minimum_free_bytes":1,"worker_root":t.path(),"maximum_worker_vmas":3500000,"receipt_directory":t.path(),"bounded_canary":{"expected_uid":unsafe{libc::geteuid()},"target_stop_intent":receipts.join("target-stop.json"),"maximum_drainage_seconds":180}})).unwrap();
        let c = p.bounded_canary.as_ref().unwrap();
        let capture_path = receipts.join("target-capture.json");
        fs::write(&capture_path, serde_json::to_vec_pretty(&capture).unwrap()).unwrap();
        fs::set_permissions(&capture_path, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(canary_target(&p, c, 1100).unwrap().is_none());
        fs::write(
            &c.target_stop_intent,
            serde_json::to_vec_pretty(&intent).unwrap(),
        )
        .unwrap();
        fs::set_permissions(&c.target_stop_intent, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(canary_target(&p, c, 1100).unwrap().is_some());
        let replacement = receipts.join("replacement.json");
        fs::write(&replacement, b"{}").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o400)).unwrap();
        fs::rename(replacement, &capture_path).unwrap();
        assert!(canary_target(&p, c, 1100).is_err());
    }
    #[test]
    fn nested_cgroup_census_recognizes_the_actual_copied_worker_and_maps() {
        struct Owned(std::process::Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let t = tempfile::tempdir().unwrap();
        let root = t.path().join("generation");
        fs::create_dir(&root).unwrap();
        let exe = root.join("historical-worker");
        fs::copy("/bin/sleep", &exe).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o555)).unwrap();
        let child = Owned(Command::new(&exe).arg("20").spawn().unwrap());
        let cg = t.path().join("cgroup");
        fs::create_dir(&cg).unwrap();
        fs::write(cg.join("cgroup.procs"), b"").unwrap();
        let nested = cg.join("child");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("cgroup.procs"), format!("{}\n", child.0.id())).unwrap();
        let pids = cgroup_pids(&cg).unwrap();
        assert_eq!(pids, vec![child.0.id()]);
        let found = workers_from_pids(&pids, &root).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, child.0.id());
        assert!(found[0].1 > 0);
        assert!(workers_from_pids(&pids, &t.path().join("foreign")).is_err());
    }
    #[test]
    fn interrupted_stop_is_bound_to_exact_plan_and_producer() {
        let intent = json!({"schema":"jetstreamer-horizon-standalone-stop-intent-v1","plan_sha256":"a","producer_invocation_id":"b"});
        assert!(intent_matches(&intent, "a", "b"));
        assert!(!intent_matches(&intent, "different", "b"));
        assert!(!intent_matches(&intent, "a", "different"));
    }
    #[test]
    fn no_clobber_receipts_preserve_existing_evidence() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("receipt.json");
        persist(&path, &json!({"first":true})).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(persist(&path, &json!({"second":true})).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}
