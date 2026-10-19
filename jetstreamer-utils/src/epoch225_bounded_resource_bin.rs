//! Private, target-stopped resource measurement, restricted to epoch225.
//! This wrapper never imports archives or creates canonical checksum sidecars.
use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        env, fs,
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicI32, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const TARGET: u64 = 97_202_500;
const TERMINAL: u64 = 97_631_459;
const MINIMUM_FREE: u64 = 3_185_678_193_366;
const MAX_SCRATCH: u64 = 256 << 30;
const WORKER: &str = "f39140b9a9659e7c6e8207076a2d0c560a6b69df42cc92e19a421cf46c2b761c";
const SNAPSHOT: &str = "094d3b28c39403580fbac083cdad67cc008b255dd375d611217103750d0f412d";
const GENESIS: &str = "133f7eaefcd59466f3b291aadd1b0d3522432072cf5b539445218c6c125ea945";
static EXTERNAL_SIGNAL: AtomicI32 = AtomicI32::new(0);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    unit: String,
    node: BoundFile,
    worker: PathBuf,
    snapshot: PathBuf,
    ledger_directory: PathBuf,
    epoch_hashes: BoundFile,
    run_root: PathBuf,
    target_slot: u64,
    terminal_slot: u64,
    minimum_free_bytes: u64,
    maximum_runtime_seconds: u64,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn bound_file(path: &Path, expected: &str, maximum: u64) -> Result<()> {
    ensure!(
        digest(expected) && path.is_absolute() && path.canonicalize()? == path,
        "invalid bound file"
    );
    let before = fs::symlink_metadata(path)?;
    ensure!(
        before.is_file()
            && before.uid() == 0
            && before.nlink() == 1
            && before.mode() & 0o222 == 0
            && before.len() <= maximum,
        "unsafe immutable input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    ensure!(
        before.dev() == opened.dev() && before.ino() == opened.ino(),
        "input replaced at open"
    );
    let mut sha = Sha256::new();
    let mut buf = [0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        bytes = bytes
            .checked_add(n as u64)
            .context("input length overflow")?;
        ensure!(bytes <= maximum, "input grew beyond bound");
        sha.update(&buf[..n]);
    }
    let after = fs::symlink_metadata(path)?;
    ensure!(
        bytes == before.len()
            && hex(&sha.finalize()) == expected
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.mtime() == after.mtime()
            && before.mtime_nsec() == after.mtime_nsec(),
        "input digest or identity changed"
    );
    Ok(())
}

fn private_directory(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        path.is_absolute()
            && path.canonicalize()? == path
            && m.is_dir()
            && m.uid() == unsafe { libc::geteuid() }
            && m.mode() & 0o077 == 0,
        "unsafe private directory"
    );
    Ok(())
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    let parent = path.parent().context("receipt parent")?;
    private_directory(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o400))?;
    serde_json::to_writer_pretty(temp.as_file_mut(), value)?;
    temp.write_all(b"\n")?;
    temp.as_file().sync_all()?;
    temp.persist_noclobber(path)
        .map_err(|e| anyhow::anyhow!("receipt already exists or cannot publish: {e}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_plan(p: &Plan) -> Result<()> {
    ensure!(
        p.schema == "jetstreamer-private-epoch225-bounded-resource-plan-v1"
            && p.unit.starts_with("horizon-qualify-225-bounded-resource-")
            && p.unit.ends_with(".service")
            && p.unit
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "wrong canary scope"
    );
    ensure!(
        p.run_root.parent() == Some(Path::new("/home/ubuntu/.jetstreamer-private"))
            && p.run_root
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("bounded-resource-225-")),
        "wrong private root"
    );
    ensure!(
        p.target_slot == TARGET
            && p.terminal_slot == TERMINAL
            && p.minimum_free_bytes >= MINIMUM_FREE
            && (600..=3600).contains(&p.maximum_runtime_seconds),
        "work or resource bounds changed"
    );
    ensure!(
        p.snapshot.file_name().and_then(|n| n.to_str())
            == Some("snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst"),
        "wrong snapshot"
    );
    ensure!(
        digest(&p.node.sha256) && digest(&p.epoch_hashes.sha256),
        "invalid input digest"
    );
    Ok(())
}

fn command(p: &Plan) -> Command {
    let mut c = Command::new(&p.node.path);
    c.arg("225")
        .arg(p.run_root.join("ledger"))
        .args(["--verify"])
        .arg(format!("--qualification-end-slot={TERMINAL}"))
        .arg(format!("--snapshot-archive={}", p.snapshot.display()))
        .arg(format!("--epoch-hashes={}", p.epoch_hashes.path.display()))
        .arg(format!(
            "--horizon-output={}",
            p.run_root.join("output/epoch-225-canary.jet").display()
        ))
        .arg(format!(
            "--replay-scratch={}",
            p.run_root.join("scratch").display()
        ))
        .env("JETSTREAMER_ALLOW_CANDIDATE_RUNTIME", "1")
        .env("RUST_LOG", "info")
        .env("SOLANA_RAYON_THREADS", "16")
        .env("JETSTREAMER_HISTORICAL_WORKER_V1_6_20", &p.worker)
        .env_remove("HORIZON_S3_ENDPOINT")
        .env_remove("HORIZON_ACCESS_KEY_ID")
        .env_remove("HORIZON_SECRET_ACCESS_KEY")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    c
}

// Optional counters must never control target detection. Only the parent's
// own progress record (not a program log or another logger) is recognized.
fn progress_slot(line: &str) -> Option<u64> {
    let (prefix, rest) = line.split_once(" jetstreamer_node] progress slot ")?;
    if !prefix.starts_with('[') || !prefix.contains(" INFO ") {
        return None;
    }
    let (slot, terminal) = rest.split_once('/')?;
    let terminal = terminal.split_whitespace().next()?.parse::<u64>().ok()?;
    if terminal != TERMINAL || slot.is_empty() || !slot.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let slot = slot.parse::<u64>().ok()?;
    (97_199_618..=TERMINAL).contains(&slot).then_some(slot)
}

fn progress_counters(line: &str) -> Option<Value> {
    let slot = progress_slot(line)?;
    let counter = |prefix: &str| {
        line.split_whitespace()
            .find_map(|s| s.strip_prefix(prefix))
            .and_then(|n| n.parse::<u64>().ok())
    };
    Some(
        json!({"slot":slot,"transactions":counter("txs=")?,"account_updates":counter("accounts=")?}),
    )
}

fn metrics(cgroup: &Path) -> Result<Value> {
    let mut map = serde_json::Map::new();
    for name in [
        "memory.current",
        "memory.peak",
        "memory.events",
        "memory.stat",
        "cpu.stat",
        "io.stat",
        "memory.pressure",
        "io.pressure",
    ] {
        map.insert(name.into(), json!(fs::read_to_string(cgroup.join(name))?));
    }
    Ok(Value::Object(map))
}

fn scratch(root: &Path) -> Result<Value> {
    let dev = fs::symlink_metadata(root)?.dev();
    let mut pending = vec![(root.to_path_buf(), 0)];
    let (mut physical, mut apparent, mut files, mut dirs) = (0u64, 0u64, 0u64, 0u64);
    let mut account_roots = Vec::new();
    let mut histogram = std::collections::BTreeMap::<u64, u64>::new();
    let started = Instant::now();
    while let Some((path, depth)) = pending.pop() {
        ensure!(
            depth <= 64
                && files + dirs + pending.len() as u64 <= 4_000_000
                && started.elapsed() < Duration::from_secs(120),
            "scratch scan bound"
        );
        let m = fs::symlink_metadata(&path)?;
        ensure!(
            m.dev() == dev && !m.file_type().is_symlink(),
            "scratch escaped filesystem or contains symlink"
        );
        physical = physical
            .checked_add(m.blocks().checked_mul(512).context("block overflow")?)
            .context("size overflow")?;
        apparent = apparent.checked_add(m.len()).context("apparent overflow")?;
        ensure!(physical <= MAX_SCRATCH, "scratch exceeds256GiB");
        if m.is_dir() {
            dirs += 1;
            if path.file_name().is_some_and(|n| n == "accounts-state") {
                account_roots.push(path.clone());
            }
            for entry in fs::read_dir(path)? {
                pending.push((entry?.path(), depth + 1));
            }
        } else {
            ensure!(m.is_file(), "unexpected scratch object");
            files += 1;
            *histogram.entry(m.len()).or_default() += 1;
        }
    }
    Ok(
        json!({"path":root,"physical_bytes":physical,"apparent_bytes":apparent,"regular_files":files,"directories":dirs,"file_size_histogram_bytes":histogram,"accounts_state_roots":account_roots}),
    )
}

fn capture_resources(scratch_root: &Path, cgroup: &Path) -> Result<Value> {
    let tree = scratch(scratch_root)?;
    let roots = tree["accounts_state_roots"]
        .as_array()
        .context("accounts-state census")?;
    ensure!(roots.len() == 1, "expected one live accounts-state");
    let account_root = Path::new(roots[0].as_str().context("accounts-state path")?);
    Ok(json!({"scratch":tree,"accounts_state":scratch(account_root)?,"cgroup":metrics(cgroup)?}))
}

fn free_bytes(path: &Path) -> Result<u64> {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    ensure!(
        unsafe { libc::statvfs(path.as_ptr(), v.as_mut_ptr()) } == 0,
        "statvfs failed"
    );
    let v = unsafe { v.assume_init() };
    v.f_bavail.checked_mul(v.f_frsize).context("free overflow")
}

extern "C" fn signal_handler(signal: libc::c_int) {
    EXTERNAL_SIGNAL.store(signal, Ordering::SeqCst);
}
fn install_signals() -> Result<()> {
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = signal_handler as *const () as usize;
        unsafe { libc::sigemptyset(&mut action.sa_mask) };
        ensure!(
            unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0,
            "cannot install signal handler"
        );
    }
    Ok(())
}

fn group_signal(pid: u32, signal: i32) -> Result<()> {
    ensure!(pid > 1 && pid <= i32::MAX as u32, "unsafe child pid");
    let result = unsafe { libc::kill(-(pid as i32), signal) };
    if result != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e.into());
        }
    }
    Ok(())
}

fn stat_group_state(stat: &str) -> Result<(u32, char)> {
    let (_, suffix) = stat.rsplit_once(')').context("malformed process stat")?;
    let fields = suffix.split_whitespace().collect::<Vec<_>>();
    ensure!(fields.len() >= 3, "short process stat");
    Ok((
        fields[2].parse()?,
        fields[0].chars().next().context("missing state")?,
    ))
}

fn group_stopped(leader: u32) -> Result<bool> {
    let mut saw_leader = false;
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = match fs::read_to_string(entry.path().join("stat")) {
            Ok(s) => s,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENOENT | libc::ESRCH)) => continue,
            Err(e) => return Err(e.into()),
        };
        if stat_group_state(&stat)?.0 != leader {
            continue;
        }
        if pid == leader {
            saw_leader = true;
        }
        for task in fs::read_dir(entry.path().join("task"))? {
            let stat = fs::read_to_string(task?.path().join("stat"))?;
            let (group, state) = stat_group_state(&stat)?;
            ensure!(group == leader, "child group changed during freeze");
            if !matches!(state, 'T' | 't') {
                return Ok(false);
            }
        }
    }
    Ok(saw_leader)
}

fn freeze_group(leader: u32) -> Result<()> {
    group_signal(leader, libc::SIGSTOP)?;
    let started = Instant::now();
    loop {
        if group_stopped(leader)? {
            return Ok(());
        }
        ensure!(
            started.elapsed() < Duration::from_secs(10),
            "child group did not freeze"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

struct ChildGroup(Child, bool);
impl Drop for ChildGroup {
    fn drop(&mut self) {
        // Never strand a frozen child on an error. SIGKILL is confined to this
        // wrapper-created process group, including temporary legacy descendants.
        // An unreaped owned child pins the process-group leader PID. Once
        // reaped, never signal that numeric PGID again: it could be reused.
        if !self.1 {
            let _ = group_signal(self.0.id(), libc::SIGCONT);
            let _ = group_signal(self.0.id(), libc::SIGKILL);
            let _ = self.0.try_wait();
        }
    }
}

fn reader<R: Read + Send + 'static>(input: R, tx: mpsc::SyncSender<Result<String, String>>) {
    thread::spawn(move || {
        let mut reader = BufReader::new(input);
        loop {
            let mut bytes = Vec::new();
            let read = reader.by_ref().take(65537).read_until(b'\n', &mut bytes);
            let message = match read {
                Ok(0) => break,
                Ok(_) if bytes.len() > 65536 => Err("child log line exceeds64KiB".into()),
                Ok(_) => String::from_utf8(bytes).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let failed = message.is_err();
            if tx.send(message).is_err() || failed {
                break;
            }
        }
    });
}

fn controlled_success(target: bool, external: i32, code: Option<i32>) -> bool {
    target && external == 0 && matches!(code, Some(0 | 1))
}

fn validate_checkpoint_names(hashes: &str) -> Result<()> {
    let names = hashes
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        names
            == [
                "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst",
                "snapshot-97631459-EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d.tar.zst",
            ],
        "wrong canonical checkpoint set"
    );
    Ok(())
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } != 0,
        "run as isolated replay user"
    );
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: canary PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    bound_file(&fs::read_link("/proc/self/exe")?, &args[5], 256 << 20)?;
    bound_file(Path::new(&args[1]), &args[3], 1 << 20)?;
    let p: Plan = serde_json::from_slice(&fs::read(&args[1])?)?;
    validate_plan(&p)?;
    let invocation = env::var("INVOCATION_ID")?;
    ensure!(identity(&invocation), "missing canonical invocation");
    let membership = fs::read_to_string("/proc/self/cgroup")?;
    ensure!(
        membership.trim() == format!("0::/system.slice/{}", p.unit),
        "foreign cgroup"
    );
    let cgroup = Path::new("/sys/fs/cgroup/system.slice").join(&p.unit);
    for name in ["", "scratch", "output", "receipts", "ledger"] {
        let dir = p.run_root.join(name);
        private_directory(&dir)?;
        if !name.is_empty() {
            ensure!(
                fs::read_dir(dir)?.next().is_none(),
                "canary directory not empty"
            );
        }
    }
    bound_file(&p.node.path, &p.node.sha256, 512 << 20)?;
    bound_file(&p.worker, WORKER, 256 << 20)?;
    bound_file(&p.snapshot, SNAPSHOT, 11 << 30)?;
    ensure!(
        fs::metadata(&p.snapshot)?.len() == 10_177_204_112,
        "snapshot length"
    );
    bound_file(&p.epoch_hashes.path, &p.epoch_hashes.sha256, 1 << 20)?;
    let hashes = fs::read_to_string(&p.epoch_hashes.path)?;
    validate_checkpoint_names(&hashes)?;
    bound_file(
        &p.ledger_directory.join("genesis.tar.bz2"),
        GENESIS,
        10 << 20,
    )?;
    let ledger = fs::symlink_metadata(&p.ledger_directory)?;
    ensure!(
        p.ledger_directory.canonicalize()? == p.ledger_directory
            && ledger.is_dir()
            && ledger.uid() == 0
            && ledger.mode() & 0o222 == 0,
        "ledger not immutable"
    );
    ensure!(
        fs::symlink_metadata(p.ledger_directory.join("genesis.bin"))
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
        "genesis shadow"
    );
    // The parent may unpack genesis beside its ledger. Keep immutable evidence
    // read-only and give this one diagnostic its own no-clobber ledger copy.
    let genesis = p.run_root.join("ledger/genesis.tar.bz2");
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(p.ledger_directory.join("genesis.tar.bz2"))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&genesis)?;
    std::io::copy(&mut source, &mut output)?;
    output.sync_all()?;
    output.set_permissions(fs::Permissions::from_mode(0o400))?;
    File::open(p.run_root.join("ledger"))?.sync_all()?;
    let mut cmd = command(&p);
    measure(
        &p,
        &invocation,
        &cgroup,
        &mut cmd,
        &json!({"plan_path":args[1],"plan_sha256":args[3],"self_sha256":args[5]}),
    )
}

fn measure(
    p: &Plan,
    invocation: &str,
    cgroup: &Path,
    cmd: &mut Command,
    bindings: &Value,
) -> Result<()> {
    let free_before = free_bytes(&p.run_root)?;
    ensure!(free_before >= p.minimum_free_bytes, "fresh free-space gate");
    let before = metrics(cgroup)?;
    install_signals()?;
    let mut child = ChildGroup(cmd.spawn()?, false);
    let pid = child.0.id();
    let (tx, rx) = mpsc::sync_channel(64);
    reader(child.0.stdout.take().context("stdout")?, tx.clone());
    reader(child.0.stderr.take().context("stderr")?, tx);
    let started = Instant::now();
    let mut observed = None;
    let mut stop_at = None;
    let mut target = false;
    let mut capture = Value::Null;
    let mut error = None;
    let mut exit = None;
    let mut first_progress: Option<Value> = None;
    let mut last_progress: Option<Value> = None;
    let outcome = (|| -> Result<()> {
        loop {
            let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
            if stop_at.is_none()
                && (external != 0 || started.elapsed().as_secs() >= p.maximum_runtime_seconds)
            {
                error = Some(
                    if external != 0 {
                        "external-signal"
                    } else {
                        "runtime-bound"
                    }
                    .to_owned(),
                );
                freeze_group(pid)?;
                capture = capture_resources(&p.run_root.join("scratch"), cgroup)?;
                group_signal(pid, libc::SIGCONT)?;
                group_signal(pid, libc::SIGINT)?;
                stop_at = Some(Instant::now());
            }
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(line)) => {
                    print!("{line}");
                    std::io::stdout().flush()?;
                    if let Some(mut counters) = progress_counters(&line) {
                        counters["elapsed_millis"] = json!(started.elapsed().as_millis());
                        if first_progress.is_none() {
                            first_progress = Some(counters.clone());
                        }
                        last_progress = Some(counters);
                    }
                    if let Some(slot) = progress_slot(&line) {
                        observed = Some(observed.unwrap_or(slot).max(slot));
                        if stop_at.is_none() && slot >= p.target_slot {
                            ensure!(
                                slot <= p.target_slot + 1000,
                                "target overshoot exceeds sealed bound"
                            );
                            freeze_group(pid)?;
                            capture = capture_resources(&p.run_root.join("scratch"), cgroup)?;
                            let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
                            ensure!(external == 0, "external signal during target capture");
                            let capture_path = p.run_root.join("receipts/target-capture.json");
                            let capture_sha256 =
                                hex(&Sha256::digest(serde_json::to_vec(&capture)?));
                            persist(&capture_path, &capture)?;
                            persist(
                                &p.run_root.join("receipts/target-stop.json"),
                                &json!({"schema":"jetstreamer-private-epoch225-canary-target-stop-v1","invocation_id":invocation,"target_slot":p.target_slot,"observed_slot":slot,"child_pid":pid,"written_unix_seconds":now()?,"scratch_snapshot_captured":true,"external_signal":0,"capture_path":capture_path,"capture_canonical_json_sha256":capture_sha256}),
                            )?;
                            target = true;
                            group_signal(pid, libc::SIGCONT)?;
                            group_signal(pid, libc::SIGINT)?;
                            stop_at = Some(Instant::now());
                        }
                    }
                }
                Ok(Err(message)) => anyhow::bail!("child log: {message}"),
                Err(mpsc::RecvTimeoutError::Timeout | mpsc::RecvTimeoutError::Disconnected) => {}
            }
            if let Some(status) = child.0.try_wait()? {
                child.1 = true;
                exit = Some(status);
                break;
            }
            if stop_at.is_some_and(|t| t.elapsed() > Duration::from_secs(120)) {
                anyhow::bail!("controlled child drainage timed out");
            }
        }
        Ok(())
    })();
    if let Err(e) = outcome {
        error = Some(format!("{e:#}"));
    }
    // Stop/reap only our own diagnostic group; a failed measurement never
    // grants retirement or replay-retry authority.
    if exit.is_none() {
        group_signal(pid, libc::SIGCONT)?;
        group_signal(pid, libc::SIGKILL)?;
        exit = child.0.try_wait()?;
        if exit.is_some() {
            child.1 = true;
        }
    }
    let external = EXTERNAL_SIGNAL.load(Ordering::SeqCst);
    let code = exit.as_ref().and_then(|s| s.code());
    let sidecar_seen = fs::read_dir(p.run_root.join("output"))?.try_fold(
        false,
        |found, entry| -> Result<bool> {
            Ok(found || entry?.file_name().to_string_lossy().ends_with(".sha256"))
        },
    )?;
    if sidecar_seen {
        error = Some("unexpected checksum sidecar in diagnostic output".to_owned());
    }
    let success = error.is_none() && controlled_success(target, external, code);
    let payload = json!({"schema":"jetstreamer-private-epoch225-bounded-resource-v1","epoch":225,"unit":p.unit,"invocation_id":invocation,"plan":{"path":bindings["plan_path"],"sha256":bindings["plan_sha256"]},"runner_sha256":bindings["self_sha256"],"node_sha256":p.node.sha256,"worker_sha256":WORKER,"snapshot_sha256":SNAPSHOT,"target_slot":p.target_slot,"observed_slot":observed,"target_reached":target,"first_progress":first_progress,"last_progress":last_progress,"child_pid":pid,"child_return_code":code,"external_signal":external,"elapsed_millis":started.elapsed().as_millis(),"capture":capture,"cgroup_before":before,"cgroup_after":metrics(cgroup)?,"free_before":free_before,"free_after":free_bytes(&p.run_root)?,"success":success,"error":error,"authority":{"ordinary_replay_authorized":false,"full_cold_epoch_peak_qualified":false,"publication_authorized":false,"runtime_promotion_authorized":false,"canonical_sidecar_authorized":false,"remote_mutations":false,"r2_mutations":false}});
    persist(
        &p.run_root.join(if success {
            "receipts/resource.json"
        } else {
            "receipts/failure.json"
        }),
        &payload,
    )?;
    ensure!(
        success,
        "bounded replay did not complete its diagnostic target"
    );
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_plan() -> Plan {
        serde_json::from_value(json!({
            "schema":"jetstreamer-private-epoch225-bounded-resource-plan-v1",
            "unit":"horizon-qualify-225-bounded-resource-test.service",
            "node":{"path":"/sealed/node","sha256":"a".repeat(64)},
            "worker":"/sealed/worker",
            "snapshot":"/sealed/snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst",
            "ledger_directory":"/sealed","epoch_hashes":{"path":"/sealed/hashes","sha256":"b".repeat(64)},
            "run_root":"/home/ubuntu/.jetstreamer-private/bounded-resource-225-test",
            "target_slot":TARGET,"terminal_slot":TERMINAL,"minimum_free_bytes":MINIMUM_FREE,"maximum_runtime_seconds":3600
        })).unwrap()
    }
    #[test]
    fn plan_cannot_expand_epoch_target_runtime_or_resource_scope() {
        validate_plan(&fixture_plan()).unwrap();
        let mut p = fixture_plan();
        p.target_slot += 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.terminal_slot += 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.minimum_free_bytes -= 1;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.maximum_runtime_seconds = 3601;
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.unit = "horizon-qualify-226-bounded-resource-test.service".into();
        assert!(validate_plan(&p).is_err());
        let mut p = fixture_plan();
        p.run_root = "/home/ubuntu/horizon".into();
        assert!(validate_plan(&p).is_err());
    }
    #[test]
    fn command_is_private_focused_and_pins_exact_runtime() {
        let p = fixture_plan();
        let c = command(&p);
        let args = c
            .get_args()
            .map(|a| a.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            &args[..2],
            [
                "225",
                "/home/ubuntu/.jetstreamer-private/bounded-resource-225-test/ledger"
            ]
        );
        assert!(args.contains(&"--verify"));
        assert!(args.contains(&"--qualification-end-slot=97631459"));
        assert!(
            !args
                .iter()
                .any(|a| a.contains("root-checkpoint-cohort") || a.contains("publish-through"))
        );
        assert!(args.iter().any(|a| {
            a.starts_with("--horizon-output=/home/ubuntu/.jetstreamer-private/")
                && a.ends_with("/output/epoch-225-canary.jet")
        }));
        let env = c
            .get_envs()
            .map(|(k, v)| (k.to_str().unwrap(), v.and_then(|s| s.to_str())))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env["JETSTREAMER_HISTORICAL_WORKER_V1_6_20"],
            Some("/sealed/worker")
        );
        assert_eq!(env["SOLANA_RAYON_THREADS"], Some("16"));
        assert_eq!(env["HORIZON_SECRET_ACCESS_KEY"], None);
    }
    #[test]
    fn checkpoints_are_exact_not_an_arbitrary_same_epoch_file() {
        let exact = "snapshot-97199617-HE57JmgvEeZjBKN8cfTLrmyCbUnptJ9PWjUdTzgxSSdi.tar.zst\nsnapshot-97631459-EXCmpk8xjtzsow8EH56CQJzQncMgiF6D1s9DJ3pw9q8d.tar.zst\n";
        validate_checkpoint_names(exact).unwrap();
        assert!(validate_checkpoint_names(&exact.replace("97631459", "97631458")).is_err());
        assert!(validate_checkpoint_names(&format!("{exact}snapshot-1-fake.tar.zst\n")).is_err());
    }
    #[test]
    fn target_detection_does_not_require_optional_counters() {
        let line =
            "[2026-10-19T00:00:00Z INFO  jetstreamer_node] progress slot 97202500/97631459 (0.6%)";
        assert_eq!(progress_slot(line), Some(TARGET));
        assert_eq!(
            progress_slot(&line.replace("jetstreamer_node]", "other_module]")),
            None
        );
        assert_eq!(progress_slot(&line.replace("97631459", "97202501")), None);
        assert_eq!(progress_slot(&line.replace("97202500/", "garbage/")), None);
        assert_eq!(
            progress_slot("program log: progress slot 97202500/97631459"),
            None
        );
        assert!(progress_counters(line).is_none());
        assert_eq!(
            progress_counters(&format!("{line} txs=123 accounts=456")).unwrap(),
            json!({"slot":TARGET,"transactions":123,"account_updates":456})
        );
    }
    #[test]
    fn only_our_posttarget_zero_or_one_exit_can_succeed() {
        for target in [false, true] {
            for external in [0, libc::SIGTERM] {
                for code in [None, Some(0), Some(1), Some(2)] {
                    assert_eq!(
                        controlled_success(target, external, code),
                        target && external == 0 && matches!(code, Some(0 | 1))
                    );
                }
            }
        }
    }
    #[test]
    fn scratch_is_bounded_and_never_follows_symlinks() {
        let t = tempfile::tempdir().unwrap();
        fs::write(t.path().join("file"), b"abc").unwrap();
        let measured = scratch(t.path()).unwrap();
        assert_eq!(measured["regular_files"], 1);
        std::os::unix::fs::symlink("/", t.path().join("escape")).unwrap();
        assert!(scratch(t.path()).is_err());
    }
    #[test]
    fn capture_requires_one_live_accounts_state_and_keeps_both_measurements() {
        let t = tempfile::tempdir().unwrap();
        assert_eq!(
            scratch(t.path()).unwrap()["accounts_state_roots"],
            json!([])
        );
        let account = t.path().join("accounts-state");
        fs::create_dir(&account).unwrap();
        fs::write(account.join("1.0"), b"account").unwrap();
        let all = scratch(t.path()).unwrap();
        assert_eq!(all["accounts_state_roots"], json!([account]));
        let narrow = scratch(&account).unwrap();
        assert_eq!(narrow["regular_files"], 1);
        assert_eq!(narrow["file_size_histogram_bytes"]["7"], 1);
    }
    #[test]
    fn log_reader_caps_line_allocation_and_reports_failure() {
        let (tx, rx) = mpsc::sync_channel(1);
        reader(std::io::Cursor::new(vec![b'x'; 65537]), tx);
        assert!(rx.recv_timeout(Duration::from_secs(2)).unwrap().is_err());
    }
    #[test]
    fn process_stat_parser_handles_parentheses_inside_comm() {
        assert_eq!(
            stat_group_state("123 (a)b(c) T 1 123 456").unwrap(),
            (123, 'T')
        );
        assert!(stat_group_state("not a stat").is_err());
    }
    #[test]
    fn freezing_an_owned_group_does_not_stop_another_group() {
        let mut own = ChildGroup(
            Command::new("/bin/sleep")
                .arg("20")
                .process_group(0)
                .spawn()
                .unwrap(),
            false,
        );
        let mut other = ChildGroup(
            Command::new("/bin/sleep")
                .arg("20")
                .process_group(0)
                .spawn()
                .unwrap(),
            false,
        );
        freeze_group(own.0.id()).unwrap();
        assert!(group_stopped(own.0.id()).unwrap());
        assert!(!group_stopped(other.0.id()).unwrap());
        for child in [&mut own, &mut other] {
            group_signal(child.0.id(), libc::SIGCONT).unwrap();
            group_signal(child.0.id(), libc::SIGKILL).unwrap();
            child.0.wait().unwrap();
            child.1 = true;
        }
    }
    #[test]
    fn immutable_input_binding_checks_root_ownership_mode_digest_and_symlinks() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("sealed");
        fs::write(&path, b"evidence").unwrap();
        let sha = hex(&Sha256::digest(b"evidence"));
        assert!(bound_file(&path, &sha, 100).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        bound_file(&path, &sha, 100).unwrap();
        assert!(bound_file(&path, &"0".repeat(64), 100).is_err());
        assert!(bound_file(&path, &sha, 7).is_err());
        let link = t.path().join("alias");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(bound_file(&link, &sha, 100).is_err());
    }
    // Separate test-harness process; production accepts no fake-node override.
    #[test]
    fn canary_child_fixture() {
        let Ok(root) = env::var("JETSTREAMER_TEST_225_RESOURCE_ROOT") else {
            return;
        };
        let root = PathBuf::from(root);
        assert!(
            root.starts_with(env::temp_dir())
                && root
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("epoch225-resource-fixture-")
        );
        if env::var("JETSTREAMER_TEST_225_PRETARGET_EXIT").is_ok() {
            std::process::exit(1);
        }
        let accounts = root.join("scratch/runtime/accounts-state");
        fs::create_dir_all(&accounts).unwrap();
        fs::write(accounts.join("1.0"), b"live account state").unwrap();
        install_signals().unwrap();
        eprintln!(
            "[2026-10-19T00:00:00Z INFO  jetstreamer_node] progress slot {TARGET}/{TERMINAL} (0.6%)"
        );
        while EXTERNAL_SIGNAL.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(10));
        }
        fs::remove_dir_all(&accounts).unwrap();
        std::process::exit(1);
    }

    fn exercise_child(pretarget: bool) -> (tempfile::TempDir, Result<()>) {
        let temp = tempfile::Builder::new()
            .prefix("epoch225-resource-fixture-")
            .tempdir()
            .unwrap();
        let mut p = fixture_plan();
        p.run_root = temp.path().to_path_buf();
        p.minimum_free_bytes = 0;
        for name in ["scratch", "output", "receipts", "cgroup"] {
            let d = temp.path().join(name);
            fs::create_dir(&d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let cgroup = temp.path().join("cgroup");
        for name in [
            "memory.current",
            "memory.peak",
            "memory.events",
            "memory.stat",
            "cpu.stat",
            "io.stat",
            "memory.pressure",
            "io.pressure",
        ] {
            fs::write(cgroup.join(name), "0\n").unwrap();
        }
        let mut cmd = Command::new(env::current_exe().unwrap());
        cmd.args(["--exact", "tests::canary_child_fixture", "--nocapture"])
            .env("JETSTREAMER_TEST_225_RESOURCE_ROOT", temp.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if pretarget {
            cmd.env("JETSTREAMER_TEST_225_PRETARGET_EXIT", "1");
        }
        let result = measure(
            &p,
            &"a".repeat(32),
            &cgroup,
            &mut cmd,
            &json!({"plan_path":"/sealed/test","plan_sha256":"b".repeat(64),"self_sha256":"c".repeat(64)}),
        );
        (temp, result)
    }

    #[test]
    fn real_target_stop_captures_live_state_before_child_retires_it() {
        let (temp, result) = exercise_child(false);
        result.unwrap();
        let receipt: Value =
            serde_json::from_slice(&fs::read(temp.path().join("receipts/resource.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["child_return_code"], 1);
        assert_eq!(receipt["capture"]["accounts_state"]["regular_files"], 1);
        assert_eq!(
            receipt["authority"]["full_cold_epoch_peak_qualified"],
            false
        );
        assert_eq!(receipt["authority"]["publication_authorized"], false);
        assert!(!temp.path().join("scratch/runtime/accounts-state").exists());
        let intent: Value = serde_json::from_slice(
            &fs::read(temp.path().join("receipts/target-stop.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(intent["target_slot"], TARGET);
        assert_eq!(intent["external_signal"], 0);
        assert_eq!(intent["scratch_snapshot_captured"], true);
        assert!(temp.path().join("receipts/target-capture.json").is_file());
    }

    #[test]
    fn real_pretarget_failure_is_not_normalized_and_keeps_counters() {
        let (temp, result) = exercise_child(true);
        assert!(result.is_err());
        let receipt: Value =
            serde_json::from_slice(&fs::read(temp.path().join("receipts/failure.json")).unwrap())
                .unwrap();
        assert_eq!(receipt["success"], false);
        assert_eq!(receipt["target_reached"], false);
        assert_eq!(receipt["child_return_code"], 1);
        assert!(!receipt["cgroup_before"].is_null() && !receipt["cgroup_after"].is_null());
        assert!(!temp.path().join("receipts/resource.json").exists());
    }

    #[test]
    fn receipts_are_owner_only_and_never_clobbered() {
        let t = tempfile::tempdir().unwrap();
        fs::set_permissions(t.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let p = t.path().join("receipt.json");
        persist(&p, &json!({"original":true})).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().mode() & 0o077, 0);
        assert!(persist(&p, &json!({"replacement":true})).is_err());
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(p).unwrap()).unwrap(),
            json!({"original":true})
        );
    }
}
