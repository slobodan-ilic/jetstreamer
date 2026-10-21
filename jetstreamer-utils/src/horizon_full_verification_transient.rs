//! Separate private v2 evidence profile for the already-running epoch-140 transient reread.
//! This is not a recovery-v1 receipt or initial-anchor/publication qualification.
use super::*;

pub(super) const PLAN_SCHEMA: &str =
    "jetstreamer-horizon-transient-full-verification-evidence-plan-v2";
const UNIT: &str = "horizon-epoch140-source-bound-full-reread-20261020-v1.service";
const INVOCATION: &str = "6c553218f2d64309935be94785077ccd";
const VERIFIER: &str =
    "/usr/local/lib/jetstreamer/horizon-epoch140-reread-20261019-v4/verify_archive";
const VERIFIER_SHA: &str = "f27caf676a477d77d5e423125d1cb840f53589af09f36ca9b67a8732c35fb9e8";
const SOURCE_SHA: &str = "65d311f5b96b2c1f2b8ff50ecfbe5da29bcf57573b55b39c48282f6d259a6842";
const UNIT_SHA: &str = "681ba1f6302aa1bc8ad764872239494cc3474443fdeb124beec2fe13addd4d42";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    runtime_fragment: Evidence,
    unit_seal_receipt: Evidence,
    source_sha256: String,
    source_identity: Identity,
    source_ctime_seconds: i64,
    source_ctime_nanoseconds: i64,
    output_metadata: PathBuf,
}

fn sealed_evidence(evidence: &Evidence, limit: u64) -> Result<Vec<u8>, String> {
    let (bytes, identity) = read_hashed(&evidence.path, &evidence.sha256, limit)?;
    require_root_sealed_file(identity, "transient profile evidence")?;
    Ok(bytes)
}

fn seal_member(seal: &Evidence, member: &Evidence) -> Result<(), String> {
    let bytes = sealed_evidence(seal, MAX_JSON_BYTES)?;
    validate_seal_member(&bytes, member)
}

fn validate_seal_member(bytes: &[u8], member: &Evidence) -> Result<(), String> {
    let receipt: SealReceipt = serde_json::from_slice(bytes)
        .map_err(|error| format!("invalid separate deployment seal: {error}"))?;
    if receipt.schema != SEAL_RECEIPT_SCHEMA
        || receipt.publication_authorized
        || receipt.replay_launch_authorized
        || receipt.remote_mutations
        || receipt.r2_mutations
        || member.path.parent() != Some(receipt.destination.as_path())
        || receipt
            .members
            .iter()
            .filter(|entry| {
                Some(OsStr::new(&entry.name)) == member.path.file_name()
                    && entry.sha256 == member.sha256
            })
            .count()
            != 1
    {
        return Err("separate seal does not bind the exact non-authorizing member".into());
    }
    Ok(())
}

fn quoted_exec_start(plan: &Plan) -> Result<String, String> {
    let values = [
        plan.verifier.path.to_string_lossy().into_owned(),
        plan.archive.path.to_string_lossy().into_owned(),
        "--full".into(),
        "--internal-full".into(),
        "--threads".into(),
        plan.unit.threads.to_string(),
    ];
    if values.iter().any(|value| {
        value
            .chars()
            .any(|c| c.is_control() || ['"', '\\', '%', '$'].contains(&c))
    }) {
        return Err("transient argv requires an unsupported escape".into());
    }
    Ok(format!(
        "ExecStart={}",
        values
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(" ")
    ))
}

fn validate_fragment(plan: &Plan, bytes: &[u8]) -> Result<(), String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "fragment is not UTF-8")?;
    let commands: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("ExecStart="))
        .collect();
    let expected = quoted_exec_start(plan)?;
    if commands != ["ExecStart=", expected.as_str()] {
        return Err("transient fragment does not have the exact reset and quoted argv".into());
    }
    for directive in [
        "Type=oneshot",
        "RemainAfterExit=yes",
        "Restart=no",
        "ProtectSystem=strict",
        "ProtectHome=read-only",
        "PrivateNetwork=yes",
    ] {
        let name = directive.split_once('=').expect("literal directive").0;
        let matching: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with(&format!("{name}=")))
            .collect();
        if matching != [directive] {
            return Err(format!("missing or conflicting {name} directive"));
        }
    }
    Ok(())
}

fn runtime_fragment(plan: &Plan, profile: &Profile, immutable: &[u8]) -> Result<(), String> {
    let (bytes, identity) = read_hashed(&profile.runtime_fragment.path, UNIT_SHA, MAX_UNIT_BYTES)?;
    // systemd owns and may write this transient fragment. Never chmod it or call it sealed.
    if identity.uid != 0 || identity.mode & 0o022 != 0 || bytes != immutable {
        return Err("runtime fragment differs from its independently sealed copy".into());
    }
    validate_fragment(plan, &bytes)
}

fn validate_state(
    plan: &Plan,
    fields: &BTreeMap<String, String>,
    check_only: bool,
) -> Result<(), String> {
    let profile = plan.transient.as_ref().ok_or("missing transient profile")?;
    let pid = parse_u64_field(fields, "MainPID")?;
    let terminal = field(fields, "ActiveState")? == "active"
        && field(fields, "SubState")? == "exited"
        && pid == 0;
    let running = check_only
        && field(fields, "ActiveState")? == "activating"
        && field(fields, "SubState")? == "start"
        && pid > 0;
    if field(fields, "LoadState")? != "loaded"
        || !(terminal || running)
        || field(fields, "InvocationID")? != plan.unit.invocation_id
        || field(fields, "Result")? != "success"
        || parse_u64_field(fields, "NRestarts")? != 0
        || parse_u64_field(fields, "ExecMainStatus")? != 0
        || parse_u64_field(fields, "ExecMainCode")? != i32::from(terminal) as u64
        || field(fields, "FragmentPath")? != profile.runtime_fragment.path.to_string_lossy()
        || field(fields, "Type")? != "oneshot"
        || field(fields, "RemainAfterExit")? != "yes"
        || field(fields, "Restart")? != "no"
        || !field(fields, "DropInPaths")?.is_empty()
    {
        return Err("not the exact zero-restart transient invocation in the required state".into());
    }
    let effective = field(fields, "ExecStart")?;
    let expected = format!("argv[]={}; ignore_errors=no ;", exact_command_line(plan));
    if effective.matches("argv[]=").count() != 1 || !effective.contains(&expected) {
        return Err("effective systemd argv differs from the bound verifier command".into());
    }
    if terminal
        && (parse_u64_field(fields, "ExecMainPID")? == 0
            || parse_u64_field(fields, "ExecMainExitTimestampMonotonic")? == 0)
    {
        return Err("terminal verifier PID or exit timestamp is absent".into());
    }
    Ok(())
}

fn state(plan: &Plan, check_only: bool) -> Result<BTreeMap<String, String>, String> {
    let output = Command::new("/usr/bin/systemctl").args([
        "show", &plan.unit.name, "--no-pager",
        "--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ExecMainCode,NRestarts,InvocationID,FragmentPath,MainPID,ExecMainPID,ExecMainExitTimestampMonotonic,Type,RemainAfterExit,Restart,DropInPaths,ExecStart",
    ]).output().map_err(|error| format!("systemctl transient identity: {error}"))?;
    if !output.status.success() {
        return Err("systemctl transient identity failed".into());
    }
    let fields = parse_systemctl_show(&output.stdout)?;
    validate_state(plan, &fields, check_only)?;
    Ok(fields)
}

fn audit_journal(
    plan: &Plan,
    bytes: &[u8],
    plain: &[u8],
    state: &BTreeMap<String, String>,
) -> Result<serde_json::Value, String> {
    let expected_command = exact_command_line(plan);
    let mut service_messages = Vec::new();
    let mut pids = BTreeSet::new();
    let mut timestamps = Vec::new();
    let mut finishes = Vec::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: JournalRecord =
            serde_json::from_slice(line).map_err(|error| format!("journal metadata: {error}"))?;
        let timestamp =
            required_journal_u64(record.realtime_timestamp.as_deref(), "__REALTIME_TIMESTAMP")?;
        if record.systemd_unit.as_deref() == Some(plan.unit.name.as_str()) {
            if record.invocation_id.as_deref() != Some(plan.unit.invocation_id.as_str())
                || record.executable.as_deref() != Some(VERIFIER)
                || record.command_line.as_deref() != Some(expected_command.as_str())
            {
                return Err("journal service executable/argv/invocation mismatch".into());
            }
            pids.insert(required_journal_u64(record.pid.as_deref(), "_PID")?);
            timestamps.push(timestamp);
            service_messages.extend_from_slice(
                record
                    .message
                    .as_deref()
                    .ok_or("missing service MESSAGE")?
                    .as_bytes(),
            );
            service_messages.push(b'\n');
        }
        if record.unit.as_deref() == Some(plan.unit.name.as_str()) {
            if record.pid.as_deref() != Some("1")
                || record.executable.as_deref() != Some("/usr/lib/systemd/systemd")
            {
                return Err("manager journal record lacks exact systemd identity".into());
            }
            let message = record.message.as_deref().ok_or("missing manager MESSAGE")?;
            if message == format!("{}: Deactivated successfully.", plan.unit.name) {
                return Err("RemainAfterExit invocation unexpectedly deactivated".into());
            }
            if message.starts_with(&format!("Finished {} - ", plan.unit.name))
                && record.job_result.as_deref() == Some("done")
            {
                finishes.push(timestamp);
            }
        }
    }
    if timestamps.is_empty()
        || finishes.len() != 1
        || pids.len() != 1
        || !pids.contains(&parse_u64_field(state, "ExecMainPID")?)
        || timestamps.iter().any(|timestamp| *timestamp > finishes[0])
        || service_messages != plain
    {
        return Err(
            "journal does not bind one exact verifier PID, complete log and successful finish"
                .into(),
        );
    }
    result_line(plain)?;
    Ok(serde_json::json!({
        "pid": pids.first(), "records": timestamps.len(),
        "first_realtime_timestamp_us": timestamps.iter().min(),
        "last_realtime_timestamp_us": timestamps.iter().max(),
        "finished_realtime_timestamp_us": finishes[0],
        "deactivated_realtime_timestamp_us": null,
        "deactivation_observed": false
    }))
}

fn source_identity(plan: &Plan, profile: &Profile, file: &File) -> Result<(), String> {
    for metadata in [file.metadata(), fs::symlink_metadata(&plan.archive.path)] {
        let metadata = metadata.map_err(|error| format!("source identity: {error}"))?;
        if !metadata.is_file()
            || identity(&metadata) != profile.source_identity
            || metadata.ctime() != profile.source_ctime_seconds
            || metadata.ctime_nsec() != profile.source_ctime_nanoseconds
        {
            return Err("source identity differs from the pre-reread binding".into());
        }
    }
    let sidecar = PathBuf::from(format!("{}.sha256", plan.archive.path.display()));
    match fs::symlink_metadata(sidecar) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err("canonical sidecar must be positively absent".into()),
    }
}

pub(super) fn run(arguments: &Arguments, plan: &Plan) -> Result<(), String> {
    let profile = plan
        .transient
        .as_ref()
        .ok_or("v2 requires explicit transient profile")?;
    let expected_fragment = PathBuf::from(format!("/run/systemd/transient/{UNIT}"));
    if plan.epoch != 140
        || plan.unit.name != UNIT
        || plan.unit.invocation_id != INVOCATION
        || plan.unit.threads != 8
        || plan.verifier.path != Path::new(VERIFIER)
        || plan.verifier.sha256 != VERIFIER_SHA
        || profile.source_sha256 != SOURCE_SHA
        || profile.runtime_fragment.path != expected_fragment
        || profile.runtime_fragment.sha256 != UNIT_SHA
        || plan.unit.installed_file.sha256 != UNIT_SHA
        || profile.source_identity.device != 64512
        || profile.source_identity.inode != 99811416
        || profile.source_identity.bytes != 103138915297
        || profile.source_identity.mode != 0o440
        || plan.archive.bytes != profile.source_identity.bytes
        || plan.archive.uid != profile.source_identity.uid
        || plan.archive.gid != profile.source_identity.gid
        || plan.archive.mode != "0440"
        || plan.authority.archive_mutations
        || plan.authority.sidecar_created
        || plan.authority.replay_launch_authorized
        || plan.authority.publication_authorized
        || plan.authority.remote_mutations
        || plan.authority.r2_mutations
    {
        return Err("v2 is restricted to the exact private epoch-140 reread and source".into());
    }
    for path in [
        &plan.output_log,
        &profile.output_metadata,
        &plan.output_receipt,
    ] {
        validate_output_path(path, "private v2 output")?;
        if path.parent() != plan.output_receipt.parent() {
            return Err("outputs need one private parent".into());
        }
    }
    if plan.output_log == profile.output_metadata
        || plan.output_log == plan.output_receipt
        || profile.output_metadata == plan.output_receipt
    {
        return Err("private output paths must be distinct".into());
    }
    let current_exe = env::current_exe().map_err(|error| error.to_string())?;
    hash_executable(&current_exe, &arguments.self_sha256)?;
    hash_executable(&plan.verifier.path, VERIFIER_SHA)?;
    let immutable = sealed_evidence(&plan.unit.installed_file, MAX_UNIT_BYTES)?;
    seal_member(&plan.deployment_seal_receipt, &plan.verifier)?;
    seal_member(&profile.unit_seal_receipt, &plan.unit.installed_file)?;
    runtime_fragment(plan, profile, &immutable)?;
    let (mut source, _) = open_regular_nofollow(&plan.archive.path, plan.archive.bytes)?;
    source_identity(plan, profile, &source)?;
    let before = state(plan, arguments.check_only)?;
    if arguments.check_only {
        println!(
            "{}",
            serde_json::json!({"outcome":"transient-profile-check-only-passed", "full_reread_result_collected":false, "source_rehashed":false, "publication_authorized":false, "r2_mutations":false})
        );
        return Ok(());
    }
    let output = Command::new("/usr/bin/journalctl")
        .args([
            "--no-pager",
            "--output=json",
            "--all",
            "--unit",
            &plan.unit.name,
        ])
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_JOURNAL_BYTES
    {
        return Err("bounded transient journal query failed".into());
    }
    let plain = collect_journal(&plan.unit.invocation_id)?;
    let audit = audit_journal(plan, &output.stdout, &plain, &before)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 8 * 1024 * 1024];
    loop {
        let count = source
            .read(&mut buffer)
            .map_err(|error| format!("post-reread source hash: {error}"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex(&digest.finalize()) != SOURCE_SHA {
        return Err("post-reread whole-source SHA mismatch".into());
    }
    source_identity(plan, profile, &source)?;
    runtime_fragment(plan, profile, &immutable)?;
    if state(plan, false)? != before {
        return Err("terminal systemd identity changed during source rehash".into());
    }
    let receipt = serde_json::json!({
        "schema":"horizon-private-transient-full-verification-v2", "status":"passed", "epoch":140,
        "archive":{"path":plan.archive.path,"sha256":SOURCE_SHA,"identity":profile.source_identity,
            "ctime_seconds":profile.source_ctime_seconds,"ctime_nanoseconds":profile.source_ctime_nanoseconds,
            "whole_source_rehashed_after_reread":true},
        "verifier":{"path":plan.verifier.path,"sha256":VERIFIER_SHA},
        "unit":{"name":UNIT,"invocation_id":INVOCATION,"effective_properties":before,"journal":audit,
            "runtime_fragment":profile.runtime_fragment.path,"fragment_sha256":UNIT_SHA,
            "immutable_copy":plan.unit.installed_file.path},
        "log":{"path":plan.output_log,"sha256":hex(&Sha256::digest(&plain))},
        "journal_metadata":{"path":profile.output_metadata,"sha256":hex(&Sha256::digest(&output.stdout))},
        "separate_seals":{"verifier":{"path":plan.deployment_seal_receipt.path,"sha256":plan.deployment_seal_receipt.sha256},
            "unit":{"path":profile.unit_seal_receipt.path,"sha256":profile.unit_seal_receipt.sha256}},
        "plan":{"path":arguments.plan,"sha256":arguments.plan_sha256},"collector_sha256":arguments.self_sha256,
        "result":{"line":result_line(&plain)?}, "initial_anchor_proven":false,
        "archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,
        "publication_authorized":false,"remote_mutations":false,"r2_mutations":false
    });
    write_new(&plan.output_log, &plain)?;
    write_new(&profile.output_metadata, &output.stdout)?;
    source_identity(plan, profile, &source)?;
    let mut bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    write_new(&plan.output_receipt, &bytes)?;
    println!(
        "{}",
        serde_json::json!({"outcome":"private-transient-full-evidence-created","receipt":plan.output_receipt,
        "receipt_sha256":hex(&Sha256::digest(&bytes)),"publication_authorized":false,"r2_mutations":false})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> Plan {
        serde_json::from_value(serde_json::json!({
            "schema":PLAN_SCHEMA,"epoch":140,
            "archive":{"path":"/private/epoch-140.jet","bytes":103138915297_u64,"uid":1001,"gid":1003,"mode":"0440"},
            "verifier":{"path":VERIFIER,"sha256":VERIFIER_SHA},
            "unit":{"name":UNIT,"invocation_id":INVOCATION,"threads":8,
                "installed_file":{"path":format!("/sealed/{UNIT}"),"sha256":UNIT_SHA}},
            "deployment_seal_receipt":{"path":"/verifier/deployment-seal-receipt.json","sha256":"00".repeat(32)},
            "output_log":"/results/scan.log","output_receipt":"/results/receipt.json",
            "authority":{"archive_mutations":false,"sidecar_created":false,"replay_launch_authorized":false,
                "publication_authorized":false,"remote_mutations":false,"r2_mutations":false},
            "transient":{
                "runtime_fragment":{"path":format!("/run/systemd/transient/{UNIT}"),"sha256":UNIT_SHA},
                "unit_seal_receipt":{"path":"/sealed/deployment-seal-receipt.json","sha256":"11".repeat(32)},
                "source_sha256":SOURCE_SHA,"source_identity":{"device":64512,"inode":99811416,
                    "bytes":103138915297_u64,"uid":1001,"gid":1003,"mode":288,"links":1,
                    "mtime_seconds":1792366350_i64,"mtime_nanoseconds":258158104},
                "source_ctime_seconds":1792366350_i64,"source_ctime_nanoseconds":292158293,
                "output_metadata":"/results/journal.jsonl"
            }
        })).unwrap()
    }

    fn fields(plan: &Plan) -> BTreeMap<String, String> {
        parse_systemctl_show(format!(concat!(
            "LoadState=loaded\nActiveState=active\nSubState=exited\nResult=success\n",
            "ExecMainStatus=0\nExecMainCode=1\nNRestarts=0\nInvocationID={}\n",
            "FragmentPath=/run/systemd/transient/{}\nMainPID=0\nExecMainPID=42\n",
            "ExecMainExitTimestampMonotonic=500\nType=oneshot\nRemainAfterExit=yes\nRestart=no\nDropInPaths=\n",
            "ExecStart={{ path={} ; argv[]={}; ignore_errors=no ; start_time=x ; stop_time=y ; pid=42 ; code=exited ; status=0 }}\n"
        ), INVOCATION, UNIT, VERIFIER, exact_command_line(plan)).as_bytes()).unwrap()
    }

    fn journal(plan: &Plan, deactivated: bool) -> (Vec<u8>, Vec<u8>) {
        let plain = b"=== verify summary (1s) ===\n=== full PoH verification ===\nRESULT: OK (internal only): first block unanchored.\n".to_vec();
        let message = std::str::from_utf8(&plain).unwrap().trim_end_matches('\n');
        let mut records = vec![
            serde_json::json!({
                "__REALTIME_TIMESTAMP":"100","MESSAGE":message,"_SYSTEMD_UNIT":UNIT,
                "_SYSTEMD_INVOCATION_ID":INVOCATION,"_EXE":VERIFIER,
                "_CMDLINE":exact_command_line(plan),"_PID":"42"
            }),
            serde_json::json!({
                "__REALTIME_TIMESTAMP":"200","MESSAGE":format!("Finished {UNIT} - verification."),
                "UNIT":UNIT,"_EXE":"/usr/lib/systemd/systemd","_PID":"1","JOB_RESULT":"done"
            }),
        ];
        if deactivated {
            records.push(serde_json::json!({"__REALTIME_TIMESTAMP":"199",
                "MESSAGE":format!("{UNIT}: Deactivated successfully."),"UNIT":UNIT,
                "_EXE":"/usr/lib/systemd/systemd","_PID":"1"}));
        }
        let bytes = records
            .iter()
            .map(|record| format!("{record}\n"))
            .collect::<String>()
            .into_bytes();
        (bytes, plain)
    }

    #[test]
    fn active_exited_is_honest_terminal_without_deactivation() {
        let plan = plan();
        let state = fields(&plan);
        validate_state(&plan, &state, false).unwrap();
        let (metadata, plain) = journal(&plan, false);
        let audit = audit_journal(&plan, &metadata, &plain, &state).unwrap();
        assert!(audit["deactivated_realtime_timestamp_us"].is_null());
        assert_eq!(audit["deactivation_observed"], false);
        assert_eq!(audit["pid"], 42);
    }

    #[test]
    fn running_is_check_only_never_collection() {
        let plan = plan();
        let mut state = fields(&plan);
        for (key, value) in [
            ("ActiveState", "activating"),
            ("SubState", "start"),
            ("MainPID", "42"),
            ("ExecMainCode", "0"),
        ] {
            state.insert(key.into(), value.into());
        }
        validate_state(&plan, &state, true).unwrap();
        assert!(validate_state(&plan, &state, false).is_err());
    }

    #[test]
    fn rejects_changed_identity_restarts_dropins_and_effective_commands() {
        let plan = plan();
        for (key, value) in [
            ("InvocationID", "foreign"),
            ("NRestarts", "1"),
            ("ExecMainStatus", "1"),
            ("MainPID", "42"),
            ("ExecMainCode", "2"),
            ("DropInPaths", "/etc/override.conf"),
            ("ExecStart", "argv[]=different;"),
            ("ExecMainExitTimestampMonotonic", "0"),
            ("FragmentPath", "/different.service"),
        ] {
            let mut state = fields(&plan);
            state.insert(key.into(), value.into());
            assert!(
                validate_state(&plan, &state, false).is_err(),
                "accepted {key}"
            );
        }
    }

    #[test]
    fn accepts_exact_quoted_reset_and_identical_core_limit_duplicates() {
        let plan = plan();
        let fragment = format!("Type=oneshot\nRemainAfterExit=yes\nRestart=no\nProtectSystem=strict\nProtectHome=read-only\nPrivateNetwork=yes\nLimitCORE=0\nLimitCORE=0\nExecStart=\n{}\n",quoted_exec_start(&plan).unwrap());
        validate_fragment(&plan, fragment.as_bytes()).unwrap();
        for changed in [
            fragment.replace("ExecStart=\n", ""),
            format!("{fragment}ExecStart=/bad\n"),
            format!("{fragment}Restart=always\n"),
            fragment.replace("\"--full\"", "\"--partial\""),
        ] {
            assert!(validate_fragment(&plan, changed.as_bytes()).is_err());
        }
    }

    #[test]
    fn rejects_unbound_journals_missing_finish_and_wrong_pid() {
        let plan = plan();
        let state = fields(&plan);
        let (metadata, plain) = journal(&plan, false);
        let text = String::from_utf8(metadata).unwrap();
        for changed in [
            text.replace(INVOCATION, "different"),
            text.replace(VERIFIER, "/unsealed"),
            text.replace("\"42\"", "\"43\""),
            text.replace("\"done\"", "\"failed\""),
            text.lines().take(1).collect::<String>(),
            text.replace("\"100\"", "\"300\""),
        ] {
            assert!(audit_journal(&plan, changed.as_bytes(), &plain, &state).is_err());
        }
        let (deactivated, _) = journal(&plan, true);
        assert!(audit_journal(&plan, &deactivated, &plain, &state).is_err());
        assert!(audit_journal(&plan, text.as_bytes(), b"different log", &state).is_err());
    }

    #[test]
    fn escapes_are_not_silently_reinterpreted() {
        let mut plan = plan();
        for path in [
            "/private/%i.jet",
            "/private/$VAR.jet",
            "/private/a\".jet",
            "/private/a\\b.jet",
        ] {
            plan.archive.path = path.into();
            assert!(quoted_exec_start(&plan).is_err());
        }
    }

    #[test]
    fn separate_seals_require_exact_destination_digest_and_single_member() {
        let member = Evidence {
            path: "/sealed/verifier".into(),
            sha256: "aa".repeat(32),
        };
        let good = serde_json::json!({"schema":SEAL_RECEIPT_SCHEMA,"destination":"/sealed",
            "members":[{"name":"verifier","sha256":member.sha256}],
            "publication_authorized":false,"replay_launch_authorized":false,"remote_mutations":false,"r2_mutations":false});
        validate_seal_member(&serde_json::to_vec(&good).unwrap(), &member).unwrap();
        for key in [
            "publication_authorized",
            "replay_launch_authorized",
            "remote_mutations",
            "r2_mutations",
        ] {
            let mut bad = good.clone();
            bad[key] = true.into();
            assert!(validate_seal_member(&serde_json::to_vec(&bad).unwrap(), &member).is_err());
        }
        for (key, value) in [
            ("destination", serde_json::json!("/other")),
            ("members", serde_json::json!([])),
            (
                "members",
                serde_json::json!([{"name":"verifier","sha256":"bb".repeat(32)}]),
            ),
            (
                "members",
                serde_json::json!([good["members"][0].clone(), good["members"][0].clone()]),
            ),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(validate_seal_member(&serde_json::to_vec(&bad).unwrap(), &member).is_err());
        }
    }

    #[test]
    fn source_binding_rejects_path_replacement_changed_ctime_and_even_dangling_sidecar() {
        let directory = tempfile::tempdir().unwrap();
        let mut plan = plan();
        plan.archive.path = directory.path().join("epoch-140.jet");
        fs::write(&plan.archive.path, b"original").unwrap();
        let file = File::open(&plan.archive.path).unwrap();
        let metadata = file.metadata().unwrap();
        {
            let profile = plan.transient.as_mut().unwrap();
            profile.source_identity = identity(&metadata);
            profile.source_ctime_seconds = metadata.ctime();
            profile.source_ctime_nanoseconds = metadata.ctime_nsec();
        }
        source_identity(&plan, plan.transient.as_ref().unwrap(), &file).unwrap();
        plan.transient.as_mut().unwrap().source_ctime_nanoseconds += 1;
        assert!(source_identity(&plan, plan.transient.as_ref().unwrap(), &file).is_err());
        plan.transient.as_mut().unwrap().source_ctime_nanoseconds -= 1;
        let sidecar = PathBuf::from(format!("{}.sha256", plan.archive.path.display()));
        std::os::unix::fs::symlink(directory.path().join("absent"), &sidecar).unwrap();
        assert!(source_identity(&plan, plan.transient.as_ref().unwrap(), &file).is_err());
        fs::remove_file(sidecar).unwrap();
        let replacement = directory.path().join("replacement.jet");
        fs::write(&replacement, b"original").unwrap();
        fs::rename(replacement, &plan.archive.path).unwrap();
        assert!(source_identity(&plan, plan.transient.as_ref().unwrap(), &file).is_err());
    }
}
