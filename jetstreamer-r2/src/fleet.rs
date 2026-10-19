//! Read-only campaign reconciliation. The plan describes gates, never completion.
use super::*;
use serde_json::json;
use std::{collections::BTreeMap, process::Command as ProcessCommand};

const SCHEMA: &str = "jetstreamer-horizon-campaign-fleet-v1";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    state: String,
    next_action: String,
    evidence: Vec<BoundFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    first_epoch: u64,
    last_epoch: u64,
    observer: BoundFile,
    previous_fleet: Option<BoundFile>,
    output: PathBuf,
    status_receipt_directory: PathBuf,
    gates: BTreeMap<u64, Gate>,
    // Include terminal and quarantined controllers, not just observer entries.
    tracked_units: Vec<String>,
}

fn bound_json(bound: &BoundFile) -> Result<Value> {
    ensure!(bound.path.is_absolute(), "evidence path must be absolute");
    let bytes = read_stable_bounded(&bound.path, 16 * 1024 * 1024, "fleet evidence")?;
    ensure!(
        hex_lower(&Sha256::digest(&bytes)) == bound.sha256,
        "fleet evidence digest mismatch: {}",
        bound.path.display()
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn utc_seconds(value: &str) -> Result<u64> {
    ensure!(
        is_canonical_utc(value),
        "invalid fleet sample UTC timestamp"
    );
    let number = |start, end| value[start..end].parse::<i32>();
    let mut time: libc::tm = unsafe { std::mem::zeroed() };
    time.tm_year = number(0, 4)? - 1900;
    time.tm_mon = number(5, 7)? - 1;
    time.tm_mday = number(8, 10)?;
    time.tm_hour = number(11, 13)?;
    time.tm_min = number(14, 16)?;
    time.tm_sec = number(17, 19)?;
    let fields = (
        time.tm_year,
        time.tm_mon,
        time.tm_mday,
        time.tm_hour,
        time.tm_min,
        time.tm_sec,
    );
    let seconds = unsafe { libc::timegm(&mut time) };
    ensure!(
        fields
            == (
                time.tm_year,
                time.tm_mon,
                time.tm_mday,
                time.tm_hour,
                time.tm_min,
                time.tm_sec
            ),
        "nonexistent sample date"
    );
    Ok(u64::try_from(seconds)?)
}

fn unit(name: &str) -> Result<Value> {
    ensure!(
        name.ends_with(".service")
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.@".contains(&b)),
        "invalid fleet unit name"
    );
    let result = ProcessCommand::new("systemctl").args([
        "show", name, "--no-pager", "--property=Id,LoadState,ActiveState,SubState,InvocationID,NRestarts,Result,ExecMainStatus,ExecStart,ControlGroup",
    ]).output()?;
    let mut values = serde_json::Map::new();
    for line in std::str::from_utf8(&result.stdout)?.lines() {
        let (key, value) = line
            .split_once('=')
            .context("malformed systemctl property")?;
        ensure!(
            values
                .insert(key.into(), Value::String(value.into()))
                .is_none(),
            "duplicate unit property"
        );
    }
    ensure!(
        values.get("Id").and_then(Value::as_str) == Some(name),
        "unit identity mismatch"
    );
    ensure!(
        result.status.success()
            || (values.get("LoadState").and_then(Value::as_str) == Some("not-found")
                && values.get("ActiveState").and_then(Value::as_str) == Some("inactive")
                && values.get("SubState").and_then(Value::as_str) == Some("dead")),
        "fleet unit observation failed for {name}"
    );
    Ok(Value::Object(values))
}

fn census(names: &BTreeSet<String>) -> Result<BTreeMap<String, Value>> {
    let mut result = BTreeMap::new();
    for name in names {
        result.insert(name.clone(), unit(name)?);
    }
    // A newly launched producer outside the observer census invalidates the cycle.
    let units = ProcessCommand::new("systemctl")
        .args([
            "list-units",
            "--type=service",
            "--state=running",
            "--output=json",
            "--no-pager",
        ])
        .output()?;
    ensure!(units.status.success(), "fleet discovery failed");
    let discovered: Vec<Value> = serde_json::from_slice(&units.stdout)?;
    for value in discovered {
        let name = value["unit"]
            .as_str()
            .context("discovered unit omits name")?;
        if name.starts_with("jetstreamer-root-sweep-") || name.starts_with("horizon-qualify-") {
            ensure!(
                names.contains(name),
                "unbound live producer {name}; rebuild fleet plan and observer census"
            );
        }
    }
    Ok(result)
}

fn live_binding(observed: &Value, current: &Value) -> bool {
    current["ActiveState"] == "active"
        && current["SubState"] == "running"
        && current["NRestarts"] == "0"
        && observed["invocation_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty() && current["InvocationID"] == id)
        && observed["restarts"] == 0
}

fn status_matches(
    status: &EpochStatus,
    etag: &str,
    publication: &StatusPublicationReceipt,
    controller: &Value,
    producer: &Value,
) -> bool {
    publication.status == *status
        && publication.object_etag == etag
        && publication.authenticated_readback
        && controller["InvocationID"] == publication.controller_invocation_id
        && producer["InvocationID"] == publication.producer_invocation_id
        && controller["ActiveState"] == "active"
        && producer["ActiveState"] == "active"
        && controller["NRestarts"] == "0"
        && producer["NRestarts"] == "0"
}

fn persist(path: &Path, value: &Value) -> Result<()> {
    ensure!(path.is_absolute(), "fleet output must be absolute");
    let parent = path.parent().context("fleet output has no parent")?;
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "fleet output directory must be root-owned and owner-only"
    );
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer_pretty(temporary.as_file_mut(), value)?;
    temporary.as_file_mut().write_all(b"\n")?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| anyhow!("fleet output publication failed: {error}"))?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn validate_previous_fleet(previous: &Value, first: u64, last: u64, sample: &str) -> Result<()> {
    ensure!(
        previous["schema"] == SCHEMA,
        "invalid previous fleet schema"
    );
    // The original sealed ledgers used an explicit assignment object. Preserve
    // their exact digest as the predecessor; never rewrite them into a new shape.
    let (old_first, old_last, old_sample) = if previous.get("assigned_range").is_some() {
        ensure!(
            previous.get("first_epoch").is_none()
                && previous.get("last_epoch").is_none()
                && previous.get("sampled_at_utc").is_none(),
            "ambiguous previous fleet shape"
        );
        (
            previous["assigned_range"]["first_epoch"].as_u64(),
            previous["assigned_range"]["last_epoch"].as_u64(),
            previous["production_observation_sampled_at_utc"].as_str(),
        )
    } else {
        (
            previous["first_epoch"].as_u64(),
            previous["last_epoch"].as_u64(),
            previous["sampled_at_utc"].as_str(),
        )
    };
    ensure!(
        old_first == Some(first) && old_last == Some(last),
        "previous fleet has different assignment"
    );
    let old_sample = old_sample.context("previous fleet omits sample timestamp")?;
    ensure!(
        utc_seconds(old_sample)? < utc_seconds(sample)?,
        "fleet sample must advance"
    );
    Ok(())
}

pub(super) async fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 5 && args[3] == "--plan-sha256",
        "usage: jetstreamer-r2 fleet-reconcile PLAN --plan-sha256 HEX"
    );
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "fleet reconciliation requires root"
    );
    let plan_bound = BoundFile {
        path: args[2].clone().into(),
        sha256: args[4].clone(),
    };
    let plan_metadata = fs::symlink_metadata(&plan_bound.path)?;
    ensure!(
        plan_metadata.is_file() && plan_metadata.uid() == 0 && plan_metadata.mode() & 0o022 == 0,
        "fleet plan must be a root-owned non-writable regular file"
    );
    let plan: Plan = serde_json::from_value(bound_json(&plan_bound)?)?;
    ensure!(
        plan.schema == "jetstreamer-horizon-campaign-fleet-plan-v1",
        "unsupported fleet plan"
    );
    ensure!(
        plan.first_epoch <= plan.last_epoch && plan.last_epoch - plan.first_epoch <= 1000,
        "invalid campaign range"
    );
    ensure!(
        plan.gates
            .keys()
            .copied()
            .eq(plan.first_epoch..=plan.last_epoch),
        "fleet gates must cover every assigned epoch exactly"
    );
    for gate in plan.gates.values() {
        ensure!(
            matches!(
                gate.state.as_str(),
                "post-replay-pipeline"
                    | "staged-admissible"
                    | "blocked-qualification"
                    | "failed-needs-repair"
                    | "not-yet-staged"
            ),
            "gate cannot declare remote or replay completion"
        );
        ensure!(
            !gate.next_action.trim().is_empty(),
            "gate requires next action"
        );
        ensure!(
            gate.state == "not-yet-staged" || !gate.evidence.is_empty(),
            "gate requires bound evidence"
        );
        for bound in &gate.evidence {
            bound_json(bound)?;
        }
    }
    let observer = bound_json(&plan.observer)?;
    let observer_bytes = read_stable_bounded(
        &plan.observer.path,
        MAX_OBSERVER_RECEIPT_BYTES,
        "fleet observer",
    )?;
    ensure!(
        hex_lower(&Sha256::digest(&observer_bytes)) == plan.observer.sha256,
        "observer changed after validation"
    );
    ensure!(
        observer["schema"] == "jetstreamer-horizon-live-resource-sample-v2",
        "fleet requires v2 observer"
    );
    let sample = observer["recorded_at_utc"]
        .as_str()
        .context("missing sample timestamp")?;
    ensure!(
        is_canonical_utc(sample),
        "invalid observer sample timestamp"
    );
    let sample_seconds = utc_seconds(sample)?;
    let started_seconds = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    ensure!(
        sample_seconds <= started_seconds && started_seconds - sample_seconds <= 1800,
        "fleet requires an observer sample no older than 30 minutes"
    );
    if let Some(previous) = &plan.previous_fleet {
        let previous = bound_json(previous)?;
        validate_previous_fleet(&previous, plan.first_epoch, plan.last_epoch, sample)?;
    }
    let replays = observer["replays"]
        .as_array()
        .context("observer replays missing")?;
    let mut names: BTreeSet<_> = plan.tracked_units.iter().cloned().collect();
    for replay in replays {
        for kind in ["controller_after", "producer_after"] {
            names.insert(observer_string(replay, &[kind, "unit"])?.into());
        }
    }
    let before = census(&names)?;
    let r2 = r2_config_from_env()?;
    let s3 = s3_client(&r2);
    let mut entries = Vec::new();
    let mut active = Vec::new();
    let mut remote_entries = Vec::new();
    for epoch in plan.first_epoch..=plan.last_epoch {
        let remote = inventory_epoch(&s3, &r2, epoch).await?;
        ensure!(
            !matches!(
                remote.state,
                InventoryState::SidecarOnly
                    | InventoryState::InvalidSidecar
                    | InventoryState::MetadataMismatch
            ),
            "epoch {epoch}: R2 pair anomaly"
        );
        let gate = &plan.gates[&epoch];
        let mut state = gate.state.as_str();
        let mut next = gate.next_action.as_str();
        let mut live = None;
        for replay in replays {
            let range = parse_observer_claim_range(observer_string(replay, &["range"])?)?;
            if !range.contains(&epoch) {
                continue;
            }
            ensure!(
                live.is_none(),
                "overlapping observer claims for epoch {epoch}"
            );
            let controller = &before[observer_string(replay, &["controller_after", "unit"])?];
            let producer = &before[observer_string(replay, &["producer_after", "unit"])?];
            ensure!(
                live_binding(&replay["controller_after"], controller)
                    && live_binding(&replay["producer_after"], producer),
                "epoch {epoch}: observer invocation is no longer live"
            );
            validate_observer_binding(
                &observer_bytes,
                &plan.observer.sha256,
                epoch,
                observer_string(replay, &["controller_after", "invocation_id"])?,
                observer_string(replay, &["producer_after", "invocation_id"])?,
            )?;
            live = Some((controller, producer));
            if gate.state != "blocked-qualification" {
                state = "live-replay";
                next = "Complete replay and canonical checkpoint, then import and dispatch receipt-gated verification";
            }
            active.push(json!({"epoch":epoch,"phase":if gate.state == "blocked-qualification" {"qualification"} else {"replay"},"controller":controller,"producer":producer,"scratch_path":replay["scratch_path"],"useful_work":replay["useful_work"],"sampled_at_utc":sample}));
        }
        if remote.state == InventoryState::ReadyPair {
            state = "remote-ready";
            next = "Preserve ready pair; perform only receipt- and boundary-gated local retirement or status cleanup";
        }
        let key = format!("epoch-{epoch}.epoch-status.json");
        let status = if let Some(object) = get_mutable_object(&s3, &r2.bucket, &key).await? {
            let status: EpochStatus = serde_json::from_slice(&object.bytes)?;
            validate_epoch_status(&status, epoch)?;
            let publication = latest_status_publication_receipt(
                &plan.status_receipt_directory,
                &r2.bucket,
                epoch,
            );
            // Missing local publication history is explicitly unbound, never current.
            let matches = live.is_some_and(|(controller, producer)| {
                publication.as_ref().is_ok_and(|(receipt, _, _)| {
                    status_matches(&status, &object.etag, receipt, controller, producer)
                })
            });
            json!({"key":key,"etag":object.etag,"payload":status,"sha256":hex_lower(&Sha256::digest(&object.bytes)),"classification":if matches {"bound-live-status"} else {"stale-or-orphaned"},"sample_matches_observer":status.sampled_at_utc == sample,"current_eta_valid":matches && status.sampled_at_utc == sample && state != "remote-ready"})
        } else {
            Value::Null
        };
        entries.push(json!({"epoch":epoch,"state":state,"next_action":next,"status":status,"gate_evidence":gate.evidence.iter().map(|e|json!({"path":e.path,"sha256":e.sha256})).collect::<Vec<_>>()}));
        remote_entries.push(remote);
    }
    let after = census(&names)?;
    ensure!(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() - sample_seconds <= 1800,
        "observer became stale during fleet reconciliation"
    );
    ensure!(
        before == after,
        "fleet unit identities or commands changed during reconciliation"
    );
    let inventory = inventory_report(remote_entries);
    let receipt = json!({"schema":SCHEMA,"first_epoch":plan.first_epoch,"last_epoch":plan.last_epoch,"sampled_at_utc":sample,"observer_receipt":plan.observer.path,"observer_sha256":plan.observer.sha256,"previous_fleet":plan.previous_fleet.as_ref().map(|p|json!({"path":p.path,"sha256":p.sha256})),"plan":plan_bound.path,"plan_sha256":plan_bound.sha256,"inventory":inventory,"unit_census":after,"active":active,"epochs":entries,"recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),"remote_mutations":false,"producer_mutations":false,"publication_authorized":false});
    persist(&plan.output, &receipt)?;
    println!("{}", plan.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn predecessor_migration_preserves_assignment_and_monotonic_sample() {
        let sample = "2026-10-19T14:34:42Z";
        let mut previous = json!({"schema":SCHEMA,"assigned_range":{"first_epoch":201,"last_epoch":300},"production_observation_sampled_at_utc":"2026-10-19T14:04:42Z"});
        validate_previous_fleet(&previous, 201, 300, sample).unwrap();
        assert!(validate_previous_fleet(&previous, 200, 300, sample).is_err());
        assert!(validate_previous_fleet(&previous, 201, 300, "2026-10-19T14:04:42Z").is_err());
        previous["first_epoch"] = json!(201);
        assert!(validate_previous_fleet(&previous, 201, 300, sample).is_err());
        previous = json!({"schema":SCHEMA,"first_epoch":201,"last_epoch":300,"sampled_at_utc":"2026-10-19T14:04:42Z"});
        validate_previous_fleet(&previous, 201, 300, sample).unwrap();
        previous["sampled_at_utc"] = json!("2026-02-30T00:00:00Z");
        assert!(validate_previous_fleet(&previous, 201, 300, sample).is_err());
    }
    #[test]
    fn stale_or_replaced_status_never_matches_a_live_claim() {
        let status = EpochStatus {
            epoch: 198,
            jet_size_bytes: 0,
            elapsed_execution_millis: 1,
            estimated_remaining_millis: 2,
            sampled_at_utc: "2026-10-19T14:07:00Z".into(),
            phase: "replay".into(),
        };
        let mut publication = StatusPublicationReceipt {
            schema: STATUS_RECEIPT_SCHEMA.into(),
            bucket: "test".into(),
            epoch: 198,
            key: "epoch-198.epoch-status.json".into(),
            status: status.clone(),
            object_etag: "etag".into(),
            previous_object_etag: None,
            observer_receipt: "/private/observer.json".into(),
            observer_receipt_sha256: "0".repeat(64),
            controller_invocation_id: "controller".into(),
            producer_invocation_id: "producer".into(),
            authenticated_readback: true,
            verified_unix_seconds: 0,
        };
        let controller =
            json!({"InvocationID":"controller","ActiveState":"active","NRestarts":"0"});
        let mut producer =
            json!({"InvocationID":"producer","ActiveState":"active","NRestarts":"0"});
        assert!(status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
        assert!(!status_matches(
            &status,
            "new-etag",
            &publication,
            &controller,
            &producer
        ));
        producer["ActiveState"] = json!("inactive");
        assert!(!status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
        producer["ActiveState"] = json!("active");
        producer["InvocationID"] = json!("replacement");
        assert!(!status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
        producer["InvocationID"] = json!("producer");
        publication.status.estimated_remaining_millis += 1;
        assert!(!status_matches(
            &status,
            "etag",
            &publication,
            &controller,
            &producer
        ));
    }
    #[test]
    fn rejects_stale_date_shapes_and_handles_utc_epoch() {
        assert_eq!(utc_seconds("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(utc_seconds("1970-01-01T00:30:00Z").unwrap(), 1800);
        assert!(utc_seconds("2026-02-30T00:00:00Z").is_err());
        assert!(utc_seconds("2026-01-01T24:00:00Z").is_err());
        assert!(utc_seconds("2026-01-01T00:00:00").is_err());
    }
    #[test]
    fn stopped_or_restarted_invocations_are_not_live() {
        let observed = json!({"invocation_id":"abc","restarts":0});
        let mut current = json!({"InvocationID":"abc","NRestarts":"0","ActiveState":"active","SubState":"running"});
        assert!(live_binding(&observed, &current));
        for (field, value) in [
            ("InvocationID", "other"),
            ("NRestarts", "1"),
            ("ActiveState", "inactive"),
            ("SubState", "dead"),
        ] {
            let saved = current[field].clone();
            current[field] = json!(value);
            assert!(!live_binding(&observed, &current));
            current[field] = saved;
        }
    }
    #[test]
    fn fleet_receipt_is_private_and_no_clobber() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("fleet.json");
        persist(&path, &json!({"test":1})).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o077, 0);
        assert!(persist(&path, &json!({"test":2})).is_err());
    }
}
