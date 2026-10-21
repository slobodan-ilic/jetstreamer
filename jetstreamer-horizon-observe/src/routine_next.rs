//! Offline successor preparation for the existing 201–300 routine profile.
//! No subprocesses, environment credentials, resource observation or deployment.
use super::*;
use std::os::unix::fs::DirBuilderExt;

const ROOT: &str = "/var/lib/jetstreamer/horizon-next-preparations-v1";
const OBSERVERS: &str = "/home/ubuntu/workspace/jetstreamer/.codex/tmp-readiness";

fn utc_string(seconds: u64) -> Result<String> {
    let seconds: libc::time_t = seconds.try_into()?;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    ensure!(
        !unsafe { libc::gmtime_r(&seconds, &mut tm) }.is_null(),
        "UTC conversion failed"
    );
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    ))
}

fn completion_bindings(p: &Plan, pb: &Bound, c: &Value) -> Result<()> {
    ensure!(
        !is_101(p)?,
        "successor preparation currently requires explicit201-300profile"
    );
    ensure!(
        c["schema"] == "jetstreamer-horizon-routine-cycle-completion-v1"
            && c["sampled_at_utc"] == p.sample_target_utc
            && c["plan"] == serde_json::to_value(pb)?
            && c["observer"]["path"].as_str() == p.observer.to_str()
            && c["fleet"]["path"].as_str() == p.fleet_output.to_str()
            && c["estimates"]["path"].as_str() == p.estimate_output.to_str()
            && c["model"]["path"].as_str()
                == p.cycle_directory.join("sealed/eta-model.json").to_str()
            && c["fleet_plan"]["path"].as_str()
                == p.cycle_directory.join("sealed/fleet-plan.json").to_str(),
        "completion does not bind exact current cycle"
    );
    for flag in [
        "archive_mutations",
        "sidecar_mutations",
        "replay_launch_authorized",
        "deletions",
    ] {
        ensure!(c[flag] == false, "completion grants mutation: {flag}");
    }
    ensure!(
        c["new_resource_samples"] == 0
            && c["inventory"]["anomalies"] == 0
            && is_sha(c["self_sha256"].as_str().unwrap_or(""))
            && c["invocation_id"].as_str().is_some_and(|s| s.len() == 32
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "not a completed unambiguous metadata owner"
    );
    ensure!(
        c["status_publications"]
            .as_array()
            .is_some_and(|a| a.len() == p.expected_epochs.len()),
        "completion status census differs"
    );
    Ok(())
}

fn derive_next(
    p: &Plan,
    pb: &Bound,
    c: &Value,
    config: &Value,
) -> Result<(Plan, Value, PathBuf, PathBuf)> {
    completion_bindings(p, pb, c)?;
    let old_stamp = stamp(&p.sample_target_utc);
    let generation = p
        .observer
        .file_name()
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix(&format!("horizon-live-resource-sample-{old_stamp}-v")))
        .and_then(|s| s.strip_suffix(".json"))
        .context("noncanonical observer generation")?;
    let n: u32 = generation.parse()?;
    ensure!(
        n > 0
            && n.to_string() == generation
            && p.observer.parent() == Some(Path::new(OBSERVERS))
            && p.observer_config.path
                == Path::new("/var/lib/jetstreamer").join(format!(
                    "horizon-next-observer-{old_stamp}-v{n}/observer.json"
                )),
        "observer config/output generation mismatch"
    );
    ensure!(
        config["schema"] == "jetstreamer-horizon-live-resource-sample-config-v2"
            && config["output"].as_str() == p.observer.to_str()
            && config["not_before_utc"] == p.sample_target_utc
            && config["minimum_interval_seconds"] == 1800
            && config
                .get("observation_reason")
                .is_none_or(|v| v == "routine")
            && config.get("epoch203_ram_auxiliary").is_none(),
        "not an unchanged ordinary routine config"
    );
    let next_time = utc_string(
        utc_seconds(&p.sample_target_utc)?
            .checked_add(1800)
            .context("time overflow")?,
    )?;
    let next_stamp = stamp(&next_time);
    let n = n.checked_add(1).context("generation overflow")?;
    let observer_package =
        Path::new("/var/lib/jetstreamer").join(format!("horizon-next-observer-{next_stamp}-v{n}"));
    let cycle_package =
        Path::new("/var/lib/jetstreamer").join(format!("horizon-routine-plan-{next_stamp}-v1"));
    let mut next_config = config.clone();
    next_config["not_before_utc"] = json!(next_time);
    next_config["previous_sample"] = json!(p.observer);
    next_config["output"] = json!(Path::new(OBSERVERS).join(format!(
        "horizon-live-resource-sample-{next_stamp}-v{n}.json"
    )));
    let observer_sha = sha(&encoded(&next_config)?);
    let mut next: Plan = serde_json::from_value(serde_json::to_value(p)?)?;
    next.sample_target_utc = next_time;
    next.observer = serde_json::from_value(next_config["output"].clone())?;
    next.observer_config = Bound {
        path: observer_package.join("observer.json"),
        sha256: observer_sha,
    };
    next.previous_observer = serde_json::from_value(c["observer"].clone())?;
    next.model_template = serde_json::from_value(c["model"].clone())?;
    next.fleet_template = serde_json::from_value(c["fleet_plan"].clone())?;
    next.previous_estimates = serde_json::from_value(c["estimates"].clone())?;
    next.previous_fleet = serde_json::from_value(c["fleet"].clone())?;
    next.cycle_unit = cycle_unit(&next)?;
    next.cycle_directory = Path::new("/var/lib/jetstreamer/horizon-routine-cycles-v1")
        .join(format!("{next_stamp}-v1"));
    next.estimate_output = p
        .estimate_output
        .parent()
        .context("estimate parent")?
        .join(format!(
            "horizon-r2-status-estimates-{next_stamp}-cohort-gated-v5.json"
        ));
    next.fleet_output = Path::new("/var/lib/jetstreamer/horizon-campaign-fleet")
        .join(format!("{next_stamp}-rust-v1/fleet-ledger.json"));
    Ok((next, next_config, observer_package, cycle_package))
}
fn encoded(value: &Value) -> Result<Vec<u8>> {
    let mut b = serde_json::to_vec_pretty(value)?;
    b.push(b'\n');
    Ok(b)
}
fn seal_plan(stage: &Path, source: &str, destination: &Path, name: &str, digest: &str) -> Value {
    json!({"schema":"jetstreamer-sealed-deployment-plan-v1","destination":destination,
        "members":[{"source":stage.join(source),"name":name,"sha256":digest,"mode":256}]})
}

fn validate_status(s: &Value, p: &Plan, observer: &Bound, estimate: &Value) -> Result<()> {
    ensure!(
        s["schema"] == "jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1"
            && s["bucket"] == p.bucket
            && s["authenticated_readback"] == true
            && s["epoch"] == estimate["epoch"]
            && s["status"]["epoch"] == estimate["epoch"]
            && s["controller_invocation_id"] == estimate["expected_controller_invocation_id"]
            && s["producer_invocation_id"] == estimate["expected_producer_invocation_id"]
            && s["status"]["sampled_at_utc"] == p.sample_target_utc
            && s["status"]["phase"] == "replay"
            && s["status"]["elapsed_execution_millis"] == estimate["elapsed_execution_millis"]
            && s["status"]["estimated_remaining_millis"] == estimate["estimated_remaining_millis"]
            && s["observer_receipt"].as_str() == observer.path.to_str()
            && s["observer_receipt_sha256"] == observer.sha256,
        "status receipt does not reproduce accepted owner/estimate"
    );
    Ok(())
}

pub(super) fn prepare(p: &Plan, pb: &Bound, self_sha: &str) -> Result<()> {
    // No new service/remote observations. Consume only root-private accepted
    // cycle artifacts; the later normal --check-only gate remains mandatory.
    let completion_path = p.cycle_directory.join("completion.json");
    let bytes = read_checked(&completion_path, LIMIT, 0, false)?;
    let completion: Value = serde_json::from_slice(&bytes)?;
    let config = bound_json(&p.observer_config, true)?;
    let (next, next_config, observer_package, cycle_package) =
        derive_next(p, pb, &completion, &config)?;
    let model = bound_json(&next.model_template, true)?;
    let fleet_plan = bound_json(&next.fleet_template, true)?;
    let fleet = bound_json(&next.previous_fleet, false)?;
    let estimates = bound_json(&next.previous_estimates, false)?;
    let observer = bound_json(&next.previous_observer, false)?;
    validate_templates(&next, &model, &fleet_plan, &fleet, &estimates, &observer)?;
    validate_observer_config(&next, &model, &next_config)?;
    let entries = verify_estimates(p, &model, &next.previous_observer, &estimates)?;
    latest_fleet_unchanged(&next, &fleet)?;
    for tool in [&next.tools.sealer, &next.tools.estimator, &next.tools.r2] {
        tool_ok(tool)?;
    }
    for group in next.additional_gate_evidence.values() {
        for b in group {
            bound_json(b, false)?;
        }
    }
    let statuses = completion["status_publications"]
        .as_array()
        .context("status list")?;
    let mut seen = BTreeSet::new();
    for b in statuses {
        let b: Bound = serde_json::from_value(b.clone())?;
        let s = bound_json(&b, false)?;
        let epoch = s["epoch"].as_u64().context("status epoch")?;
        let estimate = entries
            .iter()
            .find(|e| e["epoch"] == epoch)
            .context("status estimate missing")?;
        validate_status(&s, p, &next.previous_observer, estimate)?;
        ensure!(
            next.expected_epochs.contains(&epoch)
                && seen.insert(epoch)
                && s["authenticated_readback"] == true
                && s["status"]["sampled_at_utc"] == p.sample_target_utc
                && s["observer_receipt"].as_str() == next.previous_observer.path.to_str()
                && s["observer_receipt_sha256"] == next.previous_observer.sha256,
            "status receipt is not the accepted observation"
        );
    }
    let stage = Path::new(ROOT).join(format!("{}-v1", stamp(&next.sample_target_utc)));
    private_dir(Path::new(ROOT))?;
    absent(&stage)?;
    fs::DirBuilder::new().mode(0o700).create(&stage)?;
    File::open(ROOT)?.sync_all()?;
    let observer_source = write_new(&stage.join("observer.json"), &next_config)?;
    ensure!(
        observer_source.sha256 == next.observer_config.sha256,
        "observer serialization changed"
    );
    let cycle_source = write_new(
        &stage.join("cycle-plan.json"),
        &serde_json::to_value(&next)?,
    )?;
    let observer_seal = write_new(
        &stage.join("observer-seal-plan.json"),
        &seal_plan(
            &stage,
            "observer.json",
            &observer_package,
            "observer.json",
            &observer_source.sha256,
        ),
    )?;
    let cycle_seal = write_new(
        &stage.join("cycle-seal-plan.json"),
        &seal_plan(
            &stage,
            "cycle-plan.json",
            &cycle_package,
            "cycle-plan.json",
            &cycle_source.sha256,
        ),
    )?;
    let receipt = json!({"schema":"jetstreamer-horizon-routine-next-preparation-v1","self_sha256":self_sha,
        "current_plan":pb,"completion":{"path":completion_path,"sha256":sha(&bytes)},
        "next_sample_target_utc":next.sample_target_utc,"observer_source":observer_source,"cycle_source":cycle_source,
        "observer_seal_plan":observer_seal,"cycle_seal_plan":cycle_seal,
        "observer_destination":observer_package,"cycle_destination":cycle_package,
        "new_resource_samples":0,"service_state_changed":false,"remote_mutations":false,"r2_mutations":false,
        "replay_launch_authorized":false,"deployment_authorized":false,"preflight_required":true});
    let output = write_new(&stage.join("preparation.json"), &receipt)?;
    println!("{}", output.path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (Plan, Bound, Value, Value) {
        let b = || json!({"path":"/evidence","sha256":"a".repeat(64)});
        let p:Plan=serde_json::from_value(json!({"schema":PLAN_SCHEMA,"sample_target_utc":"2026-10-21T07:29:36Z",
            "endpoint_sha256":"a".repeat(64),"bucket":BUCKET,
            "observer":format!("{OBSERVERS}/horizon-live-resource-sample-20261021T072936Z-v204.json"),
            "observer_config":{"path":"/var/lib/jetstreamer/horizon-next-observer-20261021T072936Z-v204/observer.json","sha256":"a".repeat(64)},
            "previous_observer":b(),"model_template":b(),"fleet_template":b(),"previous_estimates":b(),"previous_fleet":b(),
            "tools":{"sealer":b(),"estimator":b(),"r2":b()},"expected_epochs":[216],
            "cycle_directory":"/var/lib/jetstreamer/horizon-routine-cycles-v1/20261021T072936Z-v1",
            "cycle_unit":"horizon-routine-cycle-20261021T072936Z-v1.service",
            "estimate_output":"/estimates/horizon-r2-status-estimates-20261021T072936Z-cohort-gated-v5.json",
            "fleet_output":"/var/lib/jetstreamer/horizon-campaign-fleet/20261021T072936Z-rust-v1/fleet-ledger.json",
            "additional_gate_evidence":{"225":[b()]}})).unwrap();
        let pb = Bound {
            path: "/current-plan.json".into(),
            sha256: "b".repeat(64),
        };
        let c = json!({"schema":"jetstreamer-horizon-routine-cycle-completion-v1","sampled_at_utc":p.sample_target_utc,
            "plan":pb,"observer":{"path":p.observer,"sha256":"c".repeat(64)},
            "model":{"path":p.cycle_directory.join("sealed/eta-model.json"),"sha256":"d".repeat(64)},
            "fleet_plan":{"path":p.cycle_directory.join("sealed/fleet-plan.json"),"sha256":"e".repeat(64)},
            "fleet":{"path":p.fleet_output,"sha256":"f".repeat(64)},
            "estimates":{"path":p.estimate_output,"sha256":"a".repeat(64)},
            "archive_mutations":false,"sidecar_mutations":false,"replay_launch_authorized":false,"deletions":false,
            "new_resource_samples":0,"inventory":{"anomalies":0},"self_sha256":"a".repeat(64),"invocation_id":"b".repeat(32),"status_publications":[b()]});
        let config = json!({"schema":"jetstreamer-horizon-live-resource-sample-config-v2","not_before_utc":p.sample_target_utc,
            "minimum_interval_seconds":1800,"output":p.observer,"previous_sample":"/old-sample",
            "replays":[{"owner":"unchanged"}],"diagnostic_replays":[{"owner":"also-unchanged"}]});
        (p, pb, c, config)
    }
    #[test]
    fn successor_is_exact_thirty_minute_immutable_binding_without_changing_gates() {
        let (p, pb, c, config) = fixture();
        let (next, cfg, op, cp) = derive_next(&p, &pb, &c, &config).unwrap();
        assert_eq!(next.sample_target_utc, "2026-10-21T07:59:36Z");
        assert_eq!(next.previous_observer.sha256, "c".repeat(64));
        assert_eq!(
            serde_json::to_value(next.additional_gate_evidence).unwrap(),
            serde_json::to_value(p.additional_gate_evidence).unwrap()
        );
        assert_eq!(cfg["replays"], config["replays"]);
        assert_eq!(cfg["diagnostic_replays"], config["diagnostic_replays"]);
        assert_eq!(next.observer_config.sha256, sha(&encoded(&cfg).unwrap()));
        assert_eq!(
            op,
            Path::new("/var/lib/jetstreamer/horizon-next-observer-20261021T075936Z-v205")
        );
        assert_eq!(
            cp,
            Path::new("/var/lib/jetstreamer/horizon-routine-plan-20261021T075936Z-v1")
        );
        assert_eq!(
            next.cycle_unit,
            "horizon-routine-cycle-20261021T075936Z-v1.service"
        );
    }
    #[test]
    fn completion_is_not_a_plan_status_countdown_or_foreign_partial_owner() {
        let (p, pb, c, config) = fixture();
        for (field, value) in [
            ("schema", json!("plan")),
            ("sampled_at_utc", json!("2026-10-21T07:59:36Z")),
            ("archive_mutations", json!(true)),
            ("new_resource_samples", json!(1)),
            ("status_publications", json!([])),
            ("invocation_id", json!("")),
        ] {
            let mut wrong = c.clone();
            wrong[field] = value;
            assert!(derive_next(&p, &pb, &wrong, &config).is_err(), "{field}");
        }
        let mut wrong = c.clone();
        wrong["plan"]["sha256"] = json!("f".repeat(64));
        assert!(derive_next(&p, &pb, &wrong, &config).is_err());
        let mut wrong = c;
        wrong["observer"]["path"] = json!("/foreign");
        assert!(derive_next(&p, &pb, &wrong, &config).is_err());
    }
    #[test]
    fn successor_never_borrows_a_different_generation_or_out_of_band_sample() {
        let (mut p, pb, c, config) = fixture();
        for (field, value) in [
            ("observation_reason", json!("user-requested-status")),
            ("minimum_interval_seconds", json!(1799)),
            ("epoch203_ram_auxiliary", json!({"unexpected":"handoff"})),
        ] {
            let mut wrong = config.clone();
            wrong[field] = value;
            assert!(derive_next(&p, &pb, &c, &wrong).is_err(), "{field}");
        }
        p.observer_config.path =
            "/var/lib/jetstreamer/horizon-next-observer-20261021T072936Z-v203/observer.json".into();
        assert!(derive_next(&p, &pb, &c, &config).is_err());
    }
    #[test]
    fn utc_successor_crosses_day_and_month_without_shortening_cadence() {
        let start = utc_seconds("2026-10-31T23:59:36Z").unwrap();
        assert_eq!(utc_string(start + 1800).unwrap(), "2026-11-01T00:29:36Z");
    }

    #[test]
    fn accepted_status_keeps_bucket_owner_clock_and_exact_positive_estimate() {
        let (p, _, _, _) = fixture();
        let observer = Bound {
            path: "/sample".into(),
            sha256: "d".repeat(64),
        };
        let e = json!({"epoch":216,"expected_controller_invocation_id":"a".repeat(32),
            "expected_producer_invocation_id":"b".repeat(32),"elapsed_execution_millis":123,"estimated_remaining_millis":456});
        let s = json!({"schema":"jetstreamer-horizon-r2-status-authenticated-publication-receipt-v1",
            "bucket":p.bucket,"epoch":216,"authenticated_readback":true,
            "controller_invocation_id":e["expected_controller_invocation_id"],"producer_invocation_id":e["expected_producer_invocation_id"],
            "observer_receipt":observer.path,"observer_receipt_sha256":observer.sha256,
            "status":{"epoch":216,"sampled_at_utc":p.sample_target_utc,"phase":"replay",
                "elapsed_execution_millis":123,"estimated_remaining_millis":456}});
        validate_status(&s, &p, &observer, &e).unwrap();
        for field in [
            "bucket",
            "controller_invocation_id",
            "producer_invocation_id",
            "observer_receipt_sha256",
            "authenticated_readback",
        ] {
            let mut wrong = s.clone();
            wrong[field] = json!("changed");
            assert!(
                validate_status(&wrong, &p, &observer, &e).is_err(),
                "{field}"
            );
        }
        for field in [
            "epoch",
            "sampled_at_utc",
            "phase",
            "elapsed_execution_millis",
            "estimated_remaining_millis",
        ] {
            let mut wrong = s.clone();
            wrong["status"][field] = json!("changed");
            assert!(
                validate_status(&wrong, &p, &observer, &e).is_err(),
                "{field}"
            );
        }
    }
}
