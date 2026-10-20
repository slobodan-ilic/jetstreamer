//! Offline, non-authorizing comparison of the exact epoch225 trace and finalized votes.
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
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    },
};

const INVOCATION: &str = "14cf7df9e73b4e459aea0ee2ad896ce2";
const UNIT: &str = "horizon-qualify-225-bounded-resource-trace-9fad80f-v1.service";
const RUNNER: &str = "/var/lib/jetstreamer/horizon-225-bounded-resource-trace-9fad80f-v1/jetstreamer-epoch225-bounded-resource";
const SIGNATURE: &str =
    "5Pe25qKyMTLNYzwTBD4DH1HKPjC9DggvzD9SwvpUQrjgBDapy6PrtxkJRf8F8rrZWe7PjbPFPKpvrWxzKEaWPwUw";
const CANONICAL: &str = "3uMcx4shPW8rToYyXRQgiD9DSzx5qDCv2uFw9NanuWPK";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BoundFile {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    journal: BoundFile,
    request: BoundFile,
    response: BoundFile,
    output: PathBuf,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn read_bound(bound: &BoundFile) -> Result<Vec<u8>> {
    ensure!(
        bound.path.is_absolute() && bound.path.canonicalize()? == bound.path,
        "noncanonical input"
    );
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&bound.path)?;
    let before = file.metadata()?;
    ensure!(
        before.is_file() && before.uid() == 0 && before.nlink() == 1 && before.mode() & 0o222 == 0,
        "input must be immutable root-owned singly linked regular file"
    );
    ensure!(before.len() <= 32 * 1024 * 1024, "oversized input");
    let mut bytes = Vec::new();
    (&mut file)
        .take(32 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let identity = |m: &fs::Metadata| {
        (
            m.dev(),
            m.ino(),
            m.len(),
            m.mtime(),
            m.mtime_nsec(),
            m.uid(),
            m.mode(),
            m.nlink(),
        )
    };
    ensure!(
        identity(&before) == identity(&file.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(&bound.path)?),
        "input changed"
    );
    ensure!(
        bytes.len() as u64 == before.len() && digest(&bytes) == bound.sha256,
        "input digest/length mismatch"
    );
    Ok(bytes)
}

fn hash(value: &str) -> Result<()> {
    ensure!(
        bs58::decode(value)
            .into_vec()
            .map_err(|error| anyhow::anyhow!("invalid base58 hash: {error}"))?
            .len()
            == 32,
        "invalid Bank hash"
    );
    Ok(())
}

fn trace_hashes(journal: &str) -> Result<BTreeMap<u64, String>> {
    let mut traces = Vec::new();
    let mut failure_seen = false;
    for line in journal.lines() {
        let row: Value = serde_json::from_str(line)?;
        ensure!(
            row["_SYSTEMD_INVOCATION_ID"] == INVOCATION
                && row["_SYSTEMD_UNIT"] == UNIT
                && row["_EXE"] == RUNNER
                && row["_UID"] == "1000",
            "foreign journal identity"
        );
        let message = row["MESSAGE"]
            .as_str()
            .context("journal MESSAGE missing; export with --all")?;
        if message.contains(&format!("historical execution mismatch at slot 97199878 entry 165 transaction 189 signature {SIGNATURE}: expected None, got Some(InstructionError {{ instruction_index: 0, error: Custom(2) }})")) {
            failure_seen = true;
        }
        if message.starts_with("historical trace:") {
            traces.push(message.to_owned());
        }
    }
    ensure!(
        failure_seen && traces.len() == 1,
        "exact failure and unique trace required"
    );
    parse_trace(&traces[0])
}

fn parse_trace(message: &str) -> Result<BTreeMap<u64, String>> {
    let rest = message
        .strip_prefix("historical trace: bank_slot=97199878 parent_slot=97199877 parent_hash=Some(")
        .context("wrong trace slot/parent")?;
    let (parent, rest) = rest
        .split_once(") vote=Some(Vote(Vote { slots: [97199877], hash: ")
        .context("wrong trace vote shape")?;
    hash(parent)?;
    let rest = rest
        .strip_prefix(CANONICAL)
        .context("wrong canonical vote hash")?;
    let rest = rest
        .strip_prefix(", timestamp: Some(1632006373) })) slot_hashes=Some(SlotHashes([")
        .context("wrong trace timestamp/SlotHashes")?;
    let entries = rest
        .strip_suffix("]))")
        .context("incomplete SlotHashes trace")?;
    let mut hashes = BTreeMap::new();
    let mut previous = u64::MAX;
    for pair in entries.split("), (") {
        let pair = pair.trim_start_matches('(').trim_end_matches(')');
        let (slot, value) = pair.split_once(", ").context("invalid SlotHashes pair")?;
        let slot: u64 = slot.parse()?;
        hash(value)?;
        ensure!(
            slot < previous && hashes.insert(slot, value.to_owned()).is_none(),
            "unordered/duplicate SlotHashes"
        );
        previous = slot;
    }
    ensure!(
        hashes.len() == 512
            && hashes
                .get(&97199877)
                .is_some_and(|h| h == parent && h != CANONICAL),
        "wrong SlotHashes count/tip or no parent divergence"
    );
    Ok(hashes)
}

fn compare(request: &Value, response: &Value, hashes: &BTreeMap<u64, String>) -> Result<Value> {
    ensure!(
        request["jsonrpc"] == "2.0"
            && request["method"] == "getBlock"
            && request["params"]
                == json!([97199878,{"commitment":"finalized","encoding":"jsonParsed","transactionDetails":"full","rewards":false,"maxSupportedTransactionVersion":0}]),
        "wrong finalized block request"
    );
    ensure!(
        request["id"].as_u64().is_some()
            && response["jsonrpc"] == "2.0"
            && request["id"] == response["id"]
            && response.get("error").is_none(),
        "RPC identity/error"
    );
    let block = &response["result"];
    ensure!(block["parentSlot"] == 97199877, "wrong block parent");
    hash(block["blockhash"].as_str().context("missing blockhash")?)?;
    hash(
        block["previousBlockhash"]
            .as_str()
            .context("missing previous blockhash")?,
    )?;
    let transactions = block["transactions"]
        .as_array()
        .context("missing full transactions")?;
    ensure!(
        transactions.len() > 189 && transactions.len() <= 10000,
        "invalid transaction count"
    );
    let mut prior = Vec::new();
    let mut matching_parent_votes = 0;
    let mut disagreeing_votes = 0;
    let mut exact_failure = false;
    for (index, tx) in transactions.iter().enumerate() {
        ensure!(
            tx["meta"].is_object() && tx["meta"].get("err").is_some(),
            "missing canonical transaction status"
        );
        let instructions = tx["transaction"]["message"]["instructions"]
            .as_array()
            .context("missing instructions")?;
        let signature = tx["transaction"]["signatures"][0]
            .as_str()
            .context("missing transaction signature")?;
        if signature == SIGNATURE {
            ensure!(
                index == 189 && tx["meta"]["err"].is_null(),
                "wrong failure position/status"
            );
        }
        if !tx["meta"]["err"].is_null() {
            continue;
        }
        for instruction in instructions {
            if instruction["program"] != "vote" || instruction["parsed"]["type"] != "vote" {
                continue;
            }
            ensure!(
                instruction["programId"] == "Vote111111111111111111111111111111111111111",
                "wrong vote program"
            );
            let vote = &instruction["parsed"]["info"]["vote"];
            let slots = vote["slots"].as_array().context("missing voted slots")?;
            let slot = slots
                .last()
                .and_then(Value::as_u64)
                .context("invalid vote tip")?;
            ensure!(
                slots.iter().all(|s| s.as_u64().is_some())
                    && slots.windows(2).all(|p| p[0].as_u64() < p[1].as_u64()),
                "invalid vote slot ordering"
            );
            let voted_hash = vote["hash"].as_str().context("missing vote hash")?;
            hash(voted_hash)?;
            let observed = hashes
                .get(&slot)
                .context("vote tip outside captured SlotHashes")?;
            if index < 189 {
                ensure!(
                    observed == voted_hash && slot < 97199877,
                    "earlier successful vote diverges"
                );
                prior.push(json!({"transaction_index":index,"signature":signature,"voted_slot":slot,"voted_hash":voted_hash}));
            }
            if slot == 97199877 {
                ensure!(
                    voted_hash == CANONICAL && observed != voted_hash,
                    "conflicting canonical parent votes"
                );
                matching_parent_votes += 1;
                if signature == SIGNATURE {
                    exact_failure = true;
                }
            }
            if observed != voted_hash {
                ensure!(slot == 97199877, "unexpected older divergent vote");
                disagreeing_votes += 1;
            }
        }
    }
    let predecessor = prior
        .iter()
        .find(|v| v["voted_slot"] == 97199876)
        .context("no matching immediate predecessor vote")?;
    ensure!(
        exact_failure && matching_parent_votes > 0 && disagreeing_votes == matching_parent_votes,
        "failure evidence incomplete"
    );
    Ok(
        json!({"block_slot":97199878,"parent_slot":97199877,"transaction_count":transactions.len(),"prior_successful_votes_all_agree":true,"prior_successful_vote_count":prior.len(),"matching_immediate_predecessor_vote":predecessor,"divergent_slot":97199877,"runtime_bank_hash":hashes[&97199877],"canonical_vote_hash":CANONICAL,"canonical_parent_vote_count":matching_parent_votes,"all_observed_older_vote_tips_agree":true,"scope":"Local divergence bracket only. This does not prove every historical bank, underlying account/freeze cause, or skipped-slot causality.","replay_launch_authorized":false,"runtime_promotion_authorized":false,"publication_authorized":false,"r2_mutations":false}),
    )
}

fn run() -> Result<()> {
    let args: Vec<_> = env::args().collect();
    ensure!(
        args.len() == 6 && args[2] == "--plan-sha256" && args[4] == "--self-sha256",
        "usage: audit PLAN --plan-sha256 HEX --self-sha256 HEX"
    );
    ensure!(unsafe { libc::geteuid() } == 0, "root required");
    ensure!(
        digest(&fs::read("/proc/self/exe")?) == args[5],
        "self digest mismatch"
    );
    let plan: Plan = serde_json::from_slice(&read_bound(&BoundFile {
        path: args[1].clone().into(),
        sha256: args[3].clone(),
    })?)?;
    ensure!(
        plan.schema == "jetstreamer-private-epoch225-vote-audit-plan-v1",
        "wrong plan schema"
    );
    let journal = read_bound(&plan.journal)?;
    let hashes = trace_hashes(std::str::from_utf8(&journal)?)?;
    let request: Value = serde_json::from_slice(&read_bound(&plan.request)?)?;
    let response: Value = serde_json::from_slice(&read_bound(&plan.response)?)?;
    let audit = compare(&request, &response, &hashes)?;
    let parent = plan.output.parent().context("missing output parent")?;
    ensure!(
        plan.output.is_absolute() && parent.canonicalize()? == parent,
        "noncanonical output"
    );
    let meta = fs::symlink_metadata(parent)?;
    ensure!(
        meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o077 == 0,
        "private root output directory required"
    );
    let report = json!({"schema":"jetstreamer-private-epoch225-vote-audit-v1","plan_sha256":args[3],"auditor_sha256":args[5],"journal":plan.journal,"request":plan.request,"response":plan.response,"audit":audit});
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&plan.output)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    File::open(parent)?.sync_all()?;
    println!("{}", plan.output.display());
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
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[test]
    fn bound_input_requires_owner_immutability_digest_and_real_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.json");
        fs::write(&path, b"evidence").unwrap();
        let mut bound = BoundFile {
            path: path.clone(),
            sha256: digest(b"evidence"),
        };
        assert!(read_bound(&bound).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(read_bound(&bound).unwrap(), b"evidence");
        } else {
            assert!(read_bound(&bound).is_err());
        }
        bound.sha256 = digest(b"other");
        assert!(read_bound(&bound).is_err());
        let alias = directory.path().join("alias.json");
        symlink(&path, &alias).unwrap();
        bound.path = alias;
        bound.sha256 = digest(b"evidence");
        assert!(read_bound(&bound).is_err());
    }

    fn trace() -> String {
        let h = "G6BFd1oz8QNkVMdPsrqkJBEF8UBpeGsbfWEEdP4ysJiJ";
        let entries = (0..512)
            .map(|n| format!("({}, {h})", 97199877 - n))
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "historical trace: bank_slot=97199878 parent_slot=97199877 parent_hash=Some({h}) vote=Some(Vote(Vote {{ slots: [97199877], hash: {CANONICAL}, timestamp: Some(1632006373) }})) slot_hashes=Some(SlotHashes([{entries}]))"
        )
    }

    #[test]
    fn accepts_complete_exact_trace() {
        assert_eq!(parse_trace(&trace()).unwrap().len(), 512);
    }

    #[test]
    fn rejects_wrong_vote_parent_truncation_and_duplicates() {
        for bad in [
            trace().replace("parent_slot=97199877", "parent_slot=97199876"),
            trace().replace(CANONICAL, "11111111111111111111111111111111"),
            trace().replace("(97199876,", "(97199877,"),
            trace().trim_end_matches(')').to_owned(),
        ] {
            assert!(parse_trace(&bad).is_err());
        }
    }

    fn request() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"getBlock","params":[97199878,{"commitment":"finalized","encoding":"jsonParsed","transactionDetails":"full","rewards":false,"maxSupportedTransactionVersion":0}]})
    }

    fn response() -> Value {
        let vote = |slot: u64, h: &str| json!({"program":"vote","programId":"Vote111111111111111111111111111111111111111","parsed":{"type":"vote","info":{"vote":{"slots":[slot],"hash":h}}}});
        let tx = |signature: &str, instructions: Value| json!({"meta":{"err":null},"transaction":{"signatures":[signature],"message":{"instructions":instructions}}});
        let mut txs = vec![tx("unrelated", json!([])); 190];
        txs[0] = tx(
            "prior",
            json!([vote(
                97199876,
                "G6BFd1oz8QNkVMdPsrqkJBEF8UBpeGsbfWEEdP4ysJiJ"
            )]),
        );
        txs[189] = tx(SIGNATURE, json!([vote(97199877, CANONICAL)]));
        json!({"jsonrpc":"2.0","id":1,"result":{"parentSlot":97199877,"blockhash":CANONICAL,"previousBlockhash":CANONICAL,"transactions":txs}})
    }

    #[test]
    fn binds_predecessor_and_exact_failure() {
        let result = compare(&request(), &response(), &parse_trace(&trace()).unwrap()).unwrap();
        assert_eq!(result["prior_successful_vote_count"], 1);
        assert_eq!(result["divergent_slot"], 97199877);
        assert_eq!(result["publication_authorized"], false);
    }

    #[test]
    fn rejects_unfinalized_or_wrong_rpc_response() {
        let hashes = parse_trace(&trace()).unwrap();
        let mut req = request();
        req["params"][1]["commitment"] = json!("confirmed");
        assert!(compare(&req, &response(), &hashes).is_err());
        let mut res = response();
        res["id"] = json!(2);
        assert!(compare(&request(), &res, &hashes).is_err());
    }

    #[test]
    fn rejects_earlier_divergence_missing_status_and_false_failure() {
        let hashes = parse_trace(&trace()).unwrap();
        for path in [0, 1, 2] {
            let mut res = response();
            match path {
                0 => {
                    res["result"]["transactions"][0]["transaction"]["message"]["instructions"][0]
                        ["parsed"]["info"]["vote"]["hash"] = json!(CANONICAL)
                }
                1 => {
                    res["result"]["transactions"][0]["meta"]
                        .as_object_mut()
                        .unwrap()
                        .remove("err");
                }
                _ => res["result"]["transactions"][189]["meta"]["err"] = json!("failed"),
            }
            assert!(compare(&request(), &res, &hashes).is_err());
        }
    }

    #[test]
    fn rejects_foreign_or_null_journal_fields() {
        assert!(
            trace_hashes(
                &json!({"MESSAGE":trace(),"_SYSTEMD_INVOCATION_ID":"foreign"}).to_string()
            )
            .is_err()
        );
        assert!(trace_hashes(&json!({"MESSAGE":null,"_SYSTEMD_INVOCATION_ID":INVOCATION,"_SYSTEMD_UNIT":UNIT,"_EXE":RUNNER,"_UID":"1000"}).to_string()).is_err());
    }
}
