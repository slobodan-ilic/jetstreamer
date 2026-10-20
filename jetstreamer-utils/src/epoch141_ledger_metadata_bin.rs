//! Exact-generation, read-only metadata gate for the private epoch141 recovery.
use {
    anyhow::{Context, Result, ensure},
    serde::Deserialize,
    serde_json::{Value, json},
    sha2::{Digest, Sha256},
    std::{
        collections::BTreeMap,
        env,
        fs::{self, File, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
        path::{Path, PathBuf},
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    },
};

const BUCKET: &str = "mainnet-beta-ledger-us-ny5";
const NAME: &str = "60911751/rocksdb.tar.bz2";
const GENERATION: &str = "1634789748052739";
const SIZE: u64 = 189_943_475_031;
const CRC: &str = "6seTSA==";
const MD5: &str = "EAYCyVn1bOWJ0TbSdb/I0g==";
const URI: &str = "gs://mainnet-beta-ledger-us-ny5/60911751/rocksdb.tar.bz2#1634789748052739";
const MAX_METADATA: u64 = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    gcloud_sha256: String,
    output: PathBuf,
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn identity(m: &fs::Metadata) -> (u64, u64, u64, u32, u32, u64, i64, i64, i64, i64) {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.uid(),
        m.mode(),
        m.nlink(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}

fn bound_file(path: &Path, digest: &str, maximum: u64, immutable: bool) -> Result<Vec<u8>> {
    ensure!(is_sha(digest), "invalid supplied SHA-256");
    ensure!(
        path.is_absolute() && path.canonicalize()? == path,
        "noncanonical input path"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let before = input.metadata()?;
    ensure!(
        before.is_file()
            && before.nlink() == 1
            && before.uid() == 0
            && before.mode() & if immutable { 0o222 } else { 0o022 } == 0
            && before.len() <= maximum,
        "unsafe bound input identity"
    );
    let mut bytes = Vec::new();
    (&mut input).take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == before.len() && sha(&bytes) == digest,
        "bound input hash/length mismatch"
    );
    ensure!(
        identity(&before) == identity(&input.metadata()?)
            && identity(&before) == identity(&fs::symlink_metadata(path)?),
        "bound input changed"
    );
    Ok(bytes)
}

fn exact_number(value: &Value, expected: u64) -> bool {
    value.as_u64() == Some(expected) || value.as_str() == Some(expected.to_string().as_str())
}

fn hash_alias(value: &Value, raw: &str, normalized: &str, expected: &str) -> Result<()> {
    let found: Vec<_> = [raw, normalized]
        .into_iter()
        .filter_map(|k| value.get(k))
        .collect();
    ensure!(
        !found.is_empty() && found.iter().all(|v| v.as_str() == Some(expected)),
        "missing or conflicting {normalized}"
    );
    Ok(())
}

fn validate_metadata(value: &Value) -> Result<()> {
    ensure!(
        value.is_object() && value["bucket"] == BUCKET && value["name"] == NAME,
        "wrong ledger object"
    );
    ensure!(
        exact_number(&value["generation"], GENERATION.parse()?)
            && exact_number(&value["size"], SIZE),
        "ledger generation/length mismatch"
    );
    hash_alias(value, "crc32c", "crc32c_hash", CRC)?;
    hash_alias(value, "md5Hash", "md5_hash", MD5)?;
    let id = format!("{BUCKET}/{NAME}/{GENERATION}");
    ensure!(
        value.get("id").is_some() || value.get("storage_url").is_some(),
        "generation identity missing"
    );
    if let Some(actual) = value.get("id") {
        ensure!(actual.as_str() == Some(&id), "raw object identity mismatch");
    }
    if let Some(actual) = value.get("storage_url") {
        ensure!(actual.as_str() == Some(URI), "versioned URL mismatch");
    }
    Ok(())
}

fn capture<R: Read>(mut pipe: R) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    (&mut pipe)
        .take(MAX_METADATA + 1)
        .read_to_end(&mut output)?;
    Ok(output)
}

fn observe_gcloud() -> Result<Vec<u8>> {
    let mut command = Command::new("/usr/lib/google-cloud-sdk/bin/gcloud");
    command
        .args([
            "storage",
            "objects",
            "describe",
            URI,
            "--account=sam.johnson@anza.xyz",
            "--billing-project=principal-lane-200702",
            "--format=json",
            "--quiet",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/home/sol")
        .env("LANG", "C.UTF-8")
        .env("CLOUDSDK_CONFIG", "/home/sol/.config/gcloud")
        .env("CLOUDSDK_CORE_DISABLE_PROMPTS", "1")
        .env("CLOUDSDK_CORE_DISABLE_FILE_LOGGING", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Do not leave root supplementary groups on the unprivileged CLI child.
    unsafe {
        command.pre_exec(|| {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(1003) != 0
                || libc::setuid(1001) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .context("spawn generation-bound metadata lookup")?;
    let stdout = child.stdout.take().context("stdout unavailable")?;
    let stderr = child.stderr.take().context("stderr unavailable")?;
    let out = thread::spawn(move || capture(stdout));
    let err = thread::spawn(move || capture(stderr));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if start.elapsed() >= Duration::from_secs(60) {
            child.kill()?;
            child.wait()?;
            anyhow::bail!("generation-bound metadata lookup timed out");
        }
        thread::sleep(Duration::from_millis(25));
    };
    let output = out
        .join()
        .map_err(|_| anyhow::anyhow!("stdout reader panicked"))??;
    let errors = err
        .join()
        .map_err(|_| anyhow::anyhow!("stderr reader panicked"))??;
    ensure!(
        output.len() as u64 <= MAX_METADATA && errors.len() as u64 <= MAX_METADATA,
        "metadata output bound exceeded"
    );
    // Never forward credential-related CLI stderr, tokens, or login URLs.
    ensure!(
        status.success(),
        "generation-bound metadata lookup failed ({status})"
    );
    Ok(output)
}

fn write_receipt(path: &Path, value: &Value) -> Result<()> {
    ensure!(path.is_absolute(), "output must be absolute");
    let parent = path.parent().context("output parent missing")?;
    ensure!(
        parent.canonicalize()? == parent,
        "noncanonical output parent"
    );
    let m = fs::symlink_metadata(parent)?;
    ensure!(
        m.is_dir() && m.uid() == 0 && m.mode() & 0o077 == 0,
        "output parent must be root-private"
    );
    let directory = File::open(parent)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    output.write_all(&bytes)?;
    output.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

fn run() -> Result<()> {
    ensure!(
        unsafe { libc::geteuid() } == 0,
        "metadata observer must run as root"
    );
    let mut args = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = args.next() {
        ensure!(
            ["--plan", "--plan-sha256", "--self-sha256"].contains(&key.as_str()),
            "unknown option"
        );
        let value = args.next().context("missing option value")?;
        ensure!(values.insert(key, value).is_none(), "duplicate option");
    }
    ensure!(
        values.len() == 3,
        "require --plan, --plan-sha256 and --self-sha256"
    );
    bound_file(
        Path::new("/proc/self/exe").read_link()?.as_path(),
        &values["--self-sha256"],
        64 * 1024 * 1024,
        true,
    )?;
    let bytes = bound_file(
        Path::new(&values["--plan"]),
        &values["--plan-sha256"],
        65536,
        true,
    )?;
    let plan: Plan = serde_json::from_slice(&bytes)?;
    ensure!(
        plan.schema == "jetstreamer-epoch141-ledger-metadata-plan-v1",
        "wrong plan schema"
    );
    let gcloud = Path::new("/usr/lib/google-cloud-sdk/bin/gcloud");
    bound_file(gcloud, &plan.gcloud_sha256, 16 * 1024 * 1024, false)?;
    let invocation = env::var("INVOCATION_ID").context("persistent systemd invocation required")?;
    ensure!(
        invocation.len() == 32
            && invocation
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid invocation ID"
    );
    let metadata = observe_gcloud()?;
    let value: Value = serde_json::from_slice(&metadata)?;
    validate_metadata(&value)?;
    bound_file(gcloud, &plan.gcloud_sha256, 16 * 1024 * 1024, false)?;
    write_receipt(
        &plan.output,
        &json!({
            "schema":"jetstreamer-epoch141-ledger-metadata-receipt-v1","epoch":141,
            "recorded_unix_seconds":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            "invocation_id":invocation,"plan_sha256":values["--plan-sha256"],"self_sha256":values["--self-sha256"],
            "gcloud_sha256":plan.gcloud_sha256,"effective_cloudsdk_config":"/home/sol/.config/gcloud",
        "cli_uid_enforced_before_exec":1001,"cli_gid_enforced_before_exec":1003,
            "metadata":value,"raw_metadata_sha256":sha(&metadata),
            "download_performed":false,"compressed_input_verified":false,"source_completeness_proven":false,
            "resource_admission_proven":false,"replay_launch_authorized":false,"publication_authorized":false,
            "remote_mutations":false,"r2_mutations":false
        }),
    )?;
    println!("epoch141 ledger metadata matched; private no-clobber receipt written");
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
    fn normalized() -> Value {
        json!({"bucket":BUCKET,"name":NAME,"generation":GENERATION,
        "size":SIZE,"crc32c_hash":CRC,"md5_hash":MD5,"storage_url":URI})
    }
    #[test]
    fn exact_normalized_and_raw_metadata_pass() {
        validate_metadata(&normalized()).unwrap();
        let raw = json!({"bucket":BUCKET,"name":NAME,"generation":GENERATION.parse::<u64>().unwrap(),
            "size":SIZE.to_string(),"crc32c":CRC,"md5Hash":MD5,"id":format!("{BUCKET}/{NAME}/{GENERATION}")});
        validate_metadata(&raw).unwrap();
    }
    #[test]
    fn rejects_wrong_generation_length_location_hash_and_alias_conflicts() {
        for (key, value) in [
            ("generation", json!("1634789748052740")),
            ("size", json!(true)),
            ("size", json!(SIZE - 1)),
            ("name", json!("other/rocksdb.tar.bz2")),
            ("bucket", json!("other")),
            ("crc32c_hash", json!("AAAAAA==")),
            ("md5_hash", Value::Null),
            ("md5Hash", json!("AAAAAAAAAAAAAAAAAAAAAA==")),
            ("crc32c", json!("AAAAAA==")),
            ("id", json!("other")),
            ("storage_url", json!(URI.replace('#', "?generation="))),
        ] {
            let mut value2 = normalized();
            value2[key] = value;
            assert!(validate_metadata(&value2).is_err(), "accepted wrong {key}");
        }
    }
    #[test]
    fn refuses_missing_generation_identity_or_hash_evidence() {
        for key in [
            "generation",
            "size",
            "storage_url",
            "crc32c_hash",
            "md5_hash",
        ] {
            let mut value = normalized();
            value.as_object_mut().unwrap().remove(key);
            assert!(validate_metadata(&value).is_err(), "accepted missing {key}");
        }
    }
    #[test]
    fn capture_is_bounded_and_receipt_is_noclobber() {
        assert_eq!(
            capture(std::io::repeat(7)).unwrap().len() as u64,
            MAX_METADATA + 1
        );
        // Root ownership is an operational gate, not bypassed by a user test.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipt.json");
        fs::write(&path, b"preserve").unwrap();
        assert!(write_receipt(&path, &json!({})).is_err());
        assert_eq!(fs::read(path).unwrap(), b"preserve");
    }
}
