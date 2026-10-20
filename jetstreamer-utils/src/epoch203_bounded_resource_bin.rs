//! Separate store8 epoch203 prefix measurement; not a complete-prefix replay.
mod profile {
    pub const EPOCH: u64 = 203;
    pub const TARGET: u64 = 87_720_000;
    pub const TERMINAL: u64 = 88_127_580;
    pub const INITIAL_REPLAY: u64 = 87_695_516;
    pub const MINIMUM_FREE: u64 = 3_185_678_193_366;
    pub const MAX_SCRATCH: u64 = 256 << 30;
    pub const MAX_RUNTIME: u64 = 21600;
    pub const SNAPSHOT_SIZE: u64 = 8_142_103_526;
    pub const PLAN_SCHEMA: &str = "jetstreamer-private-epoch203-bounded-resource-plan-v1";
    pub const RESULT_SCHEMA: &str = "jetstreamer-private-epoch203-bounded-resource-v1";
    pub const STOP_SCHEMA: &str = "jetstreamer-private-epoch203-canary-target-stop-v1";
    pub const UNIT_PREFIX: &str = "horizon-qualify-203-bounded-resource-";
    pub const ROOT_PREFIX: &str = "bounded-resource-203-";
    pub const SNAPSHOT_NAME: &str =
        "snapshot-87695515-CYEr1vEwJyh2d4SSmnmYPYYj6EPhrDWTAJJCuzF2VhLX.tar.zst";
    pub const TERMINAL_NAME: &str =
        "snapshot-88127580-4SeHmKHQrHot4gwifo1bnvDKXZwGELk2vSenotTx9oqf.tar.zst";
    pub const WORKER: &str = "3f5e8efec328b3e00dd9ce5ae396fc4067e6be6554e4da8831a13273186a748a";
    pub const WORKER_ENV: &str = "JETSTREAMER_HISTORICAL_WORKER_V1_6_16";
    pub const SNAPSHOT: &str = "e45584858d0c825f095a43ff5e5909e62a68d197d39c042a76727454525228c4";
}
mod bounded_resource_runner;
fn main() {
    bounded_resource_runner::main();
}
