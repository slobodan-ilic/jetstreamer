//! Keep isolated node modes covered when adding a new compile-time route.
use std::collections::BTreeSet;

#[test]
fn ci_covers_every_declared_node_mode_independently() {
    let manifest = include_str!("../Cargo.toml");
    let features = manifest
        .split_once("[features]\n")
        .expect("node feature table")
        .1
        .split("\n[")
        .next()
        .unwrap();
    let declared: BTreeSet<_> = features
        .lines()
        .filter_map(|line| line.split('#').next()?.split_once('='))
        .map(|(key, _)| key.trim())
        .filter(|key| *key != "default")
        .collect();
    assert!(!declared.is_empty());

    let workflow = include_str!("../../.github/workflows/rust.yaml");
    let matrix = workflow
        .split_once("matrix: &rust-feature-matrix\n")
        .expect("shared Rust matrix")
        .1
        .split_once("    steps:")
        .expect("end of shared matrix")
        .0;
    let covered: BTreeSet<_> = matrix
        .lines()
        .filter_map(|line| line.trim().strip_prefix("flags: \"--features "))
        .map(|line| line.strip_suffix('"').expect("quoted feature flag"))
        .collect();
    assert_eq!(
        declared, covered,
        "every node feature needs an isolated CI job"
    );
    for feature in declared {
        assert_eq!(
            matrix
                .matches(&format!("flags: \"--features {feature}\""))
                .count(),
            1,
            "feature must have exactly one isolated entry: {feature}"
        );
    }
    assert!(matrix.contains("scope: \"--workspace\"\n            flags: \"\""));
    assert!(matrix.contains(
        "scope: \"--workspace --exclude jetstreamer-node\"\n            flags: \"--all-features\""
    ));
    assert_eq!(workflow.matches("matrix: *rust-feature-matrix").count(), 2);
    assert_eq!(
        workflow
            .matches("${{ matrix.scope }} ${{ matrix.flags }}")
            .count(),
        3,
        "check, test and clippy must consume the same feature matrix"
    );
    assert!(workflow.contains("if: matrix.examples"));
    assert!(workflow.contains("--example reencode_archive"));
    assert!(workflow.contains("--example verify_archive"));
    assert!(workflow.contains("shell: bash\n        run: cargo test"));
    assert!(workflow.contains("2>&1 | tee \"$RUNNER_TEMP/rust-test.log\""));
    assert!(
        workflow.contains("name: Report test failure in check annotations\n        if: failure()")
    );
    assert!(workflow.contains("::error title=Rust test failure details::%s"));
}
