use std::process::Command;

#[test]
#[expect(
    clippy::expect_used,
    reason = "test fixture setup and subprocess launch must succeed"
)]
fn invalid_instance_type_env_is_rejected_by_clap() {
    let config_dir = tempfile::tempdir().expect("create isolated config directory");
    // If parsing regresses, stop at config loading before credentials, network
    // calls, or a paid CVM can be reached. Exit code 2 proves clap rejected the
    // input; the malformed config would instead produce exit code 1.
    std::fs::write(config_dir.path().join("config.json"), "{invalid config")
        .expect("write malformed config sentinel");

    for command in [&["deploy"][..], &["worker", "add"][..]] {
        let output = Command::new(env!("CARGO_BIN_EXE_gmcli"))
            .args(command)
            .env("GMCLI_CONFIG_DIR", config_dir.path())
            .env("PHALA_INSTANCE_TYPE", "tdx.xlarge")
            .output()
            .expect("run gmcli with an invalid instance type environment variable");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(2), "{command:?}: {stderr}");
        assert!(stderr.contains("tdx.xlarge"), "{stderr}");
        assert!(stderr.contains("tdx.small"), "{stderr}");
        assert!(stderr.contains("tdx.medium"), "{stderr}");
        assert!(
            stderr.contains("registry attests only these sizes"),
            "{stderr}"
        );
    }
}
