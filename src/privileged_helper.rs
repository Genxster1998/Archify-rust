use std::path::PathBuf;
use tokio::process::Command;
use anyhow::{Context, Result};

pub struct PrivilegedHelper;

impl PrivilegedHelper {
    /// Thin multiple apps in a single elevated session using osascript
    pub async fn thin_apps(
        app_paths: &[PathBuf],
        target_arch: &str,
        no_sign: bool,
        _no_entitlements: bool,
        use_codesign: bool,
    ) -> Result<(String, Vec<String>)> {
        let current_exe = std::env::current_exe().context("Failed to get current executable path")?;
        let helper_path = current_exe.parent().unwrap().join("helper");
        
        if !helper_path.exists() {
            return Err(anyhow::anyhow!("Helper binary not found at {:?}", helper_path));
        }

        let helper_str = helper_path.to_string_lossy().replace("'", "'\\''");
        let mut commands = Vec::new();

        for app_path in app_paths {
            let app_str = app_path.to_string_lossy().replace("'", "'\\''");
            let mut cmd = format!("'{}' thin '{}' {}", helper_str, app_str, target_arch);
            if no_sign {
                cmd.push_str(" --no-sign");
            }
            if use_codesign {
                cmd.push_str(" --use-codesign");
            }
            commands.push(cmd);
        }

        // Run all commands sequentially, separating them with semicolons
        // so that they all execute even if one fails.
        // Wrap everything in a subshell and redirect stderr to stdout to capture all outputs.
        let shell_command = format!("( {} ) 2>&1", commands.join(" ; "));

        let script = format!(
            "do shell script \"{}\" with administrator privileges",
            shell_command.replace("\"", "\\\"")
        );

        let output = Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .output()
            .await
            .context("Failed to execute osascript")?;

        let output_str = String::from_utf8_lossy(&output.stdout).replace("\r", "\n");
        let error_str = String::from_utf8_lossy(&output.stderr).replace("\r", "\n");

        if !output.status.success() {
            return Err(anyhow::anyhow!("Elevated operation failed: {}\n{}", error_str.trim(), output_str.trim()));
        }

        let lines = output_str.lines();
        let log_lines: Vec<String> = lines.map(|l| l.to_string()).collect();
        
        Ok(("OK".to_string(), log_lines))
    }
}