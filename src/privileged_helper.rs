use std::path::Path;
use tokio::process::Command;
use anyhow::{Context, Result};

pub struct PrivilegedHelper;

impl PrivilegedHelper {
    /// Thin an app using the privileged helper via osascript
    pub async fn thin_app(
        app_path: &Path,
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

        let mut cmd_args = vec![
            "thin".to_string(),
            format!("'{}'", app_path.to_string_lossy().replace("'", "'\\''")),
            target_arch.to_string(),
        ];
        if no_sign {
            cmd_args.push("--no-sign".to_string());
        }
        if use_codesign {
            cmd_args.push("--use-codesign".to_string());
        }

        let script = format!(
            "do shell script \"'{}' {} 2>&1\" with administrator privileges",
            helper_path.to_string_lossy().replace("'", "'\\''"),
            cmd_args.join(" ")
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