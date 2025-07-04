use std::path::Path;
use tokio::process::Command;
use anyhow::{Context, Result};
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct PrivilegedHelper;

impl PrivilegedHelper {
    /// Check if the helper is installed and authorized
    pub fn is_installed() -> bool {
        // Check if the helper service is installed and authorized
        let helper_path = "/Library/PrivilegedHelperTools/com.archify.helper";
        let plist_path = "/Library/LaunchDaemons/com.archify.helper.plist";
        
        Path::new(helper_path).exists() && Path::new(plist_path).exists()
    }

    /// Install the privileged helper using SMJobBless
    pub async fn install_helper() -> Result<()> {
        println!("Installing privileged helper...");
        
        // Get the path to the bundled smjobbless_installer tool
        let current_exe = std::env::current_exe()
            .context("Failed to get current executable path")?;
        let app_bundle_path = current_exe
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .context("Failed to find app bundle root")?;
        let installer_path = app_bundle_path
            .join("Contents")
            .join("Library")
            .join("LaunchServices")
            .join("smjobbless_installer");
        
        if !installer_path.exists() {
            return Err(anyhow::anyhow!("smjobbless_installer not found at: {:?}", installer_path));
        }
        
        // Call the installer tool (this will show the system authentication dialog)
        let status = Command::new(installer_path)
            .status()
            .await
            .context("Failed to execute smjobbless_installer")?;
        
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to install privileged helper (see logs for details)"));
        }
        
        println!("Privileged helper installed successfully!");
        Ok(())
    }

    /// Uninstall the privileged helper
    pub async fn uninstall_helper() -> Result<()> {
        println!("Uninstalling privileged helper...");
        // Use sudo to unload and remove the helper and plist
        let status = Command::new("sudo")
            .args(["launchctl", "unload", "/Library/LaunchDaemons/com.archify.helper.plist"])
            .status()
            .await
            .context("Failed to unload helper plist")?;
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to unload helper plist"));
        }
        let status = Command::new("sudo")
            .args(["rm", "-f", "/Library/LaunchDaemons/com.archify.helper.plist"])
            .status()
            .await
            .context("Failed to remove helper plist")?;
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to remove helper plist"));
        }
        let status = Command::new("sudo")
            .args(["rm", "-f", "/Library/PrivilegedHelperTools/com.archify.helper"])
            .status()
            .await
            .context("Failed to remove helper binary")?;
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to remove helper binary"));
        }
        println!("Privileged helper uninstalled successfully!");
        Ok(())
    }

    /// Thin an app using the privileged helper
    pub async fn thin_app(
        app_path: &Path,
        target_arch: &str,
        no_sign: bool,
        _no_entitlements: bool,
        use_codesign: bool,
    ) -> Result<(String, Vec<String>)> {
        if !Self::is_installed() {
            return Err(anyhow::anyhow!("Privileged helper is not installed"));
        }

        // Communicate with the running helper daemon over its UNIX socket
        let socket_path = "/var/run/com.archify.helper.sock";

        let cmd_line = {
            let mut c = String::from("thin ");
            c.push('"');
            c.push_str(&app_path.to_string_lossy().replace('"', "\\\""));
            c.push('"');
            c.push(' ');
            c.push_str(target_arch);
            if no_sign { c.push_str(" --no-sign"); }
            if use_codesign { c.push_str(" --use-codesign"); }
            c.push('\n');
            c
        };

        let mut stream = UnixStream::connect(socket_path)
            .await
            .context("Failed to connect to helper daemon socket")?;

        stream.write_all(cmd_line.as_bytes()).await
            .context("Failed to send command to helper daemon")?;

        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await
            .context("Failed reading reply from helper daemon")?;

        let reply_str = String::from_utf8_lossy(&reply);
        let mut lines = reply_str.lines();
        let status_line = lines.next().unwrap_or("");
        let log_lines: Vec<String> = lines.map(|l| l.to_string()).collect();
        if status_line.starts_with("OK") {
            Ok((status_line.to_string(), log_lines))
        } else {
            Err(anyhow::anyhow!(format!("Helper error: {}", reply_str.trim())))
        }
    }

    /// Get helper status information
    pub fn get_helper_status() -> HelperStatus {
        let is_installed = Self::is_installed();
        
        if !is_installed {
            return HelperStatus {
                is_installed: false,
                is_running: false,
                version: None,
                error: Some("Helper not installed".to_string()),
            };
        }

        // Check if the helper service is running by checking for the socket file
        let socket_path = "/var/run/com.archify.helper.sock";
        let is_running = Path::new(socket_path).exists();

        // Try to get version info
        let version = match std::process::Command::new("/Library/PrivilegedHelperTools/com.archify.helper")
            .arg("--version")
            .output()
        {
            Ok(output) => {
                if output.status.success() {
                    String::from_utf8(output.stdout).ok()
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        HelperStatus {
            is_installed,
            is_running,
            version,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HelperStatus {
    pub is_installed: bool,
    pub is_running: bool,
    pub version: Option<String>,
    pub error: Option<String>,
} 