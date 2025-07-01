use anyhow::{Context, Result};
use std::path::PathBuf;
use tokio::process::Command;

pub struct Helper;

impl Helper {
    /// Check if ldid is available
    pub async fn find_ldid() -> Option<String> {
        let possible_paths = [
            "/usr/local/bin/ldid",
            "/opt/homebrew/bin/ldid",
            "/usr/bin/ldid",
        ];

        for path in &possible_paths {
            if tokio::fs::metadata(path).await.is_ok() {
                return Some(path.to_string());
            }
        }

        None
    }

    /// Sign a binary using ldid
    pub async fn sign_binary(path: &PathBuf, no_entitlements: bool) -> Result<()> {
        let ldid_path = Self::find_ldid().await;
        if ldid_path.is_none() {
            return Err(anyhow::anyhow!("ldid not found"));
        }

        let ldid_path = ldid_path.unwrap();

        if no_entitlements {
            let status = Command::new(&ldid_path)
                .arg("-S")
                .arg(path)
                .status()
                .await
                .context("Failed to execute ldid -S")?;

            if !status.success() {
                return Err(anyhow::anyhow!("Failed to sign binary with ldid"));
            }
        } else {
            // Extract and use entitlements
            let entitlements_output = Command::new(&ldid_path)
                .arg("-e")
                .arg(path)
                .output()
                .await;

            match entitlements_output {
                Ok(output) if output.status.success() => {
                    let entitlements = String::from_utf8_lossy(&output.stdout);
                    
                    // Create temporary entitlements file
                    let temp_entitlements = tempfile::NamedTempFile::new()
                        .context("Failed to create temporary entitlements file")?;
                    
                    tokio::fs::write(temp_entitlements.path(), entitlements.as_bytes())
                        .await
                        .context("Failed to write entitlements to temporary file")?;

                    // Sign with entitlements
                    let status = Command::new(&ldid_path)
                        .arg(format!("-S{}", temp_entitlements.path().display()))
                        .arg(path)
                        .status()
                        .await
                        .context("Failed to execute ldid with entitlements")?;

                    if !status.success() {
                        return Err(anyhow::anyhow!("Failed to sign binary with entitlements"));
                    }
                }
                _ => {
                    return Err(anyhow::anyhow!("Failed to extract entitlements"));
                }
            }
        }

        Ok(())
    }
} 