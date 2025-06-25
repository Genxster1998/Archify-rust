use crate::types::{BinaryInfo, LogLevel, LogMessage};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};

pub struct BinaryProcessor;

impl BinaryProcessor {
    /// Check if a file is a Mach-O binary
    pub fn is_mach_binary(path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }

        // Check if it's a symbolic link
        if path.is_symlink() {
            return Ok(false);
        }

        // Use the `file` command to check if it's a Mach-O binary
        let output = Command::new("file")
            .arg("--mime-type")
            .arg(path)
            .output()
            .context("Failed to execute file command")?;

        let mime_type = String::from_utf8_lossy(&output.stdout);
        Ok(mime_type.contains("application/x-mach-binary"))
    }

    /// Get architectures present in a binary
    pub fn get_architectures(path: &Path) -> Result<Vec<String>> {
        let output = Command::new("lipo")
            .arg("-info")
            .arg(path)
            .output()
            .context("Failed to execute lipo -info")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        
        // Parse the output: "Non-fat file: /path/to/file is architecture: x86_64"
        // or "Architectures in the fat file: /path/to/file are: x86_64 arm64"
        if let Some(archs_part) = output_str.split(':').last() {
            let archs: Vec<String> = archs_part
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            Ok(archs)
        } else {
            Ok(Vec::new())
        }
    }

    /// Check if a binary is universal (contains multiple architectures)
    pub fn is_universal(path: &Path) -> Result<bool> {
        let archs = Self::get_architectures(path)?;
        Ok(archs.len() > 1)
    }

    /// Get detailed architecture information including sizes
    pub fn get_detailed_info(path: &Path) -> Result<BinaryInfo> {
        let output = Command::new("lipo")
            .arg("-detailed_info")
            .arg(path)
            .output()
            .context("Failed to execute lipo -detailed_info")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let archs = Self::get_architectures(path)?;
        let is_universal = archs.len() > 1;

        // Parse detailed info to get sizes
        let mut total_size = 0u64;
        let lines: Vec<&str> = output_str.lines().collect();
        
        for line in lines {
            if line.contains("size") {
                if let Some(size_str) = line.split_whitespace().find(|s| s.parse::<u64>().is_ok()) {
                    if let Ok(size) = size_str.parse::<u64>() {
                        total_size += size;
                    }
                }
            }
        }

        Ok(BinaryInfo {
            path: path.to_path_buf(),
            architectures: archs,
            size: total_size,
            is_universal,
        })
    }

    /// Calculate the size of architectures that can be removed
    pub fn calculate_removable_size(path: &Path, target_arch: &str) -> Result<u64> {
        let output = Command::new("lipo")
            .arg("-detailed_info")
            .arg(path)
            .output()
            .context("Failed to execute lipo -detailed_info")?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut removable_size = 0u64;
        let mut current_arch: Option<String> = None;

        for line in output_str.lines() {
            let line = line.trim();
            
            if line.starts_with("architecture") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    current_arch = Some(parts[1].to_string());
                }
            } else if line.contains("size") && current_arch.is_some() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if let Some(size_index) = parts.iter().position(|&s| s == "size") {
                    if size_index + 1 < parts.len() {
                        if let Ok(size) = parts[size_index + 1].parse::<u64>() {
                            let arch = current_arch.as_ref().unwrap();
                            if arch != target_arch {
                                removable_size += size;
                            }
                        }
                    }
                }
            }
        }

        Ok(removable_size)
    }

    /// Remove unwanted architectures from a binary using lipo
    pub async fn remove_architectures(
        path: &Path,
        target_arch: &str,
    ) -> Result<Vec<LogMessage>> {
        let mut logs = Vec::new();
        
        info!("Processing binary: {:?}", path);
        logs.push(LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: format!("Processing binary: {}", path.display()),
        });

        // Check if the binary is universal
        if !Self::is_universal(path)? {
            debug!("Binary is not universal, skipping: {:?}", path);
            return Ok(logs);
        }

        // Check if the target architecture is available
        let archs = Self::get_architectures(path)?;
        if !archs.contains(&target_arch.to_string()) {
            let msg = format!(
                "Target architecture {} not found in binary. Available: {:?}",
                target_arch, archs
            );
            warn!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Warning,
                message: msg,
            });
            return Ok(logs);
        }

        // Create a temporary file for the thinned binary
        let temp_file = tempfile::NamedTempFile::new()
            .context("Failed to create temporary file")?;
        let temp_path = temp_file.path();

        // Use lipo to thin the binary
        let status = TokioCommand::new("lipo")
            .arg("-thin")
            .arg(target_arch)
            .arg(path)
            .arg("-output")
            .arg(temp_path)
            .status()
            .await
            .context("Failed to execute lipo -thin")?;

        if !status.success() {
            let msg = format!("Failed to thin binary: {:?}", path);
            error!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Error,
                message: msg,
            });
            return Ok(logs);
        }

        // Replace the original file with the thinned version
        tokio::fs::rename(temp_path, path)
            .await
            .context("Failed to replace original file with thinned version")?;

        let msg = format!(
            "Successfully thinned binary {} to {} architecture",
            path.display(),
            target_arch
        );
        info!("{}", msg);
        logs.push(LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Success,
            message: msg,
        });

        Ok(logs)
    }

    /// Sign a binary using ldid (if available)
    pub async fn sign_with_ldid(
        path: &Path,
        no_entitlements: bool,
    ) -> Result<Vec<LogMessage>> {
        let mut logs = Vec::new();

        // Check if ldid is available
        let ldid_path = Self::find_ldid().await;
        if ldid_path.is_none() {
            let msg = "ldid not found, skipping signing".to_string();
            warn!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Warning,
                message: msg,
            });
            return Ok(logs);
        }

        let ldid_path = ldid_path.unwrap();

        if no_entitlements {
            // Sign without entitlements
            let status = TokioCommand::new(&ldid_path)
                .arg("-S")
                .arg(path)
                .status()
                .await
                .context("Failed to execute ldid -S")?;

            if !status.success() {
                let msg = format!("Failed to sign binary with ldid: {:?}", path);
                error!("{}", msg);
                logs.push(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: msg,
                });
            } else {
                let msg = format!("Successfully signed binary: {:?}", path);
                info!("{}", msg);
                logs.push(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Success,
                    message: msg,
                });
            }
        } else {
            // Extract and use entitlements
            let entitlements_output = TokioCommand::new(&ldid_path)
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
                    let status = TokioCommand::new(&ldid_path)
                        .arg(format!("-S{}", temp_entitlements.path().display()))
                        .arg(path)
                        .status()
                        .await
                        .context("Failed to execute ldid with entitlements")?;

                    if !status.success() {
                        let msg = format!("Failed to sign binary with entitlements: {:?}", path);
                        error!("{}", msg);
                        logs.push(LogMessage {
                            timestamp: chrono::Utc::now(),
                            level: LogLevel::Error,
                            message: msg,
                        });
                    } else {
                        let msg = format!("Successfully signed binary with entitlements: {:?}", path);
                        info!("{}", msg);
                        logs.push(LogMessage {
                            timestamp: chrono::Utc::now(),
                            level: LogLevel::Success,
                            message: msg,
                        });
                    }
                }
                _ => {
                    let msg = format!("Failed to extract entitlements from: {:?}", path);
                    warn!("{}", msg);
                    logs.push(LogMessage {
                        timestamp: chrono::Utc::now(),
                        level: LogLevel::Warning,
                        message: msg,
                    });
                }
            }
        }

        Ok(logs)
    }

    /// Find ldid executable
    async fn find_ldid() -> Option<String> {
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
} 