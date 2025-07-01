use crate::types::{LogLevel, LogMessage};
use anyhow::{Context, Result};
use std::path::Path;
use std::fs;
use goblin::mach::Mach;
use goblin::Object;
use tokio::process::Command as TokioCommand;
use tracing::{debug, error, info, warn};
use goblin::mach::constants::cputype::*;

// Define missing cpusubtype constants if not present in goblin
const CPU_SUBTYPE_ARM64E: u32 = 2;

pub struct BinaryProcessor;

impl BinaryProcessor {
    /// Check if a file is a Mach-O binary using goblin
    pub fn is_mach_binary(path: &Path) -> Result<bool> {
        if !path.exists() {
            return Ok(false);
        }
        if path.is_symlink() {
            return Ok(false);
        }
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return Ok(false),
        };
        match Object::parse(&data) {
            Ok(Object::Mach(_)) => Ok(true),
            _ => Ok(false),
        }
    }

    /// Helper to map cputype/cpusubtype to architecture string
    fn arch_name(cputype: u32, cpusubtype: u32) -> String {
        // Mask off the high bit (capability bit) for cpusubtype
        let masked_subtype = cpusubtype & 0x7FFFFFFF;
        match (cputype, masked_subtype) {
            (CPU_TYPE_X86_64, _) => "x86_64".to_string(),
            (CPU_TYPE_X86, 3) => "i386".to_string(), // CPU_SUBTYPE_I386_ALL = 3
            (CPU_TYPE_X86, 8) => "x86_64h".to_string(), // CPU_SUBTYPE_X86_64_H = 8
            (CPU_TYPE_ARM64, 0) => "arm64".to_string(), // CPU_SUBTYPE_ARM64_ALL = 0
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) => "arm64e".to_string(),
            (CPU_TYPE_ARM, 9) => "armv7".to_string(), // CPU_SUBTYPE_ARM_V7 = 9
            (CPU_TYPE_ARM, 11) => "armv7s".to_string(), // CPU_SUBTYPE_ARM_V7S = 11
            (CPU_TYPE_ARM, 12) => "armv7k".to_string(), // CPU_SUBTYPE_ARM_V7K = 12
            (CPU_TYPE_ARM, 6) => "armv6".to_string(), // CPU_SUBTYPE_ARM_V6 = 6
            (CPU_TYPE_ARM, 13) => "armv8".to_string(), // CPU_SUBTYPE_ARM_V8 = 13
            (CPU_TYPE_ARM, _) => "arm".to_string(),
            _ => format!("{}:{}", cputype, cpusubtype),
        }
    }

    /// Get architectures present in a binary using goblin
    pub fn get_architectures(path: &Path) -> Result<Vec<String>> {
        let data = fs::read(path).context("Failed to read binary file")?;
        match Object::parse(&data) {
            Ok(Object::Mach(Mach::Fat(fat))) => {
                let mut archs = Vec::new();
                for arch_result in fat.iter_arches() {
                    if let Ok(arch) = arch_result {
                        archs.push(Self::arch_name(arch.cputype, arch.cpusubtype));
                    }
                }
                Ok(archs)
            }
            Ok(Object::Mach(Mach::Binary(_mach))) => {
                Ok(vec![Self::arch_name(_mach.header.cputype(), _mach.header.cpusubtype())])
            }
            _ => Ok(Vec::new()),
        }
    }

    /// Check if a binary is universal (contains multiple architectures)
    pub fn is_universal(path: &Path) -> Result<bool> {
        let archs = Self::get_architectures(path)?;
        Ok(archs.len() > 1)
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

        // Check if the file is writable
        if let Ok(metadata) = tokio::fs::metadata(path).await {
            let permissions = metadata.permissions();
            if permissions.readonly() {
                let msg = format!("File is read-only, cannot modify: {}", path.display());
                warn!("{}", msg);
                logs.push(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Warning,
                    message: msg,
                });
                return Ok(logs);
            }
        }

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

        // Check if binary already has only the target architecture
        if archs.len() == 1 && archs[0] == target_arch {
            let msg = format!(
                "Binary {} already has only target architecture {}",
                path.display(),
                target_arch
            );
            info!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Info,
                message: msg,
            });
            return Ok(logs);
        }

        // Use lipo to thin the binary in-place (like the original archify app)
        let output = TokioCommand::new("lipo")
            .arg(path)
            .arg("-thin")
            .arg(target_arch)
            .arg("-output")
            .arg(path)
            .output()
            .await
            .context("Failed to execute lipo -thin")?;

        if !output.status.success() {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            let msg = format!("Failed to thin binary: {} (Error: {})", path.display(), error_msg);
            error!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Error,
                message: msg,
            });
            return Ok(logs);
        }

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