use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use tokio::process::Command;
use anyhow::{Context, Result};

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
        
        // Create the helper binary in a temporary location
        let helper_content = r#"#!/bin/bash
# Privileged helper for archify - robust thinning implementation
set -euo pipefail

# Debug: Check current user and permissions
echo "=== DEBUG INFO ===" >&2
echo "Current user: $(whoami)" >&2
echo "Effective user: $(id -u)" >&2
echo "Effective group: $(id -g)" >&2
echo "Arguments received: $*" >&2
echo "Number of arguments: $#" >&2
echo "==================" >&2

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >&2
}

# Error handling
error_exit() {
    log "ERROR: $1"
    exit 1
}

# Check if binary is Mach-O
is_mach_o() {
    local binary="$1"
    file "$binary" 2>/dev/null | grep -q "Mach-O"
}

# Get architectures from binary
get_architectures() {
    local binary="$1"
    lipo -info "$binary" 2>/dev/null | sed 's/.*: //' | tr ' ' '\n' | grep -E '^(x86_64|arm64|arm64e)$' || true
}

# Check if binary has specific architecture
has_architecture() {
    local binary="$1"
    local arch="$2"
    get_architectures "$binary" | grep -q "^${arch}$"
}

# Sign binary if needed
sign_binary() {
    local binary="$1"
    local no_sign="$2"
    local use_codesign="$3"
    
    if [[ "$no_sign" == "true" ]]; then
        log "Skipping signing for $binary (--no-sign specified)"
        return 0
    fi
    
    if [[ "$use_codesign" == "true" ]]; then
        log "Signing $binary with codesign"
        if codesign --force --sign - "$binary" 2>/dev/null; then
            log "Successfully signed $binary with codesign"
        else
            log "Warning: Failed to sign $binary with codesign"
        fi
    else
        log "Signing $binary with ldid"
        if ldid -S "$binary" 2>/dev/null; then
            log "Successfully signed $binary with ldid"
        else
            log "Warning: Failed to sign $binary with ldid"
        fi
    fi
}

# Main thinning function
thin_binary() {
    local binary="$1"
    local target_arch="$2"
    local no_sign="$3"
    local use_codesign="$4"
    
    log "Processing binary: $binary"
    
    # Check if it's a Mach-O binary
    if ! is_mach_o "$binary"; then
        log "Skipping non-Mach-O file: $binary"
        return 0
    fi
    
    # Get current architectures
    local current_archs=($(get_architectures "$binary"))
    if [[ ${#current_archs[@]} -eq 0 ]]; then
        log "No valid architectures found in $binary"
        return 0
    fi
    
    log "Current architectures: ${current_archs[*]}"
    
    # Check if binary already has only the target architecture
    if [[ ${#current_archs[@]} -eq 1 && "${current_archs[0]}" == "$target_arch" ]]; then
        log "Binary $binary already has only target architecture $target_arch"
        return 0
    fi
    
    # Use lipo -thin for in-place thinning (like the original archify app)
    log "Thinning $binary to $target_arch architecture"
    if lipo "$binary" -thin "$target_arch" -output "$binary" 2>/dev/null; then
        log "Successfully thinned $binary to $target_arch"
        
        # Sign the binary if needed
        sign_binary "$binary" "$no_sign" "$use_codesign"
        log "Successfully processed $binary"
        return 0
    else
        log "Failed to thin $binary to $target_arch"
        return 1
    fi
}

# Main command handler
if [[ $# -eq 0 ]]; then
    error_exit "No arguments provided. Usage: $0 <command> [options]"
fi

case "$1" in
    "thin")
        if [[ $# -lt 3 ]]; then
            error_exit "Usage: $0 thin <app_path> <target_arch> [options]"
        fi
        
        APP_PATH="$2"
        TARGET_ARCH="$3"
        NO_SIGN="false"
        USE_CODESIGN="false"
        
        # Parse additional options
        shift 3
        while [[ $# -gt 0 ]]; do
            case $1 in
                --no-sign) NO_SIGN="true" ;;
                --use-codesign) USE_CODESIGN="true" ;;
                *) error_exit "Unknown option: $1" ;;
            esac
            shift
        done
        
        # Validate inputs
        if [[ ! -d "$APP_PATH" ]]; then
            error_exit "App path does not exist: $APP_PATH"
        fi
        
        if [[ ! "$TARGET_ARCH" =~ ^(x86_64|arm64|arm64e)$ ]]; then
            error_exit "Invalid target architecture: $TARGET_ARCH"
        fi
        
        log "Starting thinning process"
        log "App path: $APP_PATH"
        log "Target architecture: $TARGET_ARCH"
        log "No sign: $NO_SIGN"
        log "Use codesign: $USE_CODESIGN"
        
        # Find all Mach-O binaries in the app
        binaries=()
        while IFS= read -r -d '' file; do
            if is_mach_o "$file"; then
                binaries+=("$file")
            fi
        done < <(find "$APP_PATH" -type f -print0)
        
        log "Found ${#binaries[@]} Mach-O binaries to process"
        
        # Process each binary
        processed_count=0
        failed_count=0
        
        for binary in "${binaries[@]}"; do
            if thin_binary "$binary" "$TARGET_ARCH" "$NO_SIGN" "$USE_CODESIGN"; then
                ((processed_count++))
            else
                ((failed_count++))
            fi
        done
        
        log "Thinning completed: $processed_count processed, $failed_count failed"
        
        if [[ $failed_count -eq 0 ]]; then
            echo "Successfully thinned $APP_PATH"
        else
            error_exit "Thinning completed with $failed_count failures"
        fi
        ;;
    *)
        error_exit "Unknown command: $1"
        ;;
esac
"#;
        
        let temp_helper_path = "/tmp/archify_helper_install";
        tokio::fs::write(temp_helper_path, helper_content).await?;
        
        // Set executable permissions
        tokio::fs::set_permissions(temp_helper_path, std::fs::Permissions::from_mode(0o755)).await?;
        
        // Create the plist file
        let plist_content = include_str!("../helper/com.archify.helper.plist");
        let temp_plist_path = "/tmp/com.archify.helper.plist";
        tokio::fs::write(temp_plist_path, plist_content).await?;
        
        // Install using SMJobBless (this will prompt for admin password)
        let status = Command::new("sudo")
            .args(&[
                "cp", temp_helper_path, "/Library/PrivilegedHelperTools/com.archify.helper"
            ])
            .status()
            .await?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to copy helper binary"));
        }
        
        let status = Command::new("sudo")
            .args(&[
                "cp", temp_plist_path, "/Library/LaunchDaemons/com.archify.helper.plist"
            ])
            .status()
            .await?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to copy plist file"));
        }
        
        // Set proper permissions
        let status = Command::new("sudo")
            .args(&[
                "chown", "root:wheel", "/Library/PrivilegedHelperTools/com.archify.helper"
            ])
            .status()
            .await?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to set helper ownership"));
        }
        
        let status = Command::new("sudo")
            .args(&[
                "chown", "root:wheel", "/Library/LaunchDaemons/com.archify.helper.plist"
            ])
            .status()
            .await?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to set plist ownership"));
        }
        
        // Load the service
        let status = Command::new("sudo")
            .args(&[
                "launchctl", "load", "/Library/LaunchDaemons/com.archify.helper.plist"
            ])
            .status()
            .await?;
            
        if !status.success() {
            return Err(anyhow::anyhow!("Failed to load helper service"));
        }
        
        // Clean up temp files
        let _ = tokio::fs::remove_file(temp_helper_path).await;
        let _ = tokio::fs::remove_file(temp_plist_path).await;
        
        println!("Privileged helper installed and loaded successfully");
        Ok(())
    }

    /// Send a thinning request to the privileged helper
    pub async fn thin_app(
        app_path: &Path,
        target_arch: &str,
        no_sign: bool,
        _no_entitlements: bool,
        use_codesign: bool,
    ) -> Result<String> {
        // Use sudo to run the helper with root permissions
        
        let mut args = vec![
            "/Library/PrivilegedHelperTools/com.archify.helper",
            "thin",
            app_path.to_str().unwrap(),
            target_arch,
        ];
        
        if no_sign {
            args.push("--no-sign");
        }
        if use_codesign {
            args.push("--use-codesign");
        }
        
        let output = Command::new("sudo")
            .args(&args)
            .output()
            .await
            .context("Failed to execute privileged helper with sudo")?;
            
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!(
                "Helper failed with status {}: {}",
                output.status,
                stderr
            ))
        }
    }
} 