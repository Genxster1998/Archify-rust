use anyhow::{Context, Result};
use std::env;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
// Custom logger that writes to both a buffer and stderr
struct Logger {
    buffer: Arc<Mutex<String>>,
}

impl Logger {
    fn new() -> Self {
        Logger {
            buffer: Arc::new(Mutex::new(String::new())),
        }
    }
    fn log(&self, msg: &str) {
        // Write to buffer
        self.buffer.lock().unwrap().push_str(msg);
        self.buffer.lock().unwrap().push('\n');
        // Also write to stderr
        eprintln!("{}", msg);
    }
    fn get_logs(&self) -> String {
        self.buffer.lock().unwrap().clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();


    if args.len() < 2 {
        eprintln!("Usage: {} <command> [options]", args[0]);
        std::process::exit(1);
    }

    match args[1].as_str() {
        "thin" => {
            if args.len() < 4 {
                eprintln!("Usage: {} thin <app_path> <target_arch> [--no-sign] [--use-codesign]", args[0]);
                std::process::exit(1);
            }
            
            let app_path = &args[2];
            let target_arch = &args[3];
            let no_sign = args.contains(&"--no-sign".to_string());
            let use_codesign = args.contains(&"--use-codesign".to_string());
            
            thin_app(app_path, target_arch, no_sign, use_codesign, &Logger::new()).await?;
        }
        "--help" | "help" => {
            println!("Archify Helper - Privileged helper for thinning macOS applications");
            println!();
            println!("Usage: {} <command> [options]", args[0]);
            println!();
            println!("Commands:");
            println!("  thin <app_path> <target_arch> [options]  Thin an application to target architecture");
            println!();
            println!("Options:");
            println!("  --no-sign        Skip signing binaries after thinning");
            println!("  --use-codesign   Use codesign instead of ldid for signing");
            println!();
            println!("Examples:");
            println!("  {} thin /Applications/Example.app x86_64", args[0]);
            println!("  {} thin /Applications/Example.app arm64 --no-sign", args[0]);
            println!("  {} thin /Applications/Example.app x86_64 --use-codesign", args[0]);
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            eprintln!("Use '{} help' for usage information", args[0]);
            std::process::exit(1);
        }
    }

    Ok(())
}

async fn thin_app(app_path: &str, target_arch: &str, no_sign: bool, use_codesign: bool, logger: &Logger) -> Result<()> {
    eprintln!("[HELPER] Starting thinning process for: {}", app_path);
    eprintln!("[HELPER] Target architecture: {}", target_arch);
    eprintln!("[HELPER] No sign: {}, Use codesign: {}", no_sign, use_codesign);

    // Validate inputs
    if !Path::new(app_path).exists() {
        return Err(anyhow::anyhow!("App path does not exist: {}", app_path));
    }

    if !["x86_64", "arm64", "arm64e"].contains(&target_arch) {
        return Err(anyhow::anyhow!("Invalid target architecture: {}", target_arch));
    }

    // Find all Mach-O binaries in the app
    let output = Command::new("find")
        .arg(app_path)
        .arg("-type")
        .arg("f")
        .output()
        .context("Failed to find files")?;

    let files = String::from_utf8_lossy(&output.stdout);
    let mut binaries = Vec::new();

    for line in files.lines() {
        if is_mach_o_binary(line).await {
            binaries.push(line.to_string());
        }
    }

    eprintln!("[HELPER] Found {} Mach-O binaries to process", binaries.len());

    let mut processed_count = 0;
    let mut failed_count = 0;

    for binary in binaries {
        if thin_binary(&binary, target_arch, no_sign, use_codesign, logger).await {
            processed_count += 1;
        } else {
            failed_count += 1;
        }
    }

    eprintln!("[HELPER] Processing complete: {} successful, {} failed", processed_count, failed_count);
    Ok(())
}

async fn is_mach_o_binary(path: &str) -> bool {
    let output = Command::new("file")
        .arg(path)
        .output()
        .ok();

    if let Some(output) = output {
        let file_type = String::from_utf8_lossy(&output.stdout);
        file_type.contains("Mach-O")
    } else {
        false
    }
}

async fn thin_binary(binary_path: &str, target_arch: &str, no_sign: bool, use_codesign: bool, logger: &Logger) -> bool {
    eprintln!("[HELPER] Processing binary: {}", binary_path);

    // Get current architectures using `lipo -archs` which outputs a plain
    // whitespace-separated list such as "x86_64 arm64".
    let arch_output = Command::new("lipo")
        .arg("-archs")
        .arg(binary_path)
        .output();

    let arch_output = match arch_output {
        Ok(output) => output,
        Err(_) => {
            eprintln!("[HELPER] Failed to get architectures for: {}", binary_path);
            return false;
        }
    };

    let arch_info = String::from_utf8_lossy(&arch_output.stdout);
    let current_archs: Vec<&str> = arch_info
        .split_whitespace()
        .filter(|&arch| ["x86_64", "arm64", "arm64e", "i386", "ppc", "ppc64"].contains(&arch))
        .collect();

    if current_archs.is_empty() {
        eprintln!("[HELPER] No valid architectures found in: {}", binary_path);
        return false;
    }

    eprintln!("[HELPER] Current architectures: {:?}", current_archs);

    // Split target architectures (comma-separated list of archs to keep)
    let target_archs: Vec<&str> = target_arch.split(',').collect();

    // Find which slices to remove (slices present in binary but not in target_archs)
    let to_remove: Vec<&str> = current_archs
        .iter()
        .cloned()
        .filter(|arch| !target_archs.contains(arch))
        .collect();

    if to_remove.is_empty() {
        eprintln!("[HELPER] Binary already has only target architectures: {:?}", target_archs);
        return true;
    }

    // Check if we are removing all slices (which is invalid)
    if to_remove.len() == current_archs.len() {
        eprintln!("[HELPER] Skipping: no matching architectures to keep in: {}", binary_path);
        return true; // Skipping is considered success for the batch flow
    }

    // Use lipo -remove for in-place thinning
    let mut cmd = Command::new("lipo");
    cmd.arg(binary_path);
    for arch in &to_remove {
        cmd.arg("-remove").arg(arch);
    }
    cmd.arg("-output").arg(binary_path);

    let status = cmd.status();

    match status {
        Ok(status) if status.success() => {
            eprintln!("[HELPER] Successfully thinned: {} (removed {:?})", binary_path, to_remove);
            
            // Sign the binary if needed
            if !no_sign {
                if use_codesign {
                    sign_with_codesign(binary_path, logger).await;
                } else {
                    sign_with_ldid(binary_path, logger).await;
                }
            }
            
            true
        }
        _ => {
            eprintln!("[HELPER] Failed to thin: {}", binary_path);
            false
        }
    }
}

async fn sign_with_codesign(binary_path: &str, logger: &Logger) {
    let status = Command::new("codesign")
        .arg("--force")
        .arg("--sign")
        .arg("-")
        .arg(binary_path)
        .status();

    match status {
        Ok(status) if status.success() => {
            logger.log(&format!("[HELPER] Successfully signed with codesign: {}", binary_path));
        }
        _ => {
            logger.log(&format!("[HELPER] Warning: Failed to sign with codesign: {}", binary_path));
        }
    }
}

async fn sign_with_ldid(binary_path: &str, logger: &Logger) {
    // Try to find ldid
    let ldid_paths = ["/usr/local/bin/ldid", "/opt/homebrew/bin/ldid", "/usr/bin/ldid"];
    let mut ldid_path = None;

    for path in &ldid_paths {
        if Path::new(path).exists() {
            ldid_path = Some(path);
            break;
        }
    }

    if let Some(ldid_path) = ldid_path {
        let status = Command::new(ldid_path)
            .arg("-S")
            .arg(binary_path)
            .status();

        match status {
            Ok(status) if status.success() => {
                logger.log(&format!("[HELPER] Successfully signed with ldid: {}", binary_path));
            }
            _ => {
                logger.log(&format!("[HELPER] Warning: Failed to sign with ldid: {}", binary_path));
            }
        }
    } else {
        logger.log(&format!("[HELPER] Warning: ldid not found, skipping signing for: {}", binary_path));
    }
}