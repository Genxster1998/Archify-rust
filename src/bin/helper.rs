use anyhow::{Context, Result};
use std::env;
use std::path::Path;
use std::process::Command;
use tokio::net::{UnixListener, UnixStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use shell_words;

const SOCKET_PATH: &str = "/var/run/com.archify.helper.sock";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    
    // If run with no arguments (launched by launchd) or explicitly with
    // "--daemon", run the background daemon that listens on a UNIX socket
    // for commands.
    if args.len() == 1 || (args.len() >= 2 && args[1] == "--daemon") {
        run_daemon().await?;
        return Ok(());
    }

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
            
            thin_app(app_path, target_arch, no_sign, use_codesign).await?;
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

async fn thin_app(app_path: &str, target_arch: &str, no_sign: bool, use_codesign: bool) -> Result<()> {
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
        if thin_binary(&binary, target_arch, no_sign, use_codesign).await {
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

async fn thin_binary(binary_path: &str, target_arch: &str, no_sign: bool, use_codesign: bool) -> bool {
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
        .filter(|&arch| ["x86_64", "arm64", "arm64e"].contains(&arch))
        .collect();

    if current_archs.is_empty() {
        eprintln!("[HELPER] No valid architectures found in: {}", binary_path);
        return false;
    }

    eprintln!("[HELPER] Current architectures: {:?}", current_archs);

    // Check if binary already has only the target architecture
    if current_archs.len() == 1 && current_archs[0] == target_arch {
        eprintln!("[HELPER] Binary already has only target architecture: {}", binary_path);
        return true;
    }

    // Use lipo -thin for in-place thinning
    let status = Command::new("lipo")
        .arg(binary_path)
        .arg("-thin")
        .arg(target_arch)
        .arg("-output")
        .arg(binary_path)
        .status();

    match status {
        Ok(status) if status.success() => {
            eprintln!("[HELPER] Successfully thinned: {}", binary_path);
            
            // Sign the binary if needed
            if !no_sign {
                if use_codesign {
                    sign_with_codesign(binary_path).await;
                } else {
                    sign_with_ldid(binary_path).await;
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

async fn sign_with_codesign(binary_path: &str) {
    let status = Command::new("codesign")
        .arg("--force")
        .arg("--sign")
        .arg("-")
        .arg(binary_path)
        .status();

    match status {
        Ok(status) if status.success() => {
            eprintln!("[HELPER] Successfully signed with codesign: {}", binary_path);
        }
        _ => {
            eprintln!("[HELPER] Warning: Failed to sign with codesign: {}", binary_path);
        }
    }
}

async fn sign_with_ldid(binary_path: &str) {
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
                eprintln!("[HELPER] Successfully signed with ldid: {}", binary_path);
            }
            _ => {
                eprintln!("[HELPER] Warning: Failed to sign with ldid: {}", binary_path);
            }
        }
    } else {
        eprintln!("[HELPER] Warning: ldid not found, skipping signing for: {}", binary_path);
    }
}

async fn run_daemon() -> Result<()> {
    // Remove any stale socket file
    let _ = std::fs::remove_file(SOCKET_PATH);

    let listener = UnixListener::bind(SOCKET_PATH)
        .context("Failed to bind unix socket for helper daemon")?;

    // Ensure correct permissions so regular (staff) users can reach it.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660)).ok();

    // If the primary group is staff (gid 20) change the socket group to staff
    unsafe {
        use std::ffi::CString;
        let cpath = CString::new(SOCKET_PATH).unwrap();
        let gid_staff: libc::gid_t = 20;
        // root user id is 0
        libc::chown(cpath.as_ptr(), 0, gid_staff);
    }

    eprintln!("[HELPER] Daemon started, listening on {}", SOCKET_PATH);

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_client(stream).await {
                eprintln!("[HELPER] client error: {}", e);
            }
        });
    }
}

async fn handle_client(stream: UnixStream) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Expect a single line command like: thin <path> <arch> [--no-sign] [--use-codesign]
    let bytes = reader.read_line(&mut line).await?;
    if bytes == 0 {
        return Ok(());
    }

    // Use shell_words to properly parse quoted arguments
    let parts = match shell_words::split(line.trim()) {
        Ok(parts) => parts,
        Err(e) => {
            let msg = format!("ERR Argument parse error: {}\n", e);
            writer.write_all(msg.as_bytes()).await?;
            return Ok(());
        }
    };
    if parts.is_empty() {
        writer.write_all(b"ERR Empty command\n").await?;
        return Ok(());
    }

    match parts[0].as_str() {
        "thin" => {
            if parts.len() < 3 {
                writer.write_all(b"ERR Usage: thin <app_path> <arch> [--no-sign] [--use-codesign]\n").await?;
            } else {
                let app_path = &parts[1];
                let arch = &parts[2];
                let no_sign = parts.iter().any(|s| s == "--no-sign");
                let use_codesign = parts.iter().any(|s| s == "--use-codesign");
                match thin_app(app_path, arch, no_sign, use_codesign).await {
                    Ok(_) => writer.write_all(b"OK\n").await?,
                    Err(e) => {
                        let msg = format!("ERR {}\n", e);
                        writer.write_all(msg.as_bytes()).await?;
                    }
                }
            }
        }
        _ => {
            writer.write_all(b"ERR Unknown command\n").await?;
        }
    }
    Ok(())
} 