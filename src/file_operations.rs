use crate::binary_processor::BinaryProcessor;
use crate::types::{AppInfo, AppType, AppSource, LogLevel, LogMessage, ProcessingConfig, ProcessingResult, BatchProcessingConfig, BatchProcessingResult};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use walkdir::WalkDir;
use futures::stream::{FuturesUnordered, StreamExt};
use serde_json;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use std::os::unix::fs::MetadataExt;
use libc;
use num_cpus;

pub struct FileOperations;

impl FileOperations {
    /// Analyze a single application
    async fn analyze_app(app_path: &Path) -> Result<Option<AppInfo>> {
        let name = app_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("Unknown")
            .to_string();

        // Skip system apps
        if Self::is_system_app(&name) {
            return Ok(None);
        }

        let total_size = Self::calculate_directory_size(app_path).await?;
        let architectures = Self::get_app_architectures(app_path).await?;
        let app_type = Self::determine_app_type(&architectures);
        let savable_size = Self::calculate_savable_size(app_path, &architectures).await?;
        let app_source = Self::detect_app_source(app_path).await?;

        Ok(Some(AppInfo {
            name,
            path: app_path.to_path_buf(),
            total_size,
            savable_size,
            architectures,
            app_type,
            app_source,
            is_selected: false,
        }))
    }

    /// Check if an app is a system app that should be skipped
    fn is_system_app(name: &str) -> bool {
        let system_apps = [
            "App Store.app",
            "Automator.app",
            "Calculator.app",
            "Calendar.app",
            "Chess.app",
            "Contacts.app",
            "Dashboard.app",
            "Dictionary.app",
            "DVD Player.app",
            "FaceTime.app",
            "Font Book.app",
            "Game Center.app",
            "Image Capture.app",
            "Launchpad.app",
            "Mail.app",
            "Maps.app",
            "Messages.app",
            "Mission Control.app",
            "Notes.app",
            "Photo Booth.app",
            "Photos.app",
            "Preview.app",
            "QuickTime Player.app",
            "Reminders.app",
            "Safari.app",
            "Siri.app",
            "Stickies.app",
            "System Preferences.app",
            "Terminal.app",
            "TextEdit.app",
            "Time Machine.app",
            "Voice Memos.app",
            "Xcode.app",
        ];

        system_apps.contains(&name)
    }

    /// Calculate the total size of a directory
    async fn calculate_directory_size(path: &Path) -> Result<u64> {
        let mut total_size = 0u64;

        for entry in WalkDir::new(path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if let Ok(metadata) = tokio::fs::metadata(entry.path()).await {
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }

    /// Get architectures present in an app's main executable
    async fn get_app_architectures(app_path: &Path) -> Result<Vec<String>> {
        let macos_path = app_path.join("Contents/MacOS");
        let mut architectures = Vec::new();

        if macos_path.exists() {
            let mut entries = tokio::fs::read_dir(&macos_path).await
                .context("Failed to read MacOS directory")?;
            
            while let Some(entry) = entries.next_entry().await? {
                let executable_path = entry.path();
                if let Ok(archs) = BinaryProcessor::get_architectures(&executable_path) {
                    architectures.extend(archs);
                }
            }
        }

        // Remove duplicates
        architectures.sort();
        architectures.dedup();
        Ok(architectures)
    }

    /// Determine the type of app based on architectures
    fn determine_app_type(architectures: &[String]) -> AppType {
        if architectures.len() > 1 {
            // Only mark as universal if both x86_64 and arm64 are present
            let has_x86_64 = architectures.iter().any(|arch| arch == "x86_64");
            let has_arm64 = architectures.iter().any(|arch| arch == "arm64" || arch == "arm64e");
            
            if has_x86_64 && has_arm64 {
                AppType::Universal
            } else {
                AppType::Other
            }
        } else if architectures.is_empty() {
            AppType::Other
        } else {
            let system_arch = get_system_architecture();
            if architectures.contains(&system_arch) {
                AppType::Native
            } else {
                AppType::Other
            }
        }
    }

    /// Calculate how much space can be saved by removing unwanted architectures
    async fn calculate_savable_size(
        app_path: &Path,
        app_architectures: &[String],
    ) -> Result<u64> {
        if app_architectures.len() <= 1 {
            return Ok(0);
        }

        let system_arch = get_system_architecture();
        let mut total_savable = 0u64;

        for entry in WalkDir::new(app_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            if BinaryProcessor::is_mach_binary(file_path)? {
                if let Ok(savable) = Self::calculate_unneeded_arch_size_for_binary(file_path, &system_arch).await {
                    total_savable += savable;
                }
            }
        }

        Ok(total_savable)
    }

    /// Calculate unneeded architecture size for a single binary using lipo -detailed_info
    pub async fn calculate_unneeded_arch_size_for_binary(binary_path: &Path, system_arch: &str) -> Result<u64> {
        let output = tokio::process::Command::new("lipo")
            .arg("-detailed_info")
            .arg(binary_path)
            .output()
            .await
            .context("Failed to execute lipo -detailed_info")?;

        if !output.status.success() {
            return Ok(0);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut architecture_sizes: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        let mut current_arch: Option<String> = None;

        for line in output_str.lines() {
            let trimmed_line = line.trim();
            if trimmed_line.starts_with("architecture") {
                let components: Vec<&str> = trimmed_line.split_whitespace().collect();
                if components.len() >= 2 {
                    current_arch = Some(components[1].to_string());
                }
            } else if trimmed_line.contains("size") && current_arch.is_some() {
                let components: Vec<&str> = trimmed_line.split_whitespace().collect();
                if let Some(size_index) = components.iter().position(|&x| x == "size") {
                    if size_index + 1 < components.len() {
                        if let Ok(size) = components[size_index + 1].parse::<u64>() {
                            architecture_sizes.insert(current_arch.clone().unwrap(), size);
                        }
                    }
                }
            }
        }

        // Calculate total size of unneeded architectures
        let unneeded_sizes: u64 = architecture_sizes
            .iter()
            .filter(|(arch, _)| *arch != system_arch)
            .map(|(_, size)| size)
            .sum();

        Ok(unneeded_sizes)
    }

    /// Process a single application (remove unwanted architectures)
    pub async fn process_app(
        app_path: &Path,
        config: &ProcessingConfig,
        progress_sender: mpsc::Sender<LogMessage>,
    ) -> Result<ProcessingResult> {
        let original_size = Self::calculate_directory_size(app_path).await?;
        let mut logs = Vec::new();

        // Process all Mach-O binaries in the app
        let mut processed_files = 0;
        let mut total_files = 0;

        // Count total files first
        for entry in WalkDir::new(app_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            if BinaryProcessor::is_mach_binary(entry.path())? {
                total_files += 1;
            }
        }

        // Process files
        for entry in WalkDir::new(app_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let file_path = entry.path();
            
            if BinaryProcessor::is_mach_binary(file_path)? {
                // Remove unwanted architectures
                let mut file_logs = BinaryProcessor::remove_architectures(file_path, &config.target_architecture).await?;
                logs.append(&mut file_logs);

                // Sign if needed
                if !config.no_sign {
                    let mut sign_logs = BinaryProcessor::sign_with_ldid(file_path, config.no_entitlements).await?;
                    logs.append(&mut sign_logs);
                }

                processed_files += 1;
                
                // Send progress update
                let progress_msg = LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Info,
                    message: format!(
                        "Processed {}/{} files in {}",
                        processed_files,
                        total_files,
                        app_path.file_name().unwrap_or_default().to_string_lossy()
                    ),
                };
                let _ = progress_sender.send(progress_msg.clone()).await;
            }
        }

        // Sign entire app with codesign if requested
        if config.use_codesign {
            let mut codesign_logs = Self::codesign_app(app_path, config.no_entitlements).await?;
            logs.append(&mut codesign_logs);
        }

        let final_size = Self::calculate_directory_size(app_path).await?;
        let saved_space = original_size.saturating_sub(final_size);

        // Send all logs
        for log in &logs {
            let _ = progress_sender.send(log.clone()).await;
        }

        Ok(ProcessingResult {
            app_path: app_path.to_path_buf(),
            output_path: None,
            original_size,
            final_size,
            saved_space,
            success: true,
            error_message: None,
            logs,
        })
    }

    /// Sign an entire app with codesign
    async fn codesign_app(app_path: &Path, no_entitlements: bool) -> Result<Vec<LogMessage>> {
        let mut logs = Vec::new();
        let mut cmd = tokio::process::Command::new("codesign");
        
        cmd.args(&["--force", "--deep", "--sign", "-"]);
        
        if !no_entitlements {
            // Extract entitlements
            if let Ok(entitlements) = Self::extract_entitlements(app_path).await {
                cmd.args(&["--entitlements", &entitlements]);
            }
        }
        
        cmd.arg(app_path);

        let output = cmd.output().await.context("Failed to execute codesign")?;

        if output.status.success() {
            let msg = format!("Successfully signed app with codesign: {:?}", app_path);
            info!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Success,
                message: msg,
            });
        } else {
            let error_msg = String::from_utf8_lossy(&output.stderr);
            let msg = format!("Failed to sign app with codesign: {}", error_msg);
            error!("{}", msg);
            logs.push(LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Error,
                message: msg,
            });
        }

        Ok(logs)
    }

    /// Extract entitlements from an app
    async fn extract_entitlements(app_path: &Path) -> Result<String> {
        let output = tokio::process::Command::new("codesign")
            .args(&["-d", "--entitlements", "-", "--xml"])
            .arg(app_path)
            .output()
            .await
            .context("Failed to extract entitlements")?;

        if output.status.success() {
            let entitlements = String::from_utf8(output.stdout)
                .context("Failed to parse entitlements output")?;
            Ok(entitlements)
        } else {
            Err(anyhow::anyhow!("Failed to extract entitlements"))
        }
    }

    /// Format bytes into human-readable format
    pub fn human_readable_size(size: u64, decimal_places: usize) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"];
        let mut size_f64 = size as f64;
        let mut unit_index = 0;
        
        while size_f64 >= 1024.0 && unit_index < units.len() - 1 {
            size_f64 /= 1024.0;
            unit_index += 1;
        }
        
        format!("{:.1$} {2}", size_f64, decimal_places, units[unit_index])
    }

    /// Batch process multiple applications
    pub async fn batch_process_apps(
        app_paths: Vec<PathBuf>,
        config: &BatchProcessingConfig,
        progress_sender: mpsc::Sender<LogMessage>,
    ) -> Result<BatchProcessingResult> {
        let mut all_results = Vec::new();
        let mut all_logs = Vec::new();
        let mut total_original_size = 0u64;
        let mut total_final_size = 0u64;
        let mut total_saved_space = 0u64;
        let mut successful_apps = 0;
        let mut failed_apps = 0;
        let total_apps = app_paths.len();
        let mut processed_count = 0;

        // Send batch start message
        let start_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: format!("Starting batch processing of {} applications (in-place)", app_paths.len()),
        };
        let _ = progress_sender.send(start_msg.clone()).await;
        all_logs.push(start_msg);

        if config.parallel_processing {
            // Parallel processing
            let mut futures = FuturesUnordered::new();
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(config.max_parallel_jobs));
            
            for app_path in app_paths {
                let semaphore = semaphore.clone();
                let config = config.clone();
                let progress_sender = progress_sender.clone();
                
                let future = async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    Self::process_single_app_in_batch(&app_path, &config, progress_sender).await
                };
                
                futures.push(future);
            }
            
            while let Some(result) = futures.next().await {
                processed_count += 1;
                let progress_msg = LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Info,
                    message: format!("PROGRESS:{}/{}", processed_count, total_apps),
                };
                let _ = progress_sender.send(progress_msg).await;
                match result {
                    Ok(result) => {
                        all_results.push(result.clone());
                        all_logs.extend(result.logs.clone());
                        
                        if result.success {
                            successful_apps += 1;
                            total_original_size += result.original_size;
                            total_final_size += result.final_size;
                            total_saved_space += result.saved_space;
                        } else {
                            failed_apps += 1;
                        }
                    }
                    Err(e) => {
                        failed_apps += 1;
                        let error_msg = LogMessage {
                            timestamp: chrono::Utc::now(),
                            level: LogLevel::Error,
                            message: format!("Failed to process app: {}", e),
                        };
                        let _ = progress_sender.send(error_msg.clone()).await;
                        all_logs.push(error_msg);
                    }
                }
            }
        } else {
            // Sequential processing
            for (index, app_path) in app_paths.iter().enumerate() {
                let progress_msg = LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Info,
                    message: format!("PROGRESS:{}/{}", index + 1, total_apps),
                };
                let _ = progress_sender.send(progress_msg).await;
                let progress_msg2 = LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Info,
                    message: format!("Processing app {}/{}: {} (in-place)", index + 1, app_paths.len(), app_path.file_name().unwrap_or_default().to_string_lossy()),
                };
                let _ = progress_sender.send(progress_msg2.clone()).await;
                all_logs.push(progress_msg2);

                match Self::process_single_app_in_batch(app_path, config, progress_sender.clone()).await {
                    Ok(result) => {
                        all_results.push(result.clone());
                        all_logs.extend(result.logs.clone());
                        
                        if result.success {
                            successful_apps += 1;
                            total_original_size += result.original_size;
                            total_final_size += result.final_size;
                            total_saved_space += result.saved_space;
                        } else {
                            failed_apps += 1;
                        }
                    }
                    Err(e) => {
                        failed_apps += 1;
                        let error_msg = LogMessage {
                            timestamp: chrono::Utc::now(),
                            level: LogLevel::Error,
                            message: format!("Failed to process {}: {}", app_path.display(), e),
                        };
                        let _ = progress_sender.send(error_msg.clone()).await;
                        all_logs.push(error_msg);
                    }
                }
            }
        }

        // Send batch completion message
        let completion_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Success,
            message: format!(
                "Batch processing completed. Success: {}, Failed: {}, Total saved: {}",
                successful_apps,
                failed_apps,
                Self::human_readable_size(total_saved_space, 2)
            ),
        };
        let _ = progress_sender.send(completion_msg.clone()).await;
        all_logs.push(completion_msg);

        // Save logs to file if requested
        if config.save_logs_to_file {
            if let Err(e) = Self::save_logs_to_file(&all_logs).await {
                warn!("Failed to save logs to file: {}", e);
            }
        }

        Ok(BatchProcessingResult {
            results: all_results,
            total_original_size,
            total_final_size,
            total_saved_space,
            successful_apps,
            failed_apps,
            all_logs,
        })
    }

    /// Process a single app as part of a batch
    async fn process_single_app_in_batch(
        app_path: &Path,
        config: &BatchProcessingConfig,
        progress_sender: mpsc::Sender<LogMessage>,
    ) -> Result<ProcessingResult> {
        let mut logs = Vec::new();
        let output_path = None;
        let _seen_paths: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));

        // Calculate initial size
        let initial_size = Self::calculate_directory_size(app_path).await?;
        
        let start_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: format!(
                "Processing {} (Initial size: {})",
                app_path.file_name().unwrap_or_default().to_string_lossy(),
                Self::human_readable_size(initial_size, 2)
            ),
        };
        let _ = progress_sender.send(start_msg.clone()).await;
        logs.push(start_msg);

        // Process the app
        let process_result = Self::process_app(app_path, &config.processing_config, progress_sender.clone()).await?;
        logs.extend(process_result.logs);

        // Calculate final size
        let final_size = Self::calculate_directory_size(app_path).await?;
        let saved_space = initial_size.saturating_sub(final_size);

        let completion_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Success,
            message: format!(
                "Completed {} (Final size: {}, Saved: {}, {:.1}%)",
                app_path.file_name().unwrap_or_default().to_string_lossy(),
                Self::human_readable_size(final_size, 2),
                Self::human_readable_size(saved_space, 2),
                if initial_size > 0 { (saved_space as f64 / initial_size as f64) * 100.0 } else { 0.0 }
            ),
        };
        let _ = progress_sender.send(completion_msg.clone()).await;
        logs.push(completion_msg);

        Ok(ProcessingResult {
            app_path: app_path.to_path_buf(),
            output_path,
            original_size: initial_size,
            final_size,
            saved_space,
            success: true,
            error_message: None,
            logs,
        })
    }

    /// Save logs to a file (in current directory)
    async fn save_logs_to_file(logs: &[LogMessage]) -> Result<()> {
        let log_file_path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("process_log.txt");
        let mut log_content = String::new();
        
        for log in logs {
            log_content.push_str(&format!(
                "[{}] {}: {}\n",
                log.timestamp.format("%Y-%m-%d %H:%M:%S"),
                log.level,
                log.message
            ));
        }
        
        tokio::fs::write(&log_file_path, log_content).await
            .context("Failed to write log file")?;
            
        Ok(())
    }

    /// Scan multiple directories for applications asynchronously with progress updates
    pub async fn scan_applications_async_multi(
        scan_dirs: Vec<PathBuf>,
        show_only_universal: bool,
        show_only_appstore: bool,
        scan_depth: usize,
        progress_sender: mpsc::Sender<LogMessage>,
    ) -> Result<()> {
        let mut apps = Vec::new();
        let _seen_paths: Arc<Mutex<HashSet<PathBuf>>> = Arc::new(Mutex::new(HashSet::new()));
        let total_dirs = scan_dirs.len();
        let concurrency_limit = num_cpus::get(); // Use all available CPU threads
        let semaphore = Arc::new(Semaphore::new(concurrency_limit));

        // Collect all app_dirs first to know total count
        let mut all_app_dirs = Vec::new();
        for dir in &scan_dirs {
            if dir.exists() {
                let app_dirs: Vec<_> = WalkDir::new(dir)
                    .max_depth(scan_depth)
                    .into_iter()
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().is_dir() && e.path().extension().map_or(false, |ext| ext == "app"))
                    .collect();
                all_app_dirs.extend(app_dirs);
            }
        }
        let total_apps = all_app_dirs.len();
        let mut scanned_count = 0;

        let start_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: format!("Scanning {} app directories in {} locations using {} threads", total_apps, total_dirs, concurrency_limit),
        };
        let _ = progress_sender.send(start_msg).await;

        let mut futs = FuturesUnordered::new();
        for entry in all_app_dirs {
            let app_path = entry.path().to_path_buf();
            let app_name = app_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Unknown")
                .to_string();
            let progress_sender = progress_sender.clone();
            let semaphore = semaphore.clone();
            let seen_paths = _seen_paths.clone();
            futs.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                // Avoid duplicates
                let mut seen = seen_paths.lock().await;
                if !seen.insert(app_path.clone()) {
                    return None;
                }
                drop(seen);
                // Send progress update
                let progress_msg = LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Info,
                    message: format!("Scanning: {}", app_name),
                };
                let _ = progress_sender.send(progress_msg).await;
                // Skip system apps
                if FileOperations::is_system_app(&app_name) {
                    return None;
                }
                // Analyze the app
                match FileOperations::analyze_app(&app_path).await {
                    Ok(Some(app_info)) => Some(app_info),
                    _ => None,
                }
            }));
        }
        while let Some(res) = futs.next().await {
            scanned_count += 1;
            let progress_msg = LogMessage {
                timestamp: chrono::Utc::now(),
                level: LogLevel::Info,
                message: format!("PROGRESS:{}/{}", scanned_count, total_apps),
            };
            let _ = progress_sender.send(progress_msg).await;
            if let Ok(Some(app_info)) = res {
                // Apply filters
                let universal_filter = !show_only_universal || app_info.app_type == AppType::Universal;
                let appstore_filter = !show_only_appstore || app_info.app_source == AppSource::AppStore;
                
                if universal_filter && appstore_filter {
                    apps.push(app_info);
                }
            }
        }
        let completion_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Success,
            message: format!("Scan completed. Found {} applications", apps.len()),
        };
        let _ = progress_sender.send(completion_msg).await;
        // Send the apps list as a special message
        let apps_msg = LogMessage {
            timestamp: chrono::Utc::now(),
            level: LogLevel::Info,
            message: format!("APPS_LIST:{}", serde_json::to_string(&apps).unwrap_or_default()),
        };
        let _ = progress_sender.send(apps_msg).await;
        Ok(())
    }

    /// Detect the source of an app by checking ownership
    pub async fn detect_app_source(app_path: &Path) -> Result<AppSource> {
        // Get the metadata of the .app folder
        let metadata = tokio::fs::metadata(app_path).await
            .context("Failed to get app metadata")?;
        
        let uid = metadata.uid();
        
        // On macOS:
        // - UID 0 (root) typically means system apps
        // - UID 501 (first user) typically means user-installed apps
        // - UID 502+ typically means other users or App Store apps
        
        // Check if it's in /Applications (system-wide) or ~/Applications (user-specific)
        let is_system_applications = app_path.starts_with("/Applications");
        let is_user_applications = app_path.starts_with(&format!("{}/Applications", std::env::var("HOME").unwrap_or_default()));
        
        // Additional check for App Store apps: they often have specific ownership patterns
        // and are typically in /Applications with non-root ownership
        if is_system_applications && uid != 0 {
            // Check if it has App Store receipt
            let receipt_path = app_path.join("Contents/_MASReceipt");
            if receipt_path.exists() {
                return Ok(AppSource::AppStore);
            }
            
            // Check if it's owned by the current user (likely user-installed)
            let current_uid = unsafe { libc::getuid() };
            if uid == current_uid {
                return Ok(AppSource::UserInstalled);
            }
            
            // If it's in /Applications but not owned by root and not by current user,
            // it's likely an App Store app
            return Ok(AppSource::AppStore);
        } else if is_user_applications {
            return Ok(AppSource::UserInstalled);
        } else if uid == 0 {
            return Ok(AppSource::System);
        }
        
        Ok(AppSource::Unknown)
    }
}

fn get_system_architecture() -> String {
    #[cfg(target_arch = "x86_64")]
    return "x86_64".to_string();
    
    #[cfg(target_arch = "aarch64")]
    return "arm64".to_string();
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return "unknown".to_string();
} 