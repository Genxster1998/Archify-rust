/*
 * Archify Rust - App Logic
 * Copyright (C) 2025 Genxster1998
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

use crate::file_operations::FileOperations;
use crate::types::{AppInfo, LogLevel, LogMessage, ProcessingConfig, BatchProcessingConfig, AppSource};
use eframe::egui;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;
use rfd::FileDialog;
use crate::privileged_helper::{PrivilegedHelper, HelperStatus};
use std::sync::OnceLock;
use image;



// Global runtime for the GUI app
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

pub struct ArchifyApp {
    selected_tab: usize,
    pub apps: Vec<AppInfo>,
    pub selected_apps: Vec<PathBuf>,
    pub processing_config: ProcessingConfig,
    pub batch_config: BatchProcessingConfig,
    pub logs: Vec<LogMessage>,
    pub is_processing: bool,
    pub is_scanning: bool,
    pub show_only_universal: bool,
    pub show_only_appstore: bool,
    pub progress: f32,
    pub progress_phase: String,
    pub total_apps_found: usize,
    pub current_scanning_app: String,
    scan_sender: Option<mpsc::Sender<LogMessage>>,
    scan_receiver: Option<mpsc::Receiver<LogMessage>>,
    pub manual_selected_apps: Vec<PathBuf>,
    pub custom_scan_dirs: Vec<PathBuf>,
    pub scan_depth: usize,
    // Elevated permission dialog state
    pub show_elevated_dialog: bool,
    pub elevated_apps: Vec<PathBuf>,
    pub user_apps: Vec<PathBuf>,
    pub elevated_confirmed: bool,
    // Helper status
    pub helper_status: HelperStatus,
    pub show_helper_install_dialog: bool,
    pub helper_log_receiver: Option<mpsc::Receiver<LogMessage>>,
    pub processing_log_receiver: Option<mpsc::Receiver<LogMessage>>,
    // Success dialog state
    pub show_success_dialog: bool,
    pub success_message: String,
    pub was_processing: bool,
    pub processing_start_time: Option<std::time::Instant>,
    // Icon texture cache for About tab
    pub about_icon_texture: Option<egui::TextureHandle>,
    pub about_gpl_texture: Option<egui::TextureHandle>,
}

impl ArchifyApp {
    pub fn new() -> Self {
        // Initialize the global runtime if not already done
        let _runtime = RUNTIME.get_or_init(|| {
            Runtime::new().expect("Failed to create Tokio runtime")
        });
        

        
        Self {
            selected_tab: 0,
            apps: Vec::new(),
            selected_apps: Vec::new(),
            processing_config: ProcessingConfig {
                target_architecture: "x86_64".to_string(),
                no_sign: true,
                no_entitlements: false,
                use_codesign: false,
                output_directory: None,
            },
            batch_config: BatchProcessingConfig {
                processing_config: ProcessingConfig {
                    target_architecture: "x86_64".to_string(),
                    no_sign: true,
                    no_entitlements: false,
                    use_codesign: false,
                    output_directory: None,
                },
                save_logs_to_file: false,
                parallel_processing: true,
                max_parallel_jobs: 4,
            },
            logs: Vec::new(),
            is_processing: false,
            is_scanning: false,
            show_only_universal: false,
            show_only_appstore: false,
            progress: 0.0,
            progress_phase: String::new(),
            total_apps_found: 0,
            current_scanning_app: String::new(),
            scan_sender: None,
            scan_receiver: None,
            manual_selected_apps: Vec::new(),
            custom_scan_dirs: Vec::new(),
            scan_depth: 2,
            // Elevated permission dialog state
            show_elevated_dialog: false,
            elevated_apps: Vec::new(),
            user_apps: Vec::new(),
            elevated_confirmed: false,
            // Helper status
            helper_status: HelperStatus {
                is_installed: false,
                is_running: false,
                version: None,
                error: None,
            },
            show_helper_install_dialog: false,
            helper_log_receiver: None,
            processing_log_receiver: None,
            // Success dialog state
            show_success_dialog: false,
            success_message: String::new(),
            was_processing: false,
            processing_start_time: None,
            // Icon texture cache for About tab
            about_icon_texture: None,
            about_gpl_texture: None,
        }
    }

    pub fn scan_applications(&mut self) {
        if self.is_scanning {
            return; // Already scanning
        }

        self.is_scanning = true;
        self.progress = 0.0;
        self.progress_phase = "Scanning applications...".to_string();
        self.total_apps_found = 0;
        self.current_scanning_app.clear();
        self.apps.clear();
        self.selected_apps.clear();

        let (tx, rx) = mpsc::channel(100);
        self.scan_sender = Some(tx.clone());
        self.scan_receiver = Some(rx);
        
        let runtime = RUNTIME.get().expect("Runtime not initialized");
        let show_only_universal = self.show_only_universal;
        let show_only_appstore = self.show_only_appstore;
        let mut scan_dirs = vec![PathBuf::from("/Applications")];
        scan_dirs.extend(self.custom_scan_dirs.iter().cloned());
        let scan_depth = self.scan_depth;

        // Spawn the scanning task
        runtime.spawn(async move {
            if let Err(e) = FileOperations::scan_applications_async_multi(scan_dirs, show_only_universal, show_only_appstore, scan_depth, tx.clone()).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Failed to scan applications: {}", e),
                }).await;
            }
        });
    }

    pub fn handle_scanning_messages(&mut self) {
        if !self.is_scanning && !self.is_processing {
            return;
        }

        if let Some(ref mut rx) = self.scan_receiver {
            while let Ok(log) = rx.try_recv() {
                // Handle progress bar update
                if log.message.starts_with("PROGRESS:") {
                    if self.is_scanning {
                        self.progress_phase = "Scanning applications...".to_string();
                    } else if self.is_processing {
                        self.progress_phase = "Processing apps...".to_string();
                    }
                    if let Some(progress_str) = log.message.strip_prefix("PROGRESS:") {
                        let parts: Vec<&str> = progress_str.split('/').collect();
                        if parts.len() == 2 {
                            if let (Ok(done), Ok(total)) = (parts[0].parse::<usize>(), parts[1].parse::<usize>()) {
                                self.progress = if total > 0 { done as f32 / total as f32 } else { 0.0 };
                            }
                        }
                    }
                    continue; // Don't add this to logs
                }
                // Check if this is a special apps list message
                if log.message.starts_with("APPS_LIST:") {
                    if let Some(apps_json) = log.message.strip_prefix("APPS_LIST:") {
                        if let Ok(apps) = serde_json::from_str::<Vec<AppInfo>>(apps_json) {
                            self.apps = apps;
                            self.is_scanning = false;
                            self.scan_sender = None;
                            self.scan_receiver = None;
                            self.progress = 1.0;
                            self.progress_phase.clear();
                            return;
                        }
                    }
                }
                self.logs.push(log);
            }
        }
    }

    pub fn process_selected_apps(&mut self) {
        if self.selected_apps.is_empty() {
            self.add_log(LogLevel::Warning, "No applications selected for processing".to_string());
            return;
        }

        // Categorize apps by permission requirements
        self.categorize_apps_by_permissions();
        
        // If there are elevated apps, show the dialog
        if !self.elevated_apps.is_empty() {
            self.show_elevated_dialog = true;
            return;
        }
        
        // Process user apps normally
        self.process_apps_with_permissions(self.user_apps.clone(), false);
    }

    fn categorize_apps_by_permissions(&mut self) {
        self.elevated_apps.clear();
        self.user_apps.clear();
        
        for app_path in &self.selected_apps {
            if let Some(app_info) = self.apps.iter().find(|a| &a.path == app_path) {
                match app_info.app_source {
                    AppSource::AppStore | AppSource::System => {
                        self.elevated_apps.push(app_path.clone());
                    }
                    AppSource::UserInstalled | AppSource::Unknown => {
                        self.user_apps.push(app_path.clone());
                    }
                }
            }
        }
    }

    fn process_apps_with_permissions(&mut self, apps: Vec<PathBuf>, elevated: bool) {
        if apps.is_empty() {
            return;
        }

        self.is_processing = true;
        self.was_processing = true;
        self.processing_start_time = Some(std::time::Instant::now());
        self.logs.clear();

        // Update batch config with current processing config
        self.batch_config.processing_config = self.processing_config.clone();

        let (tx, rx) = mpsc::channel(100);
        self.processing_log_receiver = Some(rx);
        let config = self.batch_config.clone();
        let elevated_apps = if elevated { apps.clone() } else { Vec::new() };

        let runtime = RUNTIME.get().expect("Runtime not initialized");
        runtime.spawn(async move {
            if let Err(e) = FileOperations::batch_process_apps_with_permissions(apps, &config, tx.clone(), elevated_apps).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Batch processing failed: {}", e),
                }).await;
            }
        });

        self.is_processing = false;
        let permission_type = if elevated { "elevated" } else { "user" };
        self.add_log(LogLevel::Info, format!("{} processing completed", permission_type));
    }

    pub fn confirm_elevated_processing(&mut self) {
        self.show_elevated_dialog = false;
        self.elevated_confirmed = true;

        if !self.elevated_apps.is_empty() {
            if !PrivilegedHelper::is_installed() {
                let rt = RUNTIME.get().expect("Runtime not initialized").handle().clone();
                rt.spawn(async move {
                    if let Err(e) = PrivilegedHelper::install_helper().await {
                        eprintln!("Failed to install privileged helper: {}", e);
                    }
                });
                self.add_log(LogLevel::Warning, "Installing privileged helper...".to_string());
            } else {
                // Set processing flags for success dialog
                self.is_processing = true;
                self.was_processing = true;
                self.processing_start_time = Some(std::time::Instant::now());
                
                let (log_tx, log_rx) = mpsc::channel(100);
                self.helper_log_receiver = Some(log_rx);
                
                let elevated_apps_count = self.elevated_apps.len();
                let (completion_tx, mut completion_rx) = mpsc::channel(100);
                
                for app_path in &self.elevated_apps {
                    let app_path = app_path.clone();
                    let config = self.processing_config.clone();
                    let log_tx = log_tx.clone();
                    let completion_tx = completion_tx.clone();
                    let rt = RUNTIME.get().expect("Runtime not initialized").handle().clone();
                    rt.spawn(async move {
                        match PrivilegedHelper::thin_app(
                            &app_path,
                            &config.target_architecture,
                            config.no_sign,
                            config.no_entitlements,
                            config.use_codesign,
                        ).await {
                            Ok((status, log_lines)) => {
                                // Print summary to terminal
                                println!("Successfully thinned {}: {}", app_path.display(), status);
                                let _ = log_tx.send(LogMessage {
                                    timestamp: chrono::Utc::now(),
                                    level: LogLevel::Info,
                                    message: format!("Successfully thinned {}: {}", app_path.display(), status),
                                }).await;
                                for line in log_lines {
                                    let _ = log_tx.send(LogMessage {
                                        timestamp: chrono::Utc::now(),
                                        level: LogLevel::Info,
                                        message: line,
                                    }).await;
                                }
                            }
                            Err(e) => {
                                // Print summary to terminal
                                eprintln!("Failed to thin {}: {}", app_path.display(), e);
                                let _ = log_tx.send(LogMessage {
                                    timestamp: chrono::Utc::now(),
                                    level: LogLevel::Error,
                                    message: format!("Failed to thin {}: {}", app_path.display(), e),
                                }).await;
                            }
                        }
                        
                        // Signal completion
                        let _ = completion_tx.send(()).await;
                    });
                }
                
                // Spawn a task to send completion message when all apps are done
                let log_tx_final = log_tx.clone();
                let rt_final = RUNTIME.get().expect("Runtime not initialized").handle().clone();
                rt_final.spawn(async move {
                    let mut completed = 0;
                    while let Some(_) = completion_rx.recv().await {
                        completed += 1;
                        if completed >= elevated_apps_count {
                            let _ = log_tx_final.send(LogMessage {
                                timestamp: chrono::Utc::now(),
                                level: LogLevel::Success,
                                message: "Elevated processing completed".to_string(),
                            }).await;
                            break;
                        }
                    }
                });
                drop(log_tx);
            }
        }
        self.process_apps_with_permissions(self.user_apps.clone(), false);
        self.elevated_apps.clear();
        self.user_apps.clear();
        self.elevated_confirmed = false;
    }

    pub fn cancel_elevated_processing(&mut self) {
        self.show_elevated_dialog = false;
        self.elevated_apps.clear();
        self.user_apps.clear();
        self.elevated_confirmed = false;
    }

    fn process_manual_selected_apps(&mut self) {
        if self.manual_selected_apps.is_empty() {
            self.add_log(LogLevel::Warning, "No applications selected for processing".to_string());
            return;
        }

        self.is_processing = true;
        self.was_processing = true;
        self.processing_start_time = Some(std::time::Instant::now());
        self.logs.clear();

        // Update batch config with current processing config
        self.batch_config.processing_config = self.processing_config.clone();

        let (tx, mut rx) = mpsc::channel(100);
        let config = self.batch_config.clone();
        let selected_apps = self.manual_selected_apps.clone();

        let runtime = RUNTIME.get().expect("Runtime not initialized");
        runtime.spawn(async move {
            if let Err(e) = FileOperations::batch_process_apps(selected_apps, &config, tx.clone()).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Manual thinning failed: {}", e),
                }).await;
            }
        });

        // Handle log messages
        while let Ok(log) = rx.try_recv() {
            self.logs.push(log);
        }

        self.is_processing = false;
        self.add_log(LogLevel::Info, "Manual thinning completed".to_string());
    }

    fn add_log(&mut self, level: LogLevel, message: String) {
        self.logs.push(LogMessage {
            timestamp: chrono::Utc::now(),
            level,
            message,
        });
    }

    fn analyze_processing_results(&self) -> (Vec<(String, String)>, u64) {
        let mut failed_apps = Vec::new();
        let mut total_saved = 0u64;
        
        // Look for failure patterns in logs
        for log in &self.logs {
            // Extract saved space
            if log.message.contains("saved") && log.message.contains("bytes") {
                if let Some(saved_str) = log.message.split_whitespace()
                    .find(|word| word.parse::<u64>().is_ok()) {
                    if let Ok(saved) = saved_str.parse::<u64>() {
                        total_saved += saved;
                    }
                }
            }
            
            // Look for app failure patterns
            if matches!(log.level, LogLevel::Error) {
                let message = &log.message;
                
                // Pattern 1: "Failed to thin {app_path}: {reason}"
                if message.contains("Failed to thin") {
                    if let Some(app_part) = message.strip_prefix("Failed to thin ") {
                        if let Some((app_path, reason)) = app_part.split_once(": ") {
                            let app_name = std::path::Path::new(app_path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("Unknown App")
                                .to_string();
                            failed_apps.push((app_name, reason.to_string()));
                        }
                    }
                }
                
                // Pattern 2: "Failed to process {app_path}: {reason}"
                else if message.contains("Failed to process") {
                    if let Some(app_part) = message.strip_prefix("Failed to process ") {
                        if let Some((app_path, reason)) = app_part.split_once(": ") {
                            let app_name = std::path::Path::new(app_path)
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("Unknown App")
                                .to_string();
                            failed_apps.push((app_name, reason.to_string()));
                        }
                    }
                }
                
                // Pattern 3: "Processing failed: {reason}" (general failure)
                else if message.contains("Processing failed:") {
                    if let Some(reason) = message.strip_prefix("Processing failed: ") {
                        failed_apps.push(("Unknown App".to_string(), reason.to_string()));
                    }
                }
                
                // Pattern 4: "Batch processing failed: {reason}" (general failure)
                else if message.contains("Batch processing failed:") {
                    if let Some(reason) = message.strip_prefix("Batch processing failed: ") {
                        failed_apps.push(("Batch Processing".to_string(), reason.to_string()));
                    }
                }
                
                // Pattern 5: "Manual thinning failed: {reason}" (general failure)
                else if message.contains("Manual thinning failed:") {
                    if let Some(reason) = message.strip_prefix("Manual thinning failed: ") {
                        failed_apps.push(("Manual Thinning".to_string(), reason.to_string()));
                    }
                }
                
                // Pattern 6: App Store protection messages
                else if message.contains("App Store app has protections") {
                    // Try to extract app name from context
                    let app_name = if let Some(prev_log) = self.logs.iter().rev().find(|l| 
                        l.message.contains("Processing") && !l.message.contains("failed")
                    ) {
                        // Extract app name from previous log if available
                        if prev_log.message.contains("/") {
                            let path_parts: Vec<&str> = prev_log.message.split('/').collect();
                            if let Some(last_part) = path_parts.last() {
                                if last_part.contains(".app") {
                                    last_part.to_string()
                                } else {
                                    "App Store App".to_string()
                                }
                            } else {
                                "App Store App".to_string()
                            }
                        } else {
                            "App Store App".to_string()
                        }
                    } else {
                        "App Store App".to_string()
                    };
                    failed_apps.push((app_name, "App Store protections prevent modification".to_string()));
                }
                
                // Pattern 7: Permission denied errors
                else if message.contains("Permission denied") || message.contains("permission denied") {
                    failed_apps.push(("System App".to_string(), "Permission denied - requires elevated privileges".to_string()));
                }
                
                // Pattern 8: File not found errors
                else if message.contains("No such file") || message.contains("not found") {
                    failed_apps.push(("Unknown App".to_string(), "File not found or inaccessible".to_string()));
                }
                
                // Pattern 9: Generic error messages
                else if message.contains("error") || message.contains("Error") {
                    // Try to extract a meaningful error message
                    let error_msg = if message.len() > 100 {
                        format!("{}...", &message[..100])
                    } else {
                        message.to_string()
                    };
                    failed_apps.push(("Unknown App".to_string(), error_msg));
                }
            }
        }
        
        // Remove duplicates and sort
        failed_apps.sort();
        failed_apps.dedup();
        
        (failed_apps, total_saved)
    }

    fn update_helper_status(&mut self) {
        self.helper_status = PrivilegedHelper::get_helper_status();
        }

    pub fn handle_helper_logs(&mut self, ctx: &egui::Context) {
        if let Some(ref mut rx) = self.helper_log_receiver {
            while let Ok(log) = rx.try_recv() {
                self.logs.push(log.clone());
                // Check for helper thinning success log
                if log.message.contains("Successfully thinned") && log.message.contains(": OK") {
                    // Show success dialog for helper thinning
                    self.show_success_dialog = true;
                    self.was_processing = false;
                    self.processing_start_time = None;
                    let msg = if let Some(start) = log.message.find('/') {
                        if let Some(end) = log.message.find(": OK") {
                            let app_path = &log.message[start..end];
                            format!("✅ Successfully thinned {}!", app_path)
                        } else {
                            "✅ Helper-based thinning completed successfully!".to_string()
                        }
                    } else {
                        "✅ Helper-based thinning completed successfully!".to_string()
                    };
                    self.success_message = msg;
                    ctx.request_repaint();
                }
            }
            
            // Check if helper processing is complete
            if self.was_processing && !self.is_processing {
                let has_completion_message = self.logs.iter().any(|log| {
                    log.message.contains("Elevated processing completed") ||
                    log.message.contains("processing completed") || 
                    log.message.contains("thinning completed") ||
                    log.message.contains("Batch processing completed")
                });
                
                let has_error_message = self.logs.iter().any(|log| {
                    matches!(log.level, LogLevel::Error) && 
                    (log.message.contains("failed") || log.message.contains("error"))
                });
                
                // Check for timeout (5 seconds after processing started)
                let timeout_elapsed = if let Some(start_time) = self.processing_start_time {
                    start_time.elapsed().as_secs() > 5
                } else {
                    false
                };
                
                if has_completion_message || has_error_message || timeout_elapsed {
                    self.show_success_dialog = true;
                    self.was_processing = false;
                    self.processing_start_time = None;
                    
                    if has_error_message {
                        // Analyze failures and generate detailed message
                        let (failed_apps, total_saved) = self.analyze_processing_results();
                        
                        if failed_apps.is_empty() {
                            // No specific app failures, just general errors
                            self.success_message = "⚠️ Binary thinning completed with some errors.\n\nPlease check the logs tab for details.".to_string();
                        } else {
                            // Build detailed failure message
                            let mut message = format!("⚠️ Binary thinning completed with {} app(s) failed.\n\n", failed_apps.len());
                            
                            for (app_name, reason) in &failed_apps {
                                message.push_str(&format!("• {}: {}\n", app_name, reason));
                            }
                            
                            if total_saved > 0 {
                                message.push_str(&format!("\n✅ Total space saved: {}", FileOperations::human_readable_size(total_saved, 2)));
                            }
                            
                            message.push_str("\n\n💡 Tip: Check the Logs tab for detailed information about each failure.");
                            
                            self.success_message = message;
                        }
                    } else if timeout_elapsed && !has_completion_message {
                        self.success_message = "✅ Binary thinning appears to have completed.\n\nProcessing may have finished in the background.".to_string();
                    } else {
                        // Calculate total saved space from logs
                        let mut total_saved = 0u64;
                        for log in &self.logs {
                            if log.message.contains("saved") && log.message.contains("bytes") {
                                // Try to extract saved space from log messages
                                if let Some(saved_str) = log.message.split_whitespace()
                                    .find(|word| word.parse::<u64>().is_ok()) {
                                    if let Ok(saved) = saved_str.parse::<u64>() {
                                        total_saved += saved;
                                    }
                                }
                            }
                        }
                        
                        if total_saved > 0 {
                            self.success_message = format!(
                                "✅ Binary thinning completed successfully!\n\nTotal space saved: {}",
                                FileOperations::human_readable_size(total_saved, 2)
                            );
                        } else {
                            self.success_message = "✅ Binary thinning completed successfully!".to_string();
                        }
                    }
                }
            }
        }
    }

    pub fn handle_processing_logs(&mut self) {
        if let Some(ref mut rx) = self.processing_log_receiver {
            while let Ok(log) = rx.try_recv() {
                self.logs.push(log);
            }
            
            // Check if processing is complete by looking for completion messages
            if self.was_processing && !self.is_processing {
                let has_completion_message = self.logs.iter().any(|log| {
                    log.message.contains("processing completed") || 
                    log.message.contains("thinning completed") ||
                    log.message.contains("Batch processing completed")
                });
                
                let has_error_message = self.logs.iter().any(|log| {
                    matches!(log.level, LogLevel::Error) && 
                    (log.message.contains("failed") || log.message.contains("error"))
                });
                
                // Check for timeout (5 seconds after processing started)
                let timeout_elapsed = if let Some(start_time) = self.processing_start_time {
                    start_time.elapsed().as_secs() > 5
                } else {
                    false
                };
                
                if has_completion_message || has_error_message || timeout_elapsed {
                    self.show_success_dialog = true;
                    self.was_processing = false;
                    self.processing_start_time = None;
                    
                    if has_error_message {
                        // Analyze failures and generate detailed message
                        let (failed_apps, total_saved) = self.analyze_processing_results();
                        
                        if failed_apps.is_empty() {
                            // No specific app failures, just general errors
                            self.success_message = "⚠️ Binary thinning completed with some errors.\n\nPlease check the logs tab for details.".to_string();
                        } else {
                            // Build detailed failure message
                            let mut message = format!("⚠️ Binary thinning completed with {} app(s) failed.\n\n", failed_apps.len());
                            
                            for (app_name, reason) in &failed_apps {
                                message.push_str(&format!("• {}: {}\n", app_name, reason));
                            }
                            
                            if total_saved > 0 {
                                message.push_str(&format!("\n✅ Total space saved: {}", FileOperations::human_readable_size(total_saved, 2)));
                            }
                            
                            message.push_str("\n\n💡 Tip: Check the Logs tab for detailed information about each failure.");
                            
                            self.success_message = message;
                        }
                    } else if timeout_elapsed && !has_completion_message {
                        self.success_message = "✅ Binary thinning appears to have completed.\n\nProcessing may have finished in the background.".to_string();
                    } else {
                        // Calculate total saved space from logs
                        let mut total_saved = 0u64;
                        for log in &self.logs {
                            if log.message.contains("saved") && log.message.contains("bytes") {
                                // Try to extract saved space from log messages
                                if let Some(saved_str) = log.message.split_whitespace()
                                    .find(|word| word.parse::<u64>().is_ok()) {
                                    if let Ok(saved) = saved_str.parse::<u64>() {
                                        total_saved += saved;
                                    }
                                }
                            }
                        }
                        
                        if total_saved > 0 {
                            self.success_message = format!(
                                "✅ Binary thinning completed successfully!\n\nTotal space saved: {}",
                                FileOperations::human_readable_size(total_saved, 2)
                            );
                        } else {
                            self.success_message = "✅ Binary thinning completed successfully!".to_string();
                        }
                    }
                }
            }
        }
    }

    fn render_applications_tab(&mut self, ui: &mut egui::Ui) {
        
        use egui::RichText;
        use egui::Color32;
        // Main content (everything except status bar)
        egui::TopBottomPanel::bottom("status_bar_panel").show_inside(ui, |ui| {
            let selected_apps: Vec<_> = self.apps.iter().filter(|a| self.selected_apps.contains(&a.path)).collect();
            let selected_count = selected_apps.len();
            let total_size: u64 = selected_apps.iter().map(|a| a.total_size).sum();
            let savable_size: u64 = selected_apps.iter().map(|a| a.savable_size).sum();
            ui.add_space(2.0);
            //ui.separator();
            ui.horizontal(|ui| {
                ui.label(RichText::new("Selected:").size(13.0));
                ui.label(RichText::new(format!("{} app(s)", selected_count)).size(13.0).color(Color32::from_rgb(52, 152, 219)));
                ui.separator();
                ui.label(RichText::new("Total Size:").size(13.0));
                ui.label(RichText::new(crate::file_operations::FileOperations::human_readable_size(total_size, 2)).size(13.0).color(Color32::YELLOW));
                ui.separator();
                ui.label(RichText::new("Savable:").size(13.0));
                ui.label(RichText::new(crate::file_operations::FileOperations::human_readable_size(savable_size, 2)).size(13.0).color(Color32::GREEN));
            });
            ui.add_space(2.0);
        });
        ui.horizontal(|ui| {
            if ui.button("Scan Applications").clicked() && !self.is_scanning {
                self.scan_applications();
            }
            if ui.button("Process Selected").clicked() && !self.is_processing && !self.is_scanning {
                self.process_selected_apps();
            }
            if self.is_scanning {
                ui.label("Scanning...");
            }
            if self.is_processing {
                ui.label("Processing...");
            }
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_only_universal, "Show only universal binaries");
            if self.show_only_universal {
                ui.label("(Filtering universal binaries only)");
            }
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_only_appstore, "Show only App Store apps");
            if self.show_only_appstore {
                ui.label("(Filtering App Store apps only)");
            }
        });
        ui.separator();
        // Select All checkbox
        let filtered_apps: Vec<_> = self.apps.iter().filter(|a| {
            let universal_filter = !self.show_only_universal || a.app_type == crate::types::AppType::Universal;
            let appstore_filter = !self.show_only_appstore || a.app_source == crate::types::AppSource::AppStore;
            universal_filter && appstore_filter
        }).collect();
        if !filtered_apps.is_empty() {
            let all_selected = filtered_apps.iter().all(|a| self.selected_apps.contains(&a.path));
            let mut select_all = all_selected;
            if ui.checkbox(&mut select_all, "Select All").clicked() {
                if select_all {
                    for app_info in filtered_apps {
                        if !self.selected_apps.contains(&app_info.path) {
                            self.selected_apps.push(app_info.path.clone());
                        }
                    }
                } else {
                    self.selected_apps.retain(|p| {
                        !filtered_apps.iter().any(|a| &a.path == p)
                    });
                }
            }
        }
        if self.is_scanning {
            ui.label(format!("Scanning applications... {}", self.current_scanning_app));
            ui.add(egui::ProgressBar::new(self.progress).show_percentage());
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            for app_info in self.apps.iter().filter(|a| {
                let universal_filter = !self.show_only_universal || a.app_type == crate::types::AppType::Universal;
                let appstore_filter = !self.show_only_appstore || a.app_source == crate::types::AppSource::AppStore;
                universal_filter && appstore_filter
            }) {
                let mut selected = self.selected_apps.contains(&app_info.path);
                if ui.checkbox(&mut selected, &format!("{}", app_info.name)).clicked() {
                    if selected {
                        self.selected_apps.push(app_info.path.clone());
                    } else {
                        self.selected_apps.retain(|p| p != &app_info.path);
                    }
                }
                ui.label(&format!("Type: {:?}", app_info.app_type));
                ui.label(&format!("Source: {}", app_info.app_source));
                ui.label(&format!("Size: {}", FileOperations::human_readable_size(app_info.total_size, 2)));
                ui.label(&format!("Estimated Savable: {}", FileOperations::human_readable_size(app_info.savable_size, 2)));
                if let Some(saved) = crate::types::ProcessingState::default().saved_spaces.get(&app_info.name) {
                    ui.label(&format!("Actual Saved: {}", FileOperations::human_readable_size(*saved, 2)));
                }
                ui.label(&format!("Architectures: {:?}", app_info.architectures));
                ui.separator();
            }
        });
    }
    
    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        
        ui.label("Target Architecture:");
        ui.text_edit_singleline(&mut self.processing_config.target_architecture);
        
        ui.checkbox(&mut self.processing_config.no_sign, "Don't sign binaries");
        ui.checkbox(&mut self.processing_config.no_entitlements, "Don't preserve entitlements");
        ui.checkbox(&mut self.processing_config.use_codesign, "Use codesign instead of ldid");
        
        ui.separator();
        ui.heading("App Store Apps");
        
        ui.label("Note: App Store apps have additional protections that may prevent modification.");
        ui.label("Admin privileges may be required to modify some App Store apps.");
        ui.label("The app will attempt to process App Store apps, but some may fail due to system protections.");
        
        ui.separator();
        ui.heading("Batch Processing Options");
        ui.checkbox(&mut self.batch_config.save_logs_to_file, "Save logs to file");
        ui.checkbox(&mut self.batch_config.parallel_processing, "Enable parallel processing");
        if self.batch_config.parallel_processing {
            ui.label("Max Parallel Jobs:");
            ui.add(egui::Slider::new(&mut self.batch_config.max_parallel_jobs, 1..=8));
        }
        ui.label("Note: All batch processing is in-place. The original app will be modified.");

        ui.separator();
        ui.heading("Batch App Scan Locations");
        ui.label("Default: /Applications");
        let mut remove_indices = Vec::new();
        for (i, dir) in self.custom_scan_dirs.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(dir.display().to_string());
                if ui.button("Remove").clicked() {
                    remove_indices.push(i);
                }
            });
        }
        // Remove after iteration to avoid borrow checker issues
        for &i in remove_indices.iter().rev() {
            self.custom_scan_dirs.remove(i);
        }
        if ui.button("Add Directory...").clicked() {
            if let Some(dir) = FileDialog::new()
                .set_directory(std::env::current_dir().unwrap_or_default())
                .pick_folder() {
                if !self.custom_scan_dirs.contains(&dir) {
                    self.custom_scan_dirs.push(dir);
                }
            }
        }
        ui.horizontal(|ui| {
            ui.label("Scan Depth:");
            ui.add(egui::Slider::new(&mut self.scan_depth, 1..=8));
        });

        ui.separator();
        ui.heading("Privileged Helper");
        
        // Update helper status
        self.update_helper_status();
        
        // Display helper status
        ui.label("Helper Status:");
        if self.helper_status.is_installed {
            ui.colored_label(egui::Color32::GREEN, "✓ Installed");
            if self.helper_status.is_running {
                ui.colored_label(egui::Color32::GREEN, "✓ Running");
            } else {
                ui.colored_label(egui::Color32::YELLOW, "⚠ Not Running");
            }
            if let Some(version) = &self.helper_status.version {
                ui.label(format!("Version: {}", version));
            }
        } else {
            ui.colored_label(egui::Color32::RED, "✗ Not Installed");
            if let Some(error) = &self.helper_status.error {
                ui.colored_label(egui::Color32::RED, format!("Error: {}", error));
            }
        }
        
        ui.separator();
        
        // Helper management buttons
        ui.horizontal(|ui| {
            if ui.button("Install Helper").clicked() {
                self.show_helper_install_dialog = true;
            }
            
            if self.helper_status.is_installed && ui.button("Uninstall Helper").clicked() {
                let runtime = RUNTIME.get().expect("Runtime not initialized");
                runtime.spawn(async {
                    if let Err(e) = PrivilegedHelper::uninstall_helper().await {
                        eprintln!("Failed to uninstall helper: {}", e);
                    }
                });
            }
        });
        
        if self.show_helper_install_dialog {
            egui::Window::new("Install Privileged Helper")
                .collapsible(false)
                .resizable(false)
                .show(ui.ctx(), |ui| {
                    ui.heading("Install Privileged Helper");
                    ui.label("The privileged helper is required to thin applications that require elevated permissions.");
                    ui.label("This will install a system service that runs with root privileges.");
                    ui.separator();
                    ui.label("⚠️ Security Note:");
                    ui.label("• The helper will be installed in /Library/PrivilegedHelperTools/");
                    ui.label("• It will run as a system service with root privileges");
                    ui.label("• You will be prompted for your administrator password");
                    ui.separator();
                    
                    ui.horizontal(|ui| {
                        if ui.button("Install").clicked() {
                            let runtime = RUNTIME.get().expect("Runtime not initialized");
                            runtime.spawn(async {
                                if let Err(e) = PrivilegedHelper::install_helper().await {
                                    eprintln!("Failed to install helper: {}", e);
                                }
                            });
                            self.show_helper_install_dialog = false;
                        }
                        
                        if ui.button("Cancel").clicked() {
                            self.show_helper_install_dialog = false;
                        }
                    });
                });
        }
    }
    
    fn render_logs_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Clear Logs").clicked() {
                self.logs.clear();
            }
        });
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            for log in &self.logs {
                let color = match log.level {
                    LogLevel::Info => egui::Color32::WHITE,
                    LogLevel::Warning => egui::Color32::YELLOW,
                    LogLevel::Error => egui::Color32::RED,
                    LogLevel::Success => egui::Color32::GREEN,
                };
                
                ui.colored_label(color, &log.message);
            }
        });
    }

    fn render_manual_thinning_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Manual Thinning");
        ui.label("Select one or more .app bundles from any location to thin in-place.");
        if ui.button("Select .app Bundles...").clicked() {
            if let Some(paths) = FileDialog::new()
                .set_directory(std::env::current_dir().unwrap_or_default())
                .pick_files() {
                // Only keep .app directories
                self.manual_selected_apps = paths
                    .into_iter()
                    .filter(|p| p.extension().map_or(false, |ext| ext == "app"))
                    .collect();
            }
        }
        if !self.manual_selected_apps.is_empty() {
            ui.label("Selected apps:");
            for path in &self.manual_selected_apps {
                ui.label(format!("- {}", path.display()));
            }
            if ui.button("Process Selected Apps").clicked() && !self.is_processing {
                self.process_manual_selected_apps();
            }
        }
    }

    fn render_about_tab(&mut self, ui: &mut egui::Ui) {
        // --- Texture loading section (no UI code here) ---
        let ctx = ui.ctx();
        let icon_bytes = include_bytes!("../assets/icon.png");
        if self.about_icon_texture.is_none() {
            if let Ok(image) = image::load_from_memory(icon_bytes) {
                let image = image.to_rgba8();
                let size = [image.width() as usize, image.height() as usize];
                let pixels = image.into_vec();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                let texture = ctx.load_texture(
                    "about_app_icon",
                    color_image,
                    egui::TextureOptions::default(),
                );
                self.about_icon_texture = Some(texture);
            }
        }
        let gpl_logo_bytes = include_bytes!("../assets/gpl.png");
        if self.about_gpl_texture.is_none() {
            if let Ok(image) = image::load_from_memory(gpl_logo_bytes) {
                let image = image.to_rgba8();
                let size = [image.width() as usize, image.height() as usize];
                let pixels = image.into_vec();
                let color_image = egui::ColorImage::from_rgba_unmultiplied(size, &pixels);
                let texture = ctx.load_texture(
                    "about_gpl_logo",
                    color_image,
                    egui::TextureOptions::default(),
                );
                self.about_gpl_texture = Some(texture);
            }
        }

        // --- Now do all your UI code here ---
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            // App icon with beautiful styling
            ui.add_space(10.0);
            if let Some(texture) = &self.about_icon_texture {
                ui.image((texture.id(), egui::Vec2::splat(64.0))); // Larger icon
            } else {
                ui.label(egui::RichText::new("📱")
                    .size(64.0)
                    .color(egui::Color32::from_rgb(52, 152, 219)));
            }
            ui.add_space(15.0);
            // App name with enhanced styling
            ui.heading(egui::RichText::new("Archify Rust")
                .size(32.0)
                .strong()
                .color(egui::Color32::from_rgb(52, 152, 219)));

            // Version with subtle styling
            ui.label(egui::RichText::new("v0.2.1")
                .size(18.0)
                .color(egui::Color32::from_rgb(149, 165, 166))
                .italics());
            ui.add_space(25.0);
            // Description in a beautiful frame
            ui.group(|ui| {
                ui.label(egui::RichText::new("A powerful macOS application for optimizing universal binaries by removing unnecessary architectures, helping you save disk space while maintaining compatibility with your target system.")
                    .size(14.0)
                    .color(egui::Color32::from_rgb(236, 240, 241))
                    .italics());
            });
            ui.add_space(30.0);
            // Developer section with enhanced styling
            ui.group(|ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("👨‍💻 Developer")
                        .size(14.0)
                        .color(egui::Color32::from_rgb(149, 165, 166))
                        .strong());
                    ui.label(egui::RichText::new("© 2025 Genxster1998")
                        .size(20.0)
                        .color(egui::Color32::from_rgb(52, 152, 219))
                        .strong());
                });
            });
            ui.add_space(20.0);
            // License section with GPL logo
            ui.group(|ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("📜 License")
                        .size(14.0)
                        .color(egui::Color32::from_rgb(149, 165, 166))
                        .strong());
                    if let Some(gpl_texture) = &self.about_gpl_texture {
                        // Get the original size to maintain aspect ratio
                        let size = gpl_texture.size();
                        let aspect_ratio = size[0] as f32 / size[1] as f32;
                        let display_width = 48.0;
                        let display_height = display_width / aspect_ratio;
                        ui.image((gpl_texture.id(), egui::Vec2::new(display_width, display_height)));
                    }
                    ui.label(egui::RichText::new("GNU General Public License v3.0")
                        .size(12.0)
                        .color(egui::Color32::from_rgb(149, 165, 166))
                        .italics());
                });
            });
            ui.add_space(20.0);
            // GitHub section with enhanced styling
            ui.group(|ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("🔗 Source Code")
                        .size(14.0)
                        .color(egui::Color32::from_rgb(149, 165, 166))
                        .strong());
                    ui.vertical_centered(|ui| {
                        ui.label(egui::RichText::new("🐙")
                            .size(24.0)
                            .color(egui::Color32::from_rgb(52, 152, 219)));
                        if ui.link(egui::RichText::new("GitHub Repository")
                            .size(18.0)
                            .color(egui::Color32::from_rgb(52, 152, 219))
                            .underline()
                            .strong()).clicked() {
                                // Open URL in default browser
                                let _ = std::process::Command::new("open")
                                    .arg("https://github.com/Genxster1998/Archify-rust")
                                    .output();
                            }
                    });
                    ui.label(egui::RichText::new("https://github.com/Genxster1998/Archify-rust")
                        .size(12.0)
                        .color(egui::Color32::from_rgb(149, 165, 166))
                        .italics());
                });
            });
            ui.add_space(20.0);
            // Footer with additional info
            ui.separator();
            ui.label(egui::RichText::new("Built with Rust and egui")
                .size(12.0)
                .color(egui::Color32::from_rgb(149, 165, 166))
                .italics());
        });
    }

    fn render_elevated_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Elevated Permissions Required")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("⚠️ Elevated Permissions Required");
                
                ui.label("The following apps require elevated permissions to modify:");
                ui.separator();
                
                // Show elevated apps
                for app_path in &self.elevated_apps {
                    if let Some(app_info) = self.apps.iter().find(|a| &a.path == app_path) {
                        ui.label(format!("• {} ({})", app_info.name, app_info.app_source));
                    }
                }
                
                ui.separator();
                
                // Show user apps that will be processed normally
                if !self.user_apps.is_empty() {
                    ui.label("The following apps will be processed normally (user permissions):");
                    for app_path in &self.user_apps {
                        if let Some(app_info) = self.apps.iter().find(|a| &a.path == app_path) {
                            ui.label(format!("• {} ({})", app_info.name, app_info.app_source));
                        }
                    }
                    ui.separator();
                }
                
                // Warning about elevated processing
                ui.colored_label(egui::Color32::YELLOW, "⚠️ Important Warnings:");
                ui.label("• Elevated processing may modify system files and App Store apps");
                ui.label("• Some apps may become unusable if modified incorrectly");
                ui.label("• Always backup important data before proceeding");
                ui.label("• User-owned apps should NOT be processed with elevated permissions");
                ui.label("  as this may break their UID/GID permissions");
                
                ui.separator();
                
                // Action buttons
                ui.horizontal(|ui| {
                    if ui.button("🔄 Process with Elevated Permissions").clicked() {
                        self.confirm_elevated_processing();
                    }
                    
                    if ui.button("❌ Cancel").clicked() {
                        self.cancel_elevated_processing();
                    }
                });
                
                ui.separator();
                
                // Additional info
                ui.label("Note: The app will use sudo/administrator privileges for elevated apps");
                ui.label("and normal user permissions for user-owned apps.");
            });
    }

    fn render_success_dialog(&mut self, ctx: &egui::Context) {
        let (title, icon) = if self.success_message.contains("⚠️") {
            ("Processing Complete", "⚠️")
        } else {
            ("Processing Complete", "🎉")
        };
        
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading(format!("{} {}", icon, title));
                
                // Use scrollable area for long messages
                egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                    // Split message into lines for better formatting
                    for line in self.success_message.lines() {
                        if line.starts_with("• ") {
                            // Format failure items with indentation
                            ui.label(format!("  {}", line));
                        } else {
                            ui.label(line);
                        }
                    }
                });
                
                ui.separator();
                
                ui.horizontal(|ui| {
                    if ui.button("OK").clicked() {
                        self.show_success_dialog = false;
                        self.success_message.clear();
                    }
                });
            });
    }
}

impl eframe::App for ArchifyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_scanning_messages();
        self.handle_helper_logs(ctx);
        self.handle_processing_logs();
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // Tabs
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, 0, "Applications");
                ui.selectable_value(&mut self.selected_tab, 1, "Settings");
                ui.selectable_value(&mut self.selected_tab, 2, "Logs");
                ui.selectable_value(&mut self.selected_tab, 3, "Manual");
                ui.selectable_value(&mut self.selected_tab, 4, "About");
            });
            
            ui.separator();
            
            match self.selected_tab {
                0 => self.render_applications_tab(ui),
                1 => self.render_settings_tab(ui),
                2 => self.render_logs_tab(ui),
                3 => self.render_manual_thinning_tab(ui),
                4 => self.render_about_tab(ui),
                _ => unreachable!(),
            }
        });
        
        // Show elevated permission dialog if needed
        if self.show_elevated_dialog {
            self.render_elevated_dialog(ctx);
        }
        
        // Show success dialog if needed
        if self.show_success_dialog {
            self.render_success_dialog(ctx);
        }
        
        // Request continuous updates while scanning
        if self.is_scanning {
            ctx.request_repaint();
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Clean up any ongoing operations
        self.is_scanning = false;
        self.is_processing = false;
        self.scan_sender = None;
        self.scan_receiver = None;
    }
}

impl Drop for ArchifyApp {
    fn drop(&mut self) {
        // Ensure any ongoing operations are stopped
        self.is_scanning = false;
        self.is_processing = false;
        self.scan_sender = None;
        self.scan_receiver = None;
    }
} 