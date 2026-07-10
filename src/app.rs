use crate::file_operations::FileOperations;
use crate::types::{AppInfo, LogLevel, LogMessage, ProcessingConfig, BatchProcessingConfig, AppSource, UserSettings};
use eframe::egui::{self, RichText};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;
use rfd::FileDialog;
use crate::privileged_helper::PrivilegedHelper;
use std::sync::OnceLock;
use image;
use dirs;

fn get_settings_path() -> Option<PathBuf> {
    dirs::config_dir().map(|mut p| {
        p.push("archify-rust");
        p.push("settings.json");
        p
    })
}

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
    pub helper_log_receiver: Option<mpsc::Receiver<LogMessage>>,
    pub processing_log_receiver: Option<mpsc::Receiver<LogMessage>>,
    // Success dialog state
    pub show_success_dialog: bool,
    pub success_message: String,
    pub was_processing: bool,
    pub processing_start_time: Option<std::time::Instant>,
    // Manual scanning state
    pub manual_binaries: Vec<crate::types::BinaryInfo>,
    pub manual_selected_binaries: std::collections::HashSet<PathBuf>,
    pub manual_is_scanning: bool,
    // Icon texture cache for About tab
    pub about_icon_texture: Option<egui::TextureHandle>,
    pub about_gpl_texture: Option<egui::TextureHandle>,
    // App icons cache
    pub app_icons: std::collections::HashMap<PathBuf, Option<egui::TextureHandle>>,
    // Async icon loading channels
    pub icon_receiver: Option<mpsc::Receiver<(PathBuf, u32, u32, Vec<u8>)>>,
    pub icon_sender: mpsc::Sender<(PathBuf, u32, u32, Vec<u8>)>,
    pub loading_icons: std::collections::HashSet<PathBuf>,
    pub icon_semaphore: std::sync::Arc<tokio::sync::Semaphore>,
    pub dark_mode: Option<bool>,
    pub theme_initialized: Option<bool>,
}

impl ArchifyApp {
    pub fn load_settings() -> Option<UserSettings> {
        if let Some(path) = get_settings_path() {
            if path.exists() {
                if let Ok(json) = std::fs::read_to_string(path) {
                    if let Ok(settings) = serde_json::from_str::<UserSettings>(&json) {
                        return Some(settings);
                    }
                }
            }
        }
        None
    }

    pub fn save_settings(&self) {
        if let Some(path) = get_settings_path() {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let settings = UserSettings {
                processing_config: self.processing_config.clone(),
                batch_config: self.batch_config.clone(),
                custom_scan_dirs: self.custom_scan_dirs.clone(),
                scan_depth: self.scan_depth,
                show_only_universal: self.show_only_universal,
                show_only_appstore: self.show_only_appstore,
                dark_mode: self.dark_mode,
            };
            if let Ok(json) = serde_json::to_string_pretty(&settings) {
                let _ = std::fs::write(path, json);
            }
        }
    }



    pub fn new() -> Self {
        // Initialize the global runtime if not already done
        let _runtime = RUNTIME.get_or_init(|| {
            Runtime::new().expect("Failed to create Tokio runtime")
        });
        
        let settings = Self::load_settings();
        let (icon_tx, icon_rx) = mpsc::channel(200);
        
        let mut app = Self {
            selected_tab: 0,
            apps: Vec::new(),
            selected_apps: Vec::new(),
            processing_config: ProcessingConfig {
                target_architecture: "x86_64".to_string(),
                target_architectures: None,
                no_sign: true,
                no_entitlements: false,
                use_codesign: false,
                output_directory: None,
            },
            batch_config: BatchProcessingConfig {
                processing_config: ProcessingConfig {
                    target_architecture: "x86_64".to_string(),
                    target_architectures: None,
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
            helper_log_receiver: None,
            processing_log_receiver: None,
            // Success dialog state
            show_success_dialog: false,
            success_message: String::new(),
            was_processing: false,
            processing_start_time: None,
            // Manual scanning state
            manual_binaries: Vec::new(),
            manual_selected_binaries: std::collections::HashSet::new(),
            manual_is_scanning: false,
            // Icon texture cache for About tab
            about_icon_texture: None,
            about_gpl_texture: None,
            app_icons: std::collections::HashMap::new(),
            icon_receiver: Some(icon_rx),
            icon_sender: icon_tx,
            loading_icons: std::collections::HashSet::new(),
            icon_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(3)),
            dark_mode: None,
            theme_initialized: None,
        };

        if let Some(s) = settings {
            app.processing_config = s.processing_config;
            if app.processing_config.target_architectures.is_none() {
                app.processing_config.target_architectures = Some(vec![app.processing_config.target_architecture.clone()]);
            }
            app.batch_config = s.batch_config;
            app.custom_scan_dirs = s.custom_scan_dirs;
            app.scan_depth = s.scan_depth;
            app.show_only_universal = s.show_only_universal;
            app.show_only_appstore = s.show_only_appstore;
            app.dark_mode = s.dark_mode;
        }

        app
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

        let target_arch = self.processing_config.target_architecture.clone();
        // Spawn the scanning task
        runtime.spawn(async move {
            if let Err(e) = FileOperations::scan_applications_async_multi(scan_dirs, show_only_universal, show_only_appstore, scan_depth, target_arch, tx.clone()).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Failed to scan applications: {}", e),
                }).await;
            }
        });
    }

    pub fn scan_manual_binaries(&mut self) {
        if self.is_scanning || self.manual_is_scanning {
            return;
        }

        self.is_scanning = true;
        self.manual_is_scanning = true;
        self.progress = 0.0;
        self.progress_phase = "Scanning folder for fat binaries...".to_string();
        self.manual_binaries.clear();
        self.manual_selected_binaries.clear();

        let (tx, rx) = mpsc::channel(100);
        self.scan_sender = Some(tx.clone());
        self.scan_receiver = Some(rx);

        let paths = self.manual_selected_apps.clone();
        let target_arch = self.processing_config.target_architecture.clone();
        let runtime = RUNTIME.get().expect("Runtime not initialized");

        runtime.spawn(async move {
            if let Err(e) = FileOperations::scan_binaries_async(paths, target_arch, tx.clone()).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Failed to scan folder: {}", e),
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
                // Check if this is a special binaries list message
                if log.message.starts_with("BINARIES_LIST:") {
                    if let Some(binaries_json) = log.message.strip_prefix("BINARIES_LIST:") {
                        if let Ok(binaries) = serde_json::from_str::<Vec<crate::types::BinaryInfo>>(binaries_json) {
                            self.manual_binaries = binaries;
                            self.manual_selected_binaries = self.manual_binaries.iter().map(|b| b.path.clone()).collect();
                            self.manual_is_scanning = false;
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

    pub fn handle_loaded_icons(&mut self, ctx: &egui::Context) {
        if let Some(ref mut rx) = self.icon_receiver {
            while let Ok((path, width, height, pixels)) = rx.try_recv() {
                self.loading_icons.remove(&path);
                if pixels.is_empty() {
                    println!("[DEBUG] Loaded icon failure (None) for {:?}", path);
                    self.app_icons.insert(path, None);
                } else {
                    println!("[DEBUG] Loaded icon success (Some) for {:?}", path);
                    let color_image = egui::ColorImage::from_rgba_unmultiplied(
                        [width as usize, height as usize],
                        &pixels,
                    );
                    let texture = ctx.load_texture(
                        format!("app_icon_{}", path.display()),
                        color_image,
                        egui::TextureOptions::default(),
                    );
                    self.app_icons.insert(path, Some(texture));
                }
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
            // Set processing flags for success dialog
            self.is_processing = true;
            self.was_processing = true;
            self.processing_start_time = Some(std::time::Instant::now());
            
            let (log_tx, log_rx) = mpsc::channel(100);
            self.helper_log_receiver = Some(log_rx);
            
            let elevated_apps = self.elevated_apps.clone();
            let config = self.processing_config.clone();
            let log_tx_spawn = log_tx.clone();
            let rt = RUNTIME.get().expect("Runtime not initialized").handle().clone();
            rt.spawn(async move {
                match PrivilegedHelper::thin_apps(
                    &elevated_apps,
                    &config.target_architecture,
                    config.no_sign,
                    config.no_entitlements,
                    config.use_codesign,
                ).await {
                    Ok((status, log_lines)) => {
                        println!("Successfully thinned all elevated apps: {}", status);
                        let _ = log_tx_spawn.send(LogMessage {
                            timestamp: chrono::Utc::now(),
                            level: LogLevel::Info,
                            message: format!("Successfully thinned all elevated apps: {}", status),
                        }).await;
                        for line in log_lines {
                            let _ = log_tx_spawn.send(LogMessage {
                                timestamp: chrono::Utc::now(),
                                level: LogLevel::Info,
                                message: line,
                            }).await;
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to thin elevated apps: {}", e);
                        let _ = log_tx_spawn.send(LogMessage {
                            timestamp: chrono::Utc::now(),
                            level: LogLevel::Error,
                            message: format!("Failed to thin elevated apps: {}", e),
                        }).await;
                    }
                }
                
                // Signal completion
                let _ = log_tx_spawn.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Success,
                    message: "Elevated processing completed".to_string(),
                }).await;
            });
            drop(log_tx);
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

    fn process_manual_binaries(&mut self) {
        let selected_binaries: Vec<_> = self.manual_binaries.iter()
            .filter(|b| self.manual_selected_binaries.contains(&b.path))
            .map(|b| b.path.clone())
            .collect();

        if selected_binaries.is_empty() {
            self.add_log(LogLevel::Warning, "No binaries selected for processing".to_string());
            return;
        }

        let mut normal_binaries = Vec::new();
        let mut elevated_binaries = Vec::new();

        for binary in selected_binaries {
            if requires_elevated_permissions(&binary) {
                elevated_binaries.push(binary);
            } else {
                normal_binaries.push(binary);
            }
        }

        if !elevated_binaries.is_empty() {
            self.elevated_apps.extend(elevated_binaries);
            self.show_elevated_dialog = true;
            self.add_log(LogLevel::Info, "Elevated privileges required for some binaries".to_string());
        }

        if normal_binaries.is_empty() {
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

        let runtime = RUNTIME.get().expect("Runtime not initialized");
        runtime.spawn(async move {
            if let Err(e) = FileOperations::batch_process_binaries(normal_binaries, &config, tx.clone()).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Manual thinning failed: {}", e),
                }).await;
            }
        });

        self.is_processing = false;
        self.add_log(LogLevel::Info, "Manual binary processing started".to_string());
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

    pub fn handle_helper_logs(&mut self) {
        if let Some(ref mut rx) = self.helper_log_receiver {
            while let Ok(log) = rx.try_recv() {
                self.logs.push(log);
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
                            self.success_message = "⚠ Binary thinning completed with some errors.\n\nPlease check the logs tab for details.".to_string();
                        } else {
                            // Build detailed failure message
                            let mut message = format!("⚠ Binary thinning completed with {} app(s) failed.\n\n", failed_apps.len());
                            
                            for (app_name, reason) in &failed_apps {
                                message.push_str(&format!("• {}: {}\n", app_name, reason));
                            }
                            
                            if total_saved > 0 {
                                message.push_str(&format!("\n✔ Total space saved: {}", FileOperations::human_readable_size(total_saved, 2)));
                            }
                            
                            message.push_str("\n\nℹ Tip: Check the Logs tab for detailed information about each failure.");
                            
                            self.success_message = message;
                        }
                    } else if timeout_elapsed && !has_completion_message {
                        self.success_message = "✔ Binary thinning appears to have completed.\n\nProcessing may have finished in the background.".to_string();
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
                                "✔ Binary thinning completed successfully!\n\nTotal space saved: {}",
                                FileOperations::human_readable_size(total_saved, 2)
                            );
                        } else {
                            self.success_message = "✔ Binary thinning completed successfully!".to_string();
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
                            self.success_message = "⚠ Binary thinning completed with some errors.\n\nPlease check the logs tab for details.".to_string();
                        } else {
                            // Build detailed failure message
                            let mut message = format!("⚠ Binary thinning completed with {} app(s) failed.\n\n", failed_apps.len());
                            
                            for (app_name, reason) in &failed_apps {
                                message.push_str(&format!("• {}: {}\n", app_name, reason));
                            }
                            
                            if total_saved > 0 {
                                message.push_str(&format!("\n✔ Total space saved: {}", FileOperations::human_readable_size(total_saved, 2)));
                            }
                            
                            message.push_str("\n\nℹ Tip: Check the Logs tab for detailed information about each failure.");
                            
                            self.success_message = message;
                        }
                    } else if timeout_elapsed && !has_completion_message {
                        self.success_message = "✔ Binary thinning appears to have completed.\n\nProcessing may have finished in the background.".to_string();
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
                                "✔ Binary thinning completed successfully!\n\nTotal space saved: {}",
                                FileOperations::human_readable_size(total_saved, 2)
                            );
                        } else {
                            self.success_message = "✔ Binary thinning completed successfully!".to_string();
                        }
                    }
                }
            }
        }
    }

    fn render_applications_tab(&mut self, ui: &mut egui::Ui) {
        use egui::RichText;
        use egui::Color32;

        // Status bar panel
        egui::Panel::bottom("status_bar_panel").show(ui, |ui| {
            let selected_apps: Vec<_> = self.apps.iter().filter(|a| self.selected_apps.contains(&a.path)).collect();
            let selected_count = selected_apps.len();
            let total_size: u64 = selected_apps.iter().map(|a| a.total_size).sum();
            let savable_size: u64 = selected_apps.iter().map(|a| a.savable_size).sum();
            ui.add_space(2.0);
            
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
            
            if self.is_processing {
                ui.label("Processing...");
            }
        });
        
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_only_universal, "Show only universal binaries")
                .on_hover_text("Only show applications that contain multiple architectures (Fat Binaries).");
            if self.show_only_universal {
                ui.label("(Filtering universal binaries only)");
            }
        });
        
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_only_appstore, "Show only App Store apps")
                .on_hover_text("Only show applications downloaded from the Mac App Store.");
            if self.show_only_appstore {
                ui.label("(Filtering App Store apps only)");
            }
        });
        
        ui.separator();
        
        // Select All checkbox
        let filtered_apps: Vec<_> = self.apps.iter().filter(|a| {
            let universal_filter = !self.show_only_universal || a.app_type == crate::types::AppType::Universal;
            let appstore_filter = !self.show_only_appstore || a.app_source == AppSource::AppStore;
            universal_filter && appstore_filter
        }).collect();
        
        if !filtered_apps.is_empty() {
            let all_selected = filtered_apps.iter().all(|a| self.selected_apps.contains(&a.path));
            let mut select_all = all_selected;
            
            if ui.checkbox(&mut select_all, "Select All").clicked() {
                if select_all {
                    // Select all filtered apps
                    for app_info in filtered_apps {
                        if !self.selected_apps.contains(&app_info.path) {
                            self.selected_apps.push(app_info.path.clone());
                        }
                    }
                } else {
                    // Deselect all filtered apps
                    self.selected_apps.retain(|p| {
                        !filtered_apps.iter().any(|a| &a.path == p)
                    });
                }
            }
        }
        
        // Show scanning progress if scanning
        if self.is_scanning {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!("Scanning applications... {}", self.current_scanning_app));
            });
            ui.add(egui::ProgressBar::new(self.progress).show_percentage().animate(true));
        }
        
        // Applications list
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("apps_grid").num_columns(1).striped(true).spacing([0.0, 8.0]).show(ui, |ui| {
                for app_info in self.apps.iter().filter(|a| {
                    let universal_filter = !self.show_only_universal || a.app_type == crate::types::AppType::Universal;
                    let appstore_filter = !self.show_only_appstore || a.app_source == AppSource::AppStore;
                    universal_filter && appstore_filter
                }) {
                    ui.horizontal(|ui| {
                        // Render App Icon
                        let icon_cached = self.app_icons.get(&app_info.path);
                        match icon_cached {
                            Some(Some(texture)) => {
                                ui.image((texture.id(), egui::Vec2::splat(64.0)));
                            }
                            Some(None) => {
                                // Failed to load, show fallback
                                ui.label(egui::RichText::new("📱").size(48.0));
                            }
                            None => {
                                // Not in cache (never tried loading or currently loading)
                                ui.label(egui::RichText::new("📱").size(48.0));
                                if !self.loading_icons.contains(&app_info.path) {
                                    self.loading_icons.insert(app_info.path.clone());
                                    let path = app_info.path.clone();
                                    let tx = self.icon_sender.clone();
                                    let sem = self.icon_semaphore.clone();
                                    let rt = RUNTIME.get().expect("Runtime not initialized").handle().clone();
                                    rt.spawn(async move {
                                        let _permit = sem.acquire().await;
                                        let path_clone = path.clone();
                                        let result = tokio::task::spawn_blocking(move || {
                                            crate::icon_loader::get_app_icon_rgba(&path_clone, 128)
                                        }).await;
                                        if let Ok(Some((width, height, pixels))) = result {
                                            let _ = tx.send((path, width, height, pixels)).await;
                                        } else {
                                            let _ = tx.send((path, 0, 0, Vec::new())).await;
                                        }
                                    });
                                }
                            }
                        }

                        ui.add_space(8.0);

                        // Render Checkbox and Details
                        ui.vertical(|ui| {
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
                            // Show actual saved space if available (after processing)
                            if let Some(saved) = crate::types::ProcessingState::default().saved_spaces.get(&app_info.name) {
                                ui.label(&format!("Actual Saved: {}", FileOperations::human_readable_size(*saved, 2)));
                            }
                            ui.label(&format!("Architectures: {:?}", app_info.architectures));
                        });
                    });
                    ui.end_row();
                }
            });
        });
    }
    
    fn render_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        
        ui.label("Target Architectures to Keep:");
        ui.horizontal(|ui| {
            if self.processing_config.target_architectures.is_none() {
                self.processing_config.target_architectures = Some(vec![self.processing_config.target_architecture.clone()]);
            }
            
            if let Some(ref mut archs) = self.processing_config.target_architectures {
                let possible_archs = ["x86_64", "arm64", "arm64e", "i386", "ppc", "ppc64"];
                for &arch in &possible_archs {
                    let mut is_checked = archs.contains(&arch.to_string());
                    if ui.checkbox(&mut is_checked, arch).changed() {
                        if is_checked {
                            if !archs.contains(&arch.to_string()) {
                                archs.push(arch.to_string());
                            }
                        } else {
                            if archs.len() > 1 {
                                archs.retain(|a| a != arch);
                            }
                        }
                    }
                }
                self.processing_config.target_architecture = archs.join(",");
            }
        });
        
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
            if let Some(dir) = FileDialog::new().pick_folder() {
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
        if ui.button("Save Settings").clicked() {
            self.save_settings();
            self.add_log(LogLevel::Success, "Configuration settings saved successfully.".to_string());
        }
    }
    
    fn render_logs_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Clear Logs").clicked() {
                self.logs.clear();
            }
        });
        
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for log in &self.logs {
                let color = match log.level {
                    LogLevel::Info => ui.visuals().text_color(),
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
        ui.label("Select one or more .app bundles or folders from any location to thin in-place.");
        
        ui.horizontal(|ui| {
            if ui.button("Select .app Bundles...").clicked() {
                if let Some(paths) = FileDialog::new()
                    .set_directory(std::env::current_dir().unwrap_or_default())
                    .pick_files() {
                    // Only keep .app directories
                    self.manual_selected_apps = paths
                        .into_iter()
                        .filter(|p| p.extension().map_or(false, |ext| ext == "app"))
                        .collect();
                    self.manual_binaries.clear();
                    self.manual_selected_binaries.clear();
                }
            }

            if ui.button("Select Folders...").clicked() {
                if let Some(paths) = FileDialog::new()
                    .set_directory(std::env::current_dir().unwrap_or_default())
                    .pick_folders() {
                    self.manual_selected_apps = paths;
                    self.manual_binaries.clear();
                    self.manual_selected_binaries.clear();
                }
            }
        });

        if !self.manual_selected_apps.is_empty() {
            ui.group(|ui| {
                ui.label("Selected paths:");
                for path in &self.manual_selected_apps {
                    ui.label(format!("• {}", path.display()));
                }
            });

            ui.add_space(5.0);

            ui.horizontal(|ui| {
                if ui.button("Scan for Universal/Fat Binaries").clicked() && !self.is_scanning {
                    self.scan_manual_binaries();
                }

                if self.is_scanning && self.manual_is_scanning {
                    ui.spinner();
                    ui.label(&self.progress_phase);
                }
            });

            if !self.manual_binaries.is_empty() {
                ui.separator();
                ui.heading("Universal / Fat Binaries Found");
                
                // Status Panel for selected binaries
                let selected_count = self.manual_selected_binaries.len();
                let total_size: u64 = self.manual_binaries.iter()
                    .filter(|b| self.manual_selected_binaries.contains(&b.path))
                    .map(|b| b.size)
                    .sum();
                let savable_size: u64 = self.manual_binaries.iter()
                    .filter(|b| self.manual_selected_binaries.contains(&b.path))
                    .map(|b| b.savable_size)
                    .sum();

                ui.horizontal(|ui| {
                    ui.label(RichText::new("Selected:").size(13.0));
                    ui.label(RichText::new(format!("{} binary(ies)", selected_count)).size(13.0).color(egui::Color32::from_rgb(52, 152, 219)));
                    ui.separator();
                    ui.label(RichText::new("Total Size:").size(13.0));
                    ui.label(RichText::new(crate::file_operations::FileOperations::human_readable_size(total_size, 2)).size(13.0).color(egui::Color32::YELLOW));
                    ui.separator();
                    ui.label(RichText::new("Savable:").size(13.0));
                    ui.label(RichText::new(crate::file_operations::FileOperations::human_readable_size(savable_size, 2)).size(13.0).color(egui::Color32::GREEN));
                });

                ui.add_space(5.0);

                if ui.button(RichText::new("Process Selected Binaries").strong()).clicked() && !self.is_processing {
                    self.process_manual_binaries();
                }

                ui.add_space(5.0);

                egui::ScrollArea::vertical().max_height(350.0).auto_shrink([false, false]).show(ui, |ui| {
                    let mut to_toggle = Vec::new();
                    
                    egui::Grid::new("manual_apps_grid").num_columns(1).striped(true).spacing([0.0, 8.0]).show(ui, |ui| {
                        for binary in &self.manual_binaries {
                            let is_checked = self.manual_selected_binaries.contains(&binary.path);
                            let name = binary.path.file_name().and_then(|n| n.to_str()).unwrap_or("Unknown");
                            let parent = binary.path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()).unwrap_or("");
                            
                            ui.horizontal(|ui| {
                                let mut checked = is_checked;
                                if ui.checkbox(&mut checked, "").changed() {
                                    to_toggle.push((binary.path.clone(), checked));
                                }
                                
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(name).strong());
                                    ui.small(format!("Path: .../{}/{}", parent, name));
                                    ui.small(format!(
                                        "Archs: {:?} | Size: {} | Savable: {}",
                                        binary.architectures,
                                        crate::file_operations::FileOperations::human_readable_size(binary.size, 2),
                                        crate::file_operations::FileOperations::human_readable_size(binary.savable_size, 2)
                                    ));
                                });
                            });
                            ui.end_row();
                        }
                    });

                    for (path, checked) in to_toggle {
                        if checked {
                            self.manual_selected_binaries.insert(path);
                        } else {
                            self.manual_selected_binaries.remove(&path);
                        }
                    }
                });
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
            ui.add_space(40.0);
            
            // App icon
            if let Some(texture) = &self.about_icon_texture {
                ui.image((texture.id(), egui::Vec2::splat(96.0)));
            } else {
                ui.label(egui::RichText::new("📱").size(96.0));
            }
            
            ui.add_space(16.0);
            
            // App name and version
            ui.label(egui::RichText::new("Archify")
                .size(42.0)
                .strong());
            
            ui.label(egui::RichText::new("Version 0.3.0")
                .size(16.0)
                .color(ui.visuals().weak_text_color()));
                
            ui.add_space(32.0);
            
            // Description
            ui.label(egui::RichText::new("A powerful, minimal macOS tool to optimize universal binaries by\nstripping unnecessary architectures. Save disk space effortlessly.")
                .size(15.0)
                .color(ui.visuals().weak_text_color()));
                
            ui.add_space(48.0);
            
            // Developer
            ui.label(egui::RichText::new("DEVELOPED BY").size(10.0).color(ui.visuals().weak_text_color()).strong());
            ui.add_space(2.0);
            ui.label(egui::RichText::new("Genxster1998").size(16.0));
            
            ui.add_space(24.0);
            
            // License
            ui.label(egui::RichText::new("LICENSE").size(10.0).color(ui.visuals().weak_text_color()).strong());
            ui.add_space(4.0);
            if let Some(gpl_texture) = &self.about_gpl_texture {
                let aspect = gpl_texture.size()[0] as f32 / gpl_texture.size()[1] as f32;
                ui.image((gpl_texture.id(), egui::Vec2::new(48.0, 48.0 / aspect)));
            }
            ui.label(egui::RichText::new("GNU General Public License v3.0").size(13.0));
            
            ui.add_space(24.0);
            
            // Source Code
            ui.label(egui::RichText::new("SOURCE").size(10.0).color(ui.visuals().weak_text_color()).strong());
            ui.add_space(4.0);
            if ui.link(egui::RichText::new(format!("{} GitHub Repository", egui::special_emojis::GITHUB)).size(16.0)).clicked() {
                let _ = std::process::Command::new("open")
                    .arg("https://github.com/Genxster1998/Archify-rust")
                    .output();
            }
            
            ui.add_space(60.0);
            
            ui.label(egui::RichText::new("Built with Rust & egui")
                .size(12.0)
                .color(ui.visuals().weak_text_color()));
        });
    }

    fn render_elevated_dialog(&mut self, ctx: &egui::Context) {
        egui::Window::new("Elevated Permissions Required")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚠").size(22.0).color(egui::Color32::YELLOW).strong());
                    ui.heading("Elevated Permissions Required");
                });
                
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
                ui.horizontal(|ui| {
                    ui.label(RichText::new("⚠").size(16.0).color(egui::Color32::YELLOW).strong());
                    ui.label(RichText::new("Important Warnings:").color(egui::Color32::YELLOW).strong());
                });
                ui.label("• Elevated processing may modify system files and App Store apps");
                ui.label("• Some apps may become unusable if modified incorrectly");
                ui.label("• Always backup important data before proceeding");
                ui.label("• User-owned apps should NOT be processed with elevated permissions");
                ui.label("  as this may break their UID/GID permissions");
                
                ui.separator();
                
                // Action buttons
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("↻ Process with Elevated Permissions").strong()).clicked() {
                        self.confirm_elevated_processing();
                    }
                    
                    if ui.button(RichText::new("❌ Cancel").strong()).clicked() {
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
        let (title, icon, icon_color) = if self.success_message.contains("⚠") {
            ("Processing Complete", "⚠", egui::Color32::YELLOW)
        } else {
            ("Processing Complete", "★", egui::Color32::from_rgb(241, 196, 15))
        };
        
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(icon).size(22.0).color(icon_color).strong());
                    ui.heading(title);
                });
                
                // Use scrollable area for long messages
                egui::ScrollArea::vertical().max_height(300.0).auto_shrink([false, false]).show(ui, |ui| {
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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();

        // Initialize theme on first frame
        if self.theme_initialized.is_none() {
            let is_dark = self.dark_mode.unwrap_or(true);
            if is_dark {
                ctx.set_visuals(egui::Visuals::dark());
            } else {
                ctx.set_visuals(egui::Visuals::light());
            }
            self.theme_initialized = Some(true);
        }

        self.handle_scanning_messages();
        self.handle_loaded_icons(&ctx);
        self.handle_helper_logs();
        self.handle_processing_logs();
        
        egui::CentralPanel::default().show(ui, |ui| {
            // Ensure the panel's ui uses the updated visuals immediately on first frame
            if let Some(is_dark) = self.dark_mode {
                let visuals = if is_dark {
                    egui::Visuals::dark()
                } else {
                    egui::Visuals::light()
                };
                ui.style_mut().visuals = visuals;
            }

            // Tabs
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, 0, "Applications");
                ui.selectable_value(&mut self.selected_tab, 1, "Settings");
                ui.selectable_value(&mut self.selected_tab, 2, "Logs");
                ui.selectable_value(&mut self.selected_tab, 3, "Manual");
                ui.selectable_value(&mut self.selected_tab, 4, "About");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let is_dark = ui.style().visuals.dark_mode;
                    let icon = if is_dark { "☀️" } else { "🌙" };
                    let tooltip = if is_dark { "Switch to Light Theme" } else { "Switch to Dark Theme" };
                    if ui.button(icon).on_hover_text(tooltip).clicked() {
                        let new_dark = !is_dark;
                        self.dark_mode = Some(new_dark);
                        let visuals = if new_dark {
                            egui::Visuals::dark()
                        } else {
                            egui::Visuals::light()
                        };
                        ctx.set_visuals(visuals.clone());
                        ui.style_mut().visuals = visuals;
                        self.save_settings();
                    }
                });
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
            
            // Show elevated permission dialog if needed
            if self.show_elevated_dialog {
                self.render_elevated_dialog(ui.ctx());
            }
            
            // Show success dialog if needed
            if self.show_success_dialog {
                self.render_success_dialog(ui.ctx());
            }
        });
        
        // Request continuous updates while scanning
        if self.is_scanning {
            ctx.request_repaint();
        }
    }

    fn on_exit(&mut self) {
        // Save settings to disk
        self.save_settings();

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

fn requires_elevated_permissions(path: &std::path::Path) -> bool {
    use std::ffi::CString;
    if let Some(path_str) = path.to_str() {
        if let Ok(c_path) = CString::new(path_str) {
            unsafe {
                if libc::access(c_path.as_ptr(), libc::W_OK) != 0 {
                    return true;
                }
            }
        }
    }
    false
}