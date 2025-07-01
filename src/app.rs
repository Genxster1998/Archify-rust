use crate::file_operations::FileOperations;
use crate::types::{AppInfo, LogLevel, LogMessage, ProcessingConfig, BatchProcessingConfig, AppSource};
use eframe::egui;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;
use rfd::FileDialog;
use crate::privileged_helper::PrivilegedHelper;
use std::sync::OnceLock;

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
                save_logs_to_file: true,
                parallel_processing: false,
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
        self.logs.clear();

        // Update batch config with current processing config
        self.batch_config.processing_config = self.processing_config.clone();

        let (tx, mut rx) = mpsc::channel(100);
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

        // Handle log messages
        while let Ok(log) = rx.try_recv() {
            self.logs.push(log);
        }

        self.is_processing = false;
        let permission_type = if elevated { "elevated" } else { "user" };
        self.add_log(LogLevel::Info, format!("{} processing completed", permission_type));
    }

    pub fn confirm_elevated_processing(&mut self) {
        self.show_elevated_dialog = false;
        self.elevated_confirmed = true;

        // If there are elevated apps, use privileged helper
        if !self.elevated_apps.is_empty() {
            // Check if helper is installed
            if !PrivilegedHelper::is_installed() {
                // Install helper if not present
                let rt = RUNTIME.get().expect("Runtime not initialized").handle().clone();
                rt.spawn(async move {
                    if let Err(e) = PrivilegedHelper::install_helper().await {
                        eprintln!("Failed to install privileged helper: {}", e);
                    }
                });
                self.add_log(LogLevel::Warning, "Installing privileged helper...".to_string());
            } else {
                // Process elevated apps using helper
                for app_path in &self.elevated_apps {
                    let app_path = app_path.clone();
                    let config = self.processing_config.clone();
                    let rt = RUNTIME.get().expect("Runtime not initialized").handle().clone();
                    
                    rt.spawn(async move {
                        match PrivilegedHelper::thin_app(
                            &app_path,
                            &config.target_architecture,
                            config.no_sign,
                            config.no_entitlements,
                            config.use_codesign,
                        ).await {
                            Ok(result) => {
                                println!("Successfully thinned {}: {}", app_path.display(), result);
                            }
                            Err(e) => {
                                eprintln!("Failed to thin {}: {}", app_path.display(), e);
                            }
                        }
                    });
                }
            }
        }

        // Process user apps normally
        self.process_apps_with_permissions(self.user_apps.clone(), false);

        // Clear the categorized lists
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

    fn render_applications_tab(&mut self, ui: &mut egui::Ui) {
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
            ui.label(format!("Scanning applications... {}", self.current_scanning_app));
            ui.add(egui::ProgressBar::new(self.progress).show_percentage());
        }
        
        // Applications list
        egui::ScrollArea::vertical().show(ui, |ui| {
            for app_info in self.apps.iter().filter(|a| {
                let universal_filter = !self.show_only_universal || a.app_type == crate::types::AppType::Universal;
                let appstore_filter = !self.show_only_appstore || a.app_source == AppSource::AppStore;
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
                // Show actual saved space if available (after processing)
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
}

impl eframe::App for ArchifyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle scanning messages
        self.handle_scanning_messages();
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // Tabs
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, 0, "Applications");
                ui.selectable_value(&mut self.selected_tab, 1, "Settings");
                ui.selectable_value(&mut self.selected_tab, 2, "Logs");
                ui.selectable_value(&mut self.selected_tab, 3, "Manual Thinning");
            });
            
            ui.separator();
            
            match self.selected_tab {
                0 => self.render_applications_tab(ui),
                1 => self.render_settings_tab(ui),
                2 => self.render_logs_tab(ui),
                3 => self.render_manual_thinning_tab(ui),
                _ => unreachable!(),
            }
        });
        
        // Show elevated permission dialog if needed
        if self.show_elevated_dialog {
            self.render_elevated_dialog(ctx);
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