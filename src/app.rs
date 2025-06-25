use crate::file_operations::FileOperations;
use crate::types::{AppInfo, LogLevel, LogMessage, ProcessingConfig, BatchProcessingConfig};
use eframe::egui;
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::runtime::Runtime;
use rfd::FileDialog;

pub struct ArchifyApp {
    selected_tab: usize,
    runtime: Runtime,
    pub apps: Vec<AppInfo>,
    pub selected_apps: Vec<PathBuf>,
    pub processing_config: ProcessingConfig,
    pub batch_config: BatchProcessingConfig,
    pub logs: Vec<LogMessage>,
    pub is_processing: bool,
    pub is_scanning: bool,
    pub show_only_universal: bool,
    pub progress: f32,
    pub progress_phase: String,
    pub total_apps_found: usize,
    pub current_scanning_app: String,
    scan_sender: Option<mpsc::Sender<LogMessage>>,
    scan_receiver: Option<mpsc::Receiver<LogMessage>>,
    // For single app mode
    pub single_app_path: Option<PathBuf>,
    pub single_app_output_dir: Option<PathBuf>,
    // For manual thinning
    pub manual_selected_apps: Vec<PathBuf>,
    pub custom_scan_dirs: Vec<PathBuf>,
    pub scan_depth: usize,
}

impl ArchifyApp {
    pub fn new() -> Self {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");
        
        Self {
            selected_tab: 0,
            runtime,
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
            progress: 0.0,
            progress_phase: String::new(),
            total_apps_found: 0,
            current_scanning_app: String::new(),
            scan_sender: None,
            scan_receiver: None,
            single_app_path: None,
            single_app_output_dir: None,
            manual_selected_apps: Vec::new(),
            custom_scan_dirs: Vec::new(),
            scan_depth: 2,
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
        
        let runtime = &self.runtime;
        let show_only_universal = self.show_only_universal;
        let mut scan_dirs = vec![PathBuf::from("/Applications")];
        scan_dirs.extend(self.custom_scan_dirs.iter().cloned());
        let scan_depth = self.scan_depth;

        // Spawn the scanning task
        runtime.spawn(async move {
            if let Err(e) = FileOperations::scan_applications_async_multi(scan_dirs, show_only_universal, scan_depth, tx.clone()).await {
                let _ = tx.send(LogMessage {
                    timestamp: chrono::Utc::now(),
                    level: LogLevel::Error,
                    message: format!("Failed to scan applications: {}", e),
                }).await;
            }
        });
    }

    pub fn update_scanning_progress(&mut self) {
        if !self.is_scanning {
            return;
        }

        // This will be called from the UI update loop to check for new messages
        // The actual message handling is done in the scan_applications function
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

        self.is_processing = true;
        self.logs.clear();

        // Update batch config with current processing config
        self.batch_config.processing_config = self.processing_config.clone();

        let (tx, mut rx) = mpsc::channel(100);
        let config = self.batch_config.clone();
        let selected_apps = self.selected_apps.clone();

        self.runtime.spawn(async move {
            if let Err(e) = FileOperations::batch_process_apps(selected_apps, &config, tx.clone()).await {
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
        self.add_log(LogLevel::Info, "Processing completed".to_string());
    }

    fn add_log(&mut self, level: LogLevel, message: String) {
        self.logs.push(LogMessage {
            timestamp: chrono::Utc::now(),
            level,
            message,
        });
    }

    pub fn start_thinning_progress(&mut self) {
        self.progress = 0.0;
        self.progress_phase = "Processing apps...".to_string();
        self.is_processing = true;
    }
    pub fn finish_thinning_progress(&mut self) {
        self.progress = 1.0;
        self.progress_phase.clear();
        self.is_processing = false;
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
        
        // Request continuous updates while scanning
        if self.is_scanning {
            ctx.request_repaint();
        }
    }
}

impl ArchifyApp {
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
        
        ui.separator();
        
        // Show scanning progress if scanning
        if self.is_scanning {
            ui.label(format!("Scanning applications... {}", self.current_scanning_app));
            ui.add(egui::ProgressBar::new(self.progress).show_percentage());
        }
        
        // Applications list
        egui::ScrollArea::vertical().show(ui, |ui| {
            for app_info in self.apps.iter().filter(|a| !self.show_only_universal || a.app_type == crate::types::AppType::Universal) {
                let mut selected = self.selected_apps.contains(&app_info.path);
                if ui.checkbox(&mut selected, &format!("{}", app_info.name)).clicked() {
                    if selected {
                        self.selected_apps.push(app_info.path.clone());
                    } else {
                        self.selected_apps.retain(|p| p != &app_info.path);
                    }
                }
                ui.label(&format!("Type: {:?}", app_info.app_type));
                ui.label(&format!("Size: {}", FileOperations::human_readable_size(app_info.total_size, 2)));
                ui.label(&format!("Estimated Savable: {} (upper bound, may be higher than real savings)", FileOperations::human_readable_size(app_info.savable_size, 2)));
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

    fn render_single_app_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Single App Processing");
        ui.label("Select an app bundle (.app) to process in-place, or specify an output directory for a copy.");
        
        // File picker for app
        if ui.button("Select App...").clicked() {
            // You would use a file dialog here in a real app
            // For now, just a placeholder
            // self.single_app_path = Some(PathBuf::from("/Applications/SomeApp.app"));
        }
        if let Some(ref path) = self.single_app_path {
            ui.label(format!("Selected app: {}", path.display()));
        }
        
        // Output directory picker
        if ui.button("Set Output Directory...").clicked() {
            // You would use a directory dialog here in a real app
            // For now, just a placeholder
            // self.single_app_output_dir = Some(PathBuf::from("/Users/youruser/Desktop"));
        }
        if let Some(ref dir) = self.single_app_output_dir {
            ui.label(format!("Output directory: {}", dir.display()));
        }
        
        if ui.button("Process App").clicked() {
            // TODO: Implement single app processing logic
        }
    }

    fn render_manual_thinning_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Manual Thinning");
        ui.label("Select one or more .app directories from any location to thin in-place.");
        if ui.button("Select .app Directories...").clicked() {
            if let Some(paths) = FileDialog::new()
                .set_directory(std::env::current_dir().unwrap_or_default())
                .pick_folders() {
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
                // TODO: Call batch_process_apps with self.manual_selected_apps
            }
        }
    }
} 