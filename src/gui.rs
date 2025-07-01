use crate::app::ArchifyApp;
use crate::types::LogLevel;
use eframe::egui;

#[derive(Default)]
pub struct GuiState {
    selected_tab: usize,
}

impl GuiState {
    pub fn render(&mut self, ctx: &egui::Context, app: &mut ArchifyApp) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Archify Rust - ARM64 Binary Remover");
            
            // Tabs
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.selected_tab, 0, "Applications");
                ui.selectable_value(&mut self.selected_tab, 1, "Settings");
                ui.selectable_value(&mut self.selected_tab, 2, "Logs");
            });
            
            ui.separator();
            
            match self.selected_tab {
                0 => self.render_applications_tab(ui, app),
                1 => self.render_settings_tab(ui, app),
                2 => self.render_logs_tab(ui, app),
                _ => unreachable!(),
            }
        });
    }
    
    fn render_applications_tab(&mut self, ui: &mut egui::Ui, app: &mut ArchifyApp) {
        ui.horizontal(|ui| {
            if ui.button("Scan Applications").clicked() {
                app.scan_applications();
            }
            
            if ui.button("Process Selected").clicked() && !app.is_processing {
                app.process_selected_apps();
            }
            
            if app.is_processing {
                ui.label("Processing...");
            }
        });
        
        ui.separator();
        
        // Applications list
        egui::ScrollArea::vertical().show(ui, |ui| {
            for app_info in &app.apps {
                let mut selected = app.selected_apps.contains(&app_info.path);
                if ui.checkbox(&mut selected, &format!("{}", app_info.name)).clicked() {
                    if selected {
                        app.selected_apps.push(app_info.path.clone());
                    } else {
                        app.selected_apps.retain(|p| p != &app_info.path);
                    }
                }
                
                ui.label(&format!("Type: {:?}", app_info.app_type));
                ui.label(&format!("Size: {} bytes", app_info.total_size));
                ui.label(&format!("Savable: {} bytes", app_info.savable_size));
                ui.label(&format!("Architectures: {:?}", app_info.architectures));
                ui.separator();
            }
        });
    }
    
    fn render_settings_tab(&mut self, ui: &mut egui::Ui, app: &mut ArchifyApp) {
        ui.heading("Processing Settings");
        
        ui.label("Target Architecture:");
        ui.text_edit_singleline(&mut app.processing_config.target_architecture);
        
        ui.checkbox(&mut app.processing_config.no_sign, "Don't sign binaries");
        ui.checkbox(&mut app.processing_config.no_entitlements, "Don't preserve entitlements");
        ui.checkbox(&mut app.processing_config.use_codesign, "Use codesign instead of ldid");
    }
    
    fn render_logs_tab(&mut self, ui: &mut egui::Ui, app: &mut ArchifyApp) {
        ui.horizontal(|ui| {
            if ui.button("Clear Logs").clicked() {
                app.logs.clear();
            }
        });
        
        egui::ScrollArea::vertical().show(ui, |ui| {
            for log in &app.logs {
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
} 