use eframe::egui;
use tracing_subscriber;

mod app;
mod binary_processor;
mod file_operations;
mod types;

use app::ArchifyApp;

fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_min_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "Archify Rust",
        options,
        Box::new(|_cc| Box::new(ArchifyApp::new())),
    )
} 