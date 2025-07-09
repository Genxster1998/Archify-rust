/*
 * Archify Rust - Main Application
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

use eframe::egui;
use tracing_subscriber;
use eframe::icon_data::from_png_bytes;

mod app;
mod binary_processor;
mod file_operations;
mod types;
mod privileged_helper;

use app::ArchifyApp;
use std::env;
use std::path::PathBuf;
use types::{BatchProcessingConfig, LogLevel};
use file_operations::FileOperations;

fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "--batch-elevated" {
        // CLI mode: process apps as root
        let app_paths: Vec<PathBuf> = args[2..].iter().map(|s| PathBuf::from(s)).collect();
        
        // Validate that all paths exist and are .app bundles
        let valid_paths: Vec<PathBuf> = app_paths.into_iter()
            .filter(|p| p.exists() && p.extension().map_or(false, |ext| ext == "app"))
            .collect();
            
        if valid_paths.is_empty() {
            eprintln!("[ERROR] No valid .app bundles found in arguments");
            return Ok(());
        }
        
        let config = BatchProcessingConfig::default();
        
        // Create a runtime for CLI mode
        let rt = tokio::runtime::Runtime::new().expect("Failed to create runtime");
        rt.block_on(async {
            let (tx, mut rx) = tokio::sync::mpsc::channel(100);
            println!("[archify-rust] Running batch processing as root for: {:?}", valid_paths);
            
            // Spawn the batch processing in a separate task
            let processing_handle = tokio::spawn(async move {
                FileOperations::batch_process_apps(valid_paths, &config, tx).await
            });
            
            // Print logs to stdout
            while let Some(log) = rx.recv().await {
                let color = match log.level {
                    LogLevel::Info => "[INFO]",
                    LogLevel::Warning => "[WARN]",
                    LogLevel::Error => "[ERROR]",
                    LogLevel::Success => "[SUCCESS]",
                };
                println!("{} {}", color, log.message);
            }
            
            // Wait for processing to complete
            if let Err(e) = processing_handle.await {
                eprintln!("[ERROR] Processing failed: {}", e);
            }
        });
        
        return Ok(());
    }

    // Embed app icon as bytes at compile time
    let icon_data = include_bytes!("../assets/icon.png");
    let icon = from_png_bytes(icon_data).ok();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 750.0])
            .with_min_inner_size([400.0, 370.0])
            .with_icon(icon.unwrap_or_default()),
        ..Default::default()
    };

    eframe::run_native(
        "Archify Rust",
        options,
        Box::new(|_cc| Box::new(ArchifyApp::new())),
    )
} 