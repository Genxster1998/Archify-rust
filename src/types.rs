use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub path: PathBuf,
    pub total_size: u64,
    pub savable_size: u64,
    pub architectures: Vec<String>,
    pub app_type: AppType,
    pub is_selected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AppType {
    Universal,
    Native,
    Other,
}

impl std::fmt::Display for AppType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppType::Universal => write!(f, "Universal"),
            AppType::Native => write!(f, "Native"),
            AppType::Other => write!(f, "Other"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingConfig {
    pub target_architecture: String,
    pub no_sign: bool,
    pub no_entitlements: bool,
    pub use_codesign: bool,
    pub output_directory: Option<PathBuf>,
}

impl Default for ProcessingConfig {
    fn default() -> Self {
        Self {
            target_architecture: get_system_architecture(),
            no_sign: true,
            no_entitlements: true,
            use_codesign: false,
            output_directory: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProcessingConfig {
    pub processing_config: ProcessingConfig,
    pub save_logs_to_file: bool,
    pub parallel_processing: bool,
    pub max_parallel_jobs: usize,
}

impl Default for BatchProcessingConfig {
    fn default() -> Self {
        Self {
            processing_config: ProcessingConfig::default(),
            save_logs_to_file: true,
            parallel_processing: false,
            max_parallel_jobs: 4,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingState {
    pub is_scanning: bool,
    pub is_processing: bool,
    pub scanning_progress: f32,
    pub processing_progress: f32,
    pub current_app: Option<String>,
    pub total_saved_space: u64,
    pub initial_total_size: u64,
    pub final_total_size: u64,
    pub saved_spaces: HashMap<String, u64>,
    pub log_messages: Vec<LogMessage>,
}

impl Default for ProcessingState {
    fn default() -> Self {
        Self {
            is_scanning: false,
            is_processing: false,
            scanning_progress: 0.0,
            processing_progress: 0.0,
            current_app: None,
            total_saved_space: 0,
            initial_total_size: 0,
            final_total_size: 0,
            saved_spaces: HashMap::new(),
            log_messages: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMessage {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: LogLevel,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Info,
    Warning,
    Error,
    Success,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warning => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Success => write!(f, "SUCCESS"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: PathBuf,
    pub architectures: Vec<String>,
    pub size: u64,
    pub is_universal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessingResult {
    pub app_path: PathBuf,
    pub output_path: Option<PathBuf>,
    pub original_size: u64,
    pub final_size: u64,
    pub saved_space: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub logs: Vec<LogMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProcessingResult {
    pub results: Vec<ProcessingResult>,
    pub total_original_size: u64,
    pub total_final_size: u64,
    pub total_saved_space: u64,
    pub successful_apps: usize,
    pub failed_apps: usize,
    pub all_logs: Vec<LogMessage>,
}

fn get_system_architecture() -> String {
    #[cfg(target_arch = "x86_64")]
    return "x86_64".to_string();
    
    #[cfg(target_arch = "aarch64")]
    return "arm64".to_string();
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return "unknown".to_string();
} 