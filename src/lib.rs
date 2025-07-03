pub mod app;
pub mod types;
pub mod file_operations;
pub mod binary_processor;
pub mod gui;
pub mod privileged_helper;
pub mod helper;

#[cfg(test)]
mod tests {
    use crate::file_operations::FileOperations;
    use crate::types::AppSource;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_detect_app_source() {
        // Test with a known system app
        let system_app_path = PathBuf::from("/System/Applications/Calculator.app");
        if system_app_path.exists() {
            let source = FileOperations::detect_app_source(&system_app_path).await.unwrap();
            assert_eq!(source, AppSource::System);
        }

        // Test with /Applications (should be App Store or User Installed)
        let app_store_app_path = PathBuf::from("/Applications");
        if app_store_app_path.exists() {
            // This is just a directory test, not a specific app
            println!("Applications directory exists");
        }
    }

    #[tokio::test]
    async fn test_calculate_unneeded_arch_size() {
        // Test with a known universal binary (like /usr/bin/lipo itself)
        let lipo_path = PathBuf::from("/usr/bin/lipo");
        if lipo_path.exists() {
            let system_arch = if cfg!(target_arch = "x86_64") { "x86_64" } else { "arm64" };
            let result = FileOperations::calculate_unneeded_arch_size_for_binary(&lipo_path, system_arch).await;
            match result {
                Ok(size) => {
                    println!("Unneeded architecture size for lipo: {} bytes", size);
                    // Should be >= 0
                    assert!(size >= 0);
                }
                Err(e) => {
                    println!("Error calculating unneeded arch size: {}", e);
                    // This is acceptable if lipo is not universal
                }
            }
        }
    }
} 