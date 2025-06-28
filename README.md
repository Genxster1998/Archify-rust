# Archify Rust

A Rust implementation of Archify for removing ARM64e/ARM64 code from binaries on macOS.

## Features

- **App Source Detection**: Automatically detects whether apps are from the App Store, user-installed, or system apps
- **App Store Filter**: Filter to show only App Store apps
- **Universal Binary Filter**: Filter to show only universal binaries (x86_64 + arm64)
- **Accurate Size Calculation**: Uses `lipo -detailed_info` for precise savable size estimation without disk I/O
- **High Performance**: Uses all available CPU threads for parallel scanning and processing
- **Batch Processing**: Process multiple apps simultaneously
- **Progress Tracking**: Real-time progress updates during scanning and processing
- **Logging**: Comprehensive logging of all operations

## App Source Detection

The application can detect the source of apps by examining:

1. **File Ownership**: Checks the UID of the `.app` folder
2. **Location**: Determines if the app is in `/Applications` (system-wide) or `~/Applications` (user-specific)
3. **App Store Receipt**: Looks for `Contents/_MASReceipt` folder (indicates App Store purchase)
4. **Ownership Patterns**: 
   - UID 0 (root) = System apps
   - Current user UID = User-installed apps
   - Other UIDs in `/Applications` = Likely App Store apps

### App Source Types

- **App Store**: Apps purchased from the Mac App Store
- **User Installed**: Apps installed by the user (drag & drop, installers, etc.)
- **System**: Built-in macOS system applications
- **Unknown**: Apps that couldn't be classified

## Performance Optimizations

- **Efficient Size Calculation**: Uses `lipo -detailed_info` to get architecture sizes without writing temporary files
- **Parallel Processing**: Uses all available CPU cores for scanning and analysis
- **Fast Universal Detection**: Uses `goblin` for fast Mach-O header parsing
- **Accurate Universal Classification**: Only marks as universal if both x86_64 and arm64 architectures are present

## Usage

1. **Scan Applications**: Click "Scan Applications" to discover apps on your system
2. **Apply Filters**: Use the checkboxes to filter by:
   - Universal binaries only (x86_64 + arm64)
   - App Store apps only
3. **Select Apps**: Check the apps you want to process
4. **Process**: Click "Process Selected" to remove unwanted architectures

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run
```

## Dependencies

- `eframe` / `egui`: GUI framework
- `tokio`: Async runtime
- `libc`: System calls for UID detection
- `walkdir`: File system traversal
- `goblin`: Fast Mach-O binary parsing
- `num_cpus`: CPU core detection for parallelism
- `serde`: Serialization
- `anyhow`: Error handling

## License

GPL-3.0 