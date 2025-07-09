<!-- Centered App Icon -->
<p align="center">
  <img src="assets/icon.png" alt="Archify Rust Icon" width="120" height="120" />
</p>

<!-- Centered Badges -->
<p align="center">
  <a href="https://github.com/Genxster1998/archify-rust/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Genxster1998/archify-rust/ci.yml?branch=main" alt="Build Status" />
  </a>
  <a href="https://github.com/Genxster1998/archify-rust/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Genxster1998/archify-rust" alt="License" />
  </a>
  <a href="https://github.com/Genxster1998/archify-rust/issues">
    <img src="https://img.shields.io/github/issues/Genxster1998/archify-rust" alt="Issues" />
  </a>
  <a href="https://github.com/Genxster1998/archify-rust/stargazers">
    <img src="https://img.shields.io/github/stars/Genxster1998/archify-rust" alt="Stars" />
  </a>
</p>

# Archify Rust

A modern Rust implementation of Archify for removing ARM64e/ARM64 code from macOS universal binaries. This tool helps reduce disk space usage by removing unnecessary architectures from applications.

## Features

### Core Functionality
- **Universal Binary Detection**: Fast detection using the `goblin` crate
- **Accurate Size Calculation**: Uses `lipo -detailed_info` for precise savable space estimation
- **Parallel Processing**: Utilizes all available CPU cores for faster processing
- **App Source Detection**: Automatically detects App Store vs user-installed applications
- **In-Place Thinning**: Modifies applications directly without creating copies

### Modern Architecture
- **Rust Binary Helper**: Replaces bash scripts with a robust Rust binary for privileged operations
- **GUI Installation**: Modern GUI prompts for installing the privileged helper (no terminal required)
- **Proper App Bundle**: Uses `cargo-bundle` to create a proper macOS `.app` bundle
- **Entitlements Support**: Proper entitlements and launchd plist for system integration

### User Interface
- **Modern GUI**: Built with `egui` for a native macOS experience
- **Batch Processing**: Select multiple applications for processing
- **Real-time Logging**: Live progress updates and detailed logging
- **App Filtering**: Filter by universal binaries, App Store apps, etc.
- **Manual Thinning**: Select individual `.app` bundles for processing

## Installation

### Prerequisites
- macOS 10.15 or later
- Rust 1.70+ and Cargo
- Administrator privileges (for installing the helper)

### Building from Source

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/archify-rust.git
   cd archify-rust
   ```

2. **Build the application**:
   ```bash
   ./build.sh
   ```

   This will:
   - Build the main application
   - Build the privileged helper binary
   - Create a proper macOS `.app` bundle
   - Bundle the helper binary and plist files

3. **Install the app bundle**:
   ```bash
   # Copy to Applications folder
   cp -r target/release/bundle/osx/Archify.app /Applications/
   
   # Or run directly
   open target/release/bundle/osx/Archify.app
   ```

### First Run Setup

1. **Launch the application** from Applications or the build directory
2. **Install the Privileged Helper**:
   - Go to the Settings tab
   - Click "Install Helper" in the Privileged Helper section
   - Enter your administrator password when prompted
   - The helper will be installed as a system service

## Usage

### GUI Mode (Recommended)

1. **Launch Archify Rust**
2. **Scan Applications**:
   - Click "Scan Applications" to find apps in `/Applications`
   - Add custom directories in Settings if needed
   - Use filters to show only universal binaries or App Store apps

3. **Select Applications**:
   - Check the applications you want to thin
   - Use "Select All" to select all visible apps
   - Review the estimated savable space

4. **Process Applications**:
   - Click "Process Selected Apps"
   - The app will automatically handle permission requirements
   - Monitor progress in the Logs tab

### Manual Thinning

1. **Go to Manual Thinning tab**
2. **Select .app bundles** from any location
3. **Click "Process Selected Apps"**

### Batch Processing

For advanced users, you can also use the CLI mode:

```bash
# Process apps with elevated permissions
sudo ./target/release/archify-rust --batch-elevated /path/to/app1.app /path/to/app2.app
```

## Architecture

### Main Application (`src/main.rs`)
- GUI application built with `egui`
- Handles user interface and coordination
- Manages scanning and processing workflows

### Helper Binary (`src/bin/helper.rs`)
- Rust binary for privileged operations
- Installed as a system service via launchd
- Handles actual thinning operations with root privileges
- Supports signing with `codesign` or `ldid`

### File Operations (`src/file_operations.rs`)
- Core scanning and processing logic
- Parallel processing implementation
- App source detection and filtering

### Privileged Helper (`src/privileged_helper.rs`)
- Manages helper installation/uninstallation
- GUI prompts for administrator privileges
- Service status monitoring

## Security

### Privileged Helper
- Runs as a system service with root privileges
- Installed in `/Library/PrivilegedHelperTools/`
- Uses launchd for service management
- Proper entitlements and code signing support

### Permissions
- **User Apps**: Processed with user permissions
- **System/App Store Apps**: Require elevated permissions
- **Automatic Detection**: App source determines permission requirements

## Configuration

### Settings Tab
- **Target Architecture**: Choose x86_64, arm64, or arm64e
- **Signing Options**: Use codesign or ldid for binary signing
- **Batch Processing**: Configure parallel processing and logging
- **Scan Locations**: Add custom directories for app discovery

### Helper Management
- **Install/Uninstall**: Manage the privileged helper
- **Status Monitoring**: Check if helper is installed and running
- **Version Information**: Display helper version and status

## Troubleshooting

### Helper Installation Issues
- Ensure you have administrator privileges
- Check that the app bundle is properly built
- Verify the helper binary exists in the app bundle resources

### Processing Failures
- Check the Logs tab for detailed error messages
- Ensure the helper is installed and running
- Verify target applications are not in use

### Build Issues
- Ensure Rust and Cargo are up to date
- Install `cargo-bundle` if not already installed
- Check that all dependencies are available

## Development

### Project Structure
```
archify-rust/
├── src/
│   ├── main.rs              # Main application entry point
│   ├── app.rs               # GUI application logic
│   ├── bin/helper.rs        # Privileged helper binary
│   ├── file_operations.rs   # Core file processing
│   ├── privileged_helper.rs # Helper management
│   ├── types.rs             # Data structures
│   └── gui.rs               # GUI components
├── helper/
│   ├── com.archify.helper.plist        # Helper entitlements
│   └── com.archify.helper.launchd.plist # Launchd service plist
├── build.sh                 # Build script
└── Cargo.toml              # Project configuration
```

### Building
```bash
# Build everything
./build.sh

# Build just the helper
cargo build --release --bin helper

# Build just the main app
cargo build --release

# Create app bundle
cargo bundle --release
```

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## Acknowledgments

- Original Archify project for the concept and approach
- `goblin` crate for fast Mach-O parsing
- `egui` for the modern GUI framework
- `cargo-bundle` for proper macOS app bundling 