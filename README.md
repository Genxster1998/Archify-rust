<p align="center">
  <img src="https://raw.githubusercontent.com/Genxster1998/archify-rust/main/assets/icon.png" width="128" height="128" alt="Archify Logo">
</p>

# Archify Rust

A modern Rust implementation of Archify for removing unnecessary ARM64e/ARM64 code from macOS universal binaries. This tool helps reduce disk space usage by removing unwanted architectures from applications.

## Features

- **Reclaim Disk Space**: Easily remove unused binary architectures (like `x86_64` or `arm64e`) from macOS applications to free up gigabytes of storage.
- **Smart App Detection**: Scans your `/Applications` directory to identify universal binaries, displaying the exact amount of space you can save.
- **On-Demand Elevation**: Prompts for administrative privileges only when processing system apps.
- **Modern User Interface**: A native, responsive macOS application list with crisp high-DPI icons and a real-time progress log.
- **Flexible Processing**: Thin multiple applications at once, filter by App Store downloads, or process custom files and folders outside standard directories.
- **Safety First**: Only modifies fat binaries in place and automatically signs them afterward to ensure they run correctly on your Mac.

## Screenshots

<p align="center">
  <img src="https://raw.githubusercontent.com/Genxster1998/archify-rust/main/screenshots/SCR1.png" width="800" alt="Main Scan Screen">
  <br><br>
  <img src="https://raw.githubusercontent.com/Genxster1998/archify-rust/main/screenshots/SCR2.png" width="800" alt="Scanning Progress">
  <br><br>
  <img src="https://raw.githubusercontent.com/Genxster1998/archify-rust/main/screenshots/SCR3.png" width="800" alt="Detailed Processing Logs">
  <br><br>
  <img src="https://raw.githubusercontent.com/Genxster1998/archify-rust/main/screenshots/SCR4.png" width="800" alt="Settings Configuration">
</p>

---

## Installation

### Prerequisites
- macOS 10.15 or later.
- Administrator privileges (prompted on-demand when processing protected system folders like `/Applications`).

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

3. **Install the app bundle**:
   ```bash
   # Copy to Applications folder
   cp -r target/release/bundle/osx/Archify.app /Applications/
   
   # Or run directly
   open target/release/bundle/osx/Archify.app
   ```

---

## Usage

### GUI Mode (Recommended)

1. **Launch Archify** from Applications or your build directory.
2. **Scan Applications**:
   - Click "Scan Applications" to discover fat binaries in `/Applications`.
   - Add custom scan directories in Settings.
   - Toggle filters to only list Universal/Fat binaries or Mac App Store apps.
3. **Select & Estimate**:
   - Check the apps you want to thin.
   - Review the calculated total size and estimated savable space.
4. **Process**:
   - Click "Process Selected".
   - If any chosen app is in a protected system folder, macOS will display a single prompt requesting your administrator password.
   - Monitor detailed, step-by-step progress under the **Logs** tab.

### Manual Thinning Tab
For binaries located outside scanned paths:
1. Navigate to the **Manual Thinning** tab.
2. Drag or select individual `.app` bundles.
3. Click "Process Selected Binaries".

---

## Configuration

### Settings Tab
- **Target Architecture**: Choose between `x86_64`, `arm64`, or `arm64e`.
- **Signing Options**: Choose `codesign` or `ldid` to automatically resign thinned binaries.
- **Scan Locations**: Add or remove custom folders to include in searches.

---

## Development

### Project Structure
```
archify-rust/
├── src/
│   ├── main.rs              # Main application entry point
│   ├── app.rs               # GUI application layout and logic
│   ├── bin/helper.rs        # Privileged helper CLI binary
│   ├── file_operations.rs   # Universal binary detection and local file operations
│   ├── privileged_helper.rs # Elevated on-demand script wrapping (osascript)
│   ├── types.rs             # Data structures and enums
│   └── icon_loader.rs       # Native Cocoa high-DPI icon loader (Retina support)
├── assets/                  # PNG and ICNS graphics assets
├── build.sh                 # Unified build and packaging script
└── Cargo.toml              # Cargo crate configuration
```

---

## License

This project is licensed under the GPL-3.0 License - see the LICENSE file for details.

## Acknowledgments

- Original Archify project for the concept and approach.
- `goblin` crate for fast Mach-O parsing.
- `egui` and `eframe` for the GUI framework.
- `objc2` for type-safe native Apple Cocoa bindings.
- `cargo-bundle` for macOS app bundle staging.
