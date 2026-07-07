#!/bin/bash

set -euo pipefail

echo "🚀 Building Archify Rust Application..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if we're on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_error "This script is designed for macOS only"
    exit 1
fi

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    print_error "Rust/Cargo is not installed. Please install Rust first."
    exit 1
fi

# Check if cargo-bundle is installed
if ! cargo bundle --version &> /dev/null; then
    print_warning "cargo-bundle not found. Installing..."
    cargo install cargo-bundle
fi

print_status "Building helper binary..."
cargo build --release --bin helper

if [ $? -ne 0 ]; then
    print_error "Failed to build helper binary"
    exit 1
fi

print_status "Building main application..."
cargo build --release

if [ $? -ne 0 ]; then
    print_error "Failed to build main application"
    exit 1
fi

print_status "Creating app bundle..."
cargo bundle --release

if [ $? -ne 0 ]; then
    print_error "Failed to create app bundle"
    exit 1
fi

# Copy helper binary to MacOS directory
APP_BUNDLE="target/release/bundle/osx/Archify.app"
MACOS_DIR="$APP_BUNDLE/Contents/MacOS"
HELPER_SOURCE="target/release/helper"

if [ ! -f "$HELPER_SOURCE" ]; then
    print_error "Helper binary not found at $HELPER_SOURCE"
    exit 1
fi

if [ ! -d "$APP_BUNDLE" ]; then
    print_error "App bundle not found at $APP_BUNDLE"
    exit 1
fi

cp "$HELPER_SOURCE" "$MACOS_DIR/helper"
chmod +x "$MACOS_DIR/helper"

print_status "Helper binary copied to: $MACOS_DIR"

# Copy manually provided icon.icns into Resources and update Info.plist
RESOURCES_DIR="$APP_BUNDLE/Contents/Resources"
mkdir -p "$RESOURCES_DIR"

if [ -f "assets/icon.icns" ]; then
    print_status "Copying assets/icon.icns to Resources..."
    cp "assets/icon.icns" "$RESOURCES_DIR/Archify.icns"
    plutil -replace CFBundleIconFile -string "Archify.icns" "$APP_BUNDLE/Contents/Info.plist"
elif [ -f "assets/icon.png" ]; then
    print_warning "assets/icon.icns not found, copying icon.png as fallback..."
    cp "assets/icon.png" "$RESOURCES_DIR/Archify.png"
    plutil -replace CFBundleIconFile -string "Archify.png" "$APP_BUNDLE/Contents/Info.plist"
fi

# Optional: Sign the app bundle (if you have a developer certificate)
if command -v codesign &> /dev/null; then
    print_warning "To sign the app bundle, run:"
    echo "codesign --deep --sign 'Developer ID Application: Your Name (TEAMID)' $APP_BUNDLE"
fi

print_status "Build completed successfully! 🎉" 