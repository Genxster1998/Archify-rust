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

print_status "Building SMJobBless installer..."
make

if [ $? -ne 0 ]; then
    print_error "Failed to build smjobbless_installer"
    exit 1
fi

print_status "Creating app bundle..."
cargo bundle --release

if [ $? -ne 0 ]; then
    print_error "Failed to create app bundle"
    exit 1
fi

# Correct macOS bundle layout for privileged helper
APP_BUNDLE="target/release/bundle/osx/Archify.app"
LAUNCHSERVICES_DIR="$APP_BUNDLE/Contents/Library/LaunchServices"
HELPER_SOURCE="target/release/helper"
HELPER_PLIST_SOURCE="helper/com.archify.helper.plist"
INSTALLER_SOURCE="smjobbless_installer"

if [ ! -f "$HELPER_SOURCE" ]; then
    print_error "Helper binary not found at $HELPER_SOURCE"
    exit 1
fi

if [ ! -d "$APP_BUNDLE" ]; then
    print_error "App bundle not found at $APP_BUNDLE"
    exit 1
fi

if [ ! -f "$INSTALLER_SOURCE" ]; then
    print_error "smjobbless_installer not found. Did make succeed?"
    exit 1
fi

mkdir -p "$LAUNCHSERVICES_DIR"

# Copy helper binary, plist, and installer to LaunchServices
cp "$HELPER_SOURCE" "$LAUNCHSERVICES_DIR/com.archify.helper"
cp "$HELPER_PLIST_SOURCE" "$LAUNCHSERVICES_DIR/com.archify.helper.plist"
cp "$INSTALLER_SOURCE" "$LAUNCHSERVICES_DIR/smjobbless_installer"
chmod +x "$LAUNCHSERVICES_DIR/com.archify.helper"
chmod +x "$LAUNCHSERVICES_DIR/smjobbless_installer"

print_status "Helper binary, plist, and installer copied to: $LAUNCHSERVICES_DIR"

# Optional: Sign the app bundle (if you have a developer certificate)
if command -v codesign &> /dev/null; then
    print_warning "To sign the app bundle, run:"
    echo "codesign --deep --sign 'Developer ID Application: Your Name (TEAMID)' $APP_BUNDLE"
fi

print_status "Build completed successfully! 🎉" 