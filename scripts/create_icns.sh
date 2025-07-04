#!/bin/bash

set -euo pipefail

echo "🎨 Creating ICNS file from PNG icon..."

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

# Check if icon.png exists
if [ ! -f "assets/icon.png" ]; then
    print_error "assets/icon.png not found"
    exit 1
fi

# Create iconset directory
ICONSET_DIR="assets/icon.iconset"
mkdir -p "$ICONSET_DIR"

print_status "Creating icon sizes..."

# Create different icon sizes
sips -z 16 16     assets/icon.png --out "$ICONSET_DIR/icon_16x16.png"
sips -z 32 32     assets/icon.png --out "$ICONSET_DIR/icon_16x16@2x.png"
sips -z 32 32     assets/icon.png --out "$ICONSET_DIR/icon_32x32.png"
sips -z 64 64     assets/icon.png --out "$ICONSET_DIR/icon_32x32@2x.png"
sips -z 128 128   assets/icon.png --out "$ICONSET_DIR/icon_128x128.png"
sips -z 256 256   assets/icon.png --out "$ICONSET_DIR/icon_128x128@2x.png"
sips -z 256 256   assets/icon.png --out "$ICONSET_DIR/icon_256x256.png"
sips -z 512 512   assets/icon.png --out "$ICONSET_DIR/icon_256x256@2x.png"
sips -z 512 512   assets/icon.png --out "$ICONSET_DIR/icon_512x512.png"
sips -z 1024 1024 assets/icon.png --out "$ICONSET_DIR/icon_512x512@2x.png"

print_status "Converting to ICNS format..."

# Convert iconset to ICNS
iconutil -c icns "$ICONSET_DIR" -o "assets/icon.icns"

# Clean up iconset directory
rm -rf "$ICONSET_DIR"

print_status "ICNS file created successfully at assets/icon.icns! 🎉" 