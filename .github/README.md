# GitHub Actions Workflows

This directory contains GitHub Actions workflows for building and releasing the Archify Rust application.

## Workflows

### 1. Build and Test (`build.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` branch

**Purpose:**
- Runs tests on both x86_64 and arm64 architectures
- Builds the application for both architectures
- Creates app bundles with proper structure
- Verifies the build artifacts
- Uploads build artifacts for inspection

**Artifacts:**
- App bundles for both architectures
- Available for 7 days

### 2. Build and Release (`release.yml`)

**Triggers:**
- Push of tags starting with `v*` (e.g., `v0.2.1`)
- Manual workflow dispatch with version input

**Purpose:**
- Builds the application for both x86_64 and arm64 architectures
- Creates universal binary (works on both Intel and Apple Silicon)
- Creates DMG installers for each architecture and universal
- Creates a GitHub release with all DMG files
- Generates release notes automatically

**Artifacts:**
- Universal DMG (recommended for all users)
- x86_64 DMG (Intel Macs only)
- arm64 DMG (Apple Silicon Macs only)
- App bundles for each architecture

## How to Use

### For Testing Builds

1. Push to `main` or `develop` branch
2. The `build.yml` workflow will automatically run
3. Check the Actions tab to see build results
4. Download artifacts if needed for testing

### For Creating Releases

#### Option 1: Tag-based Release
```bash
# Create and push a tag
git tag v0.2.1
git push origin v0.2.1
```

#### Option 2: Manual Release
1. Go to the Actions tab in GitHub
2. Select "Build and Release" workflow
3. Click "Run workflow"
4. Enter the version (e.g., `v0.2.1`)
5. Click "Run workflow"

## Build Process

The workflows perform the following steps:

1. **Setup Environment**
   - Install Rust toolchain for target architectures
   - Install cargo-bundle for app bundling
   - Install Xcode Command Line Tools
   - Install clang for SMJobBless installer

2. **Create Icon**
   - Convert PNG icon to ICNS format
   - Generate multiple icon sizes for macOS

3. **Build Components**
   - Build helper binary
   - Build main application
   - Build SMJobBless installer
   - Create app bundle using cargo-bundle

4. **Setup App Bundle**
   - Create LaunchServices directory structure
   - Copy helper binary, plist, and installer
   - Set proper executable permissions

5. **Create Universal Binary** (Release only)
   - Combine x86_64 and arm64 binaries using `lipo`
   - Create universal app bundle

6. **Create DMG Installers** (Release only)
   - Create DMG for each architecture
   - Create universal DMG
   - Include proper icons and layout

7. **Release** (Release only)
   - Create GitHub release
   - Upload all DMG files
   - Generate release notes

## Requirements

- macOS runners (required for building macOS apps)
- Rust toolchain
- Xcode Command Line Tools
- cargo-bundle crate
- create-dmg tool (installed via Homebrew)

## Troubleshooting

### Common Issues

1. **Build fails on helper binary**
   - Check that all dependencies are properly specified in Cargo.toml
   - Verify that the helper binary compiles locally

2. **App bundle creation fails**
   - Ensure cargo-bundle is properly configured in Cargo.toml
   - Check that all required files exist

3. **DMG creation fails**
   - Verify that create-dmg is available
   - Check that icon.icns file is created properly

4. **Universal binary creation fails**
   - Ensure both architectures build successfully
   - Check that lipo command is available

### Local Testing

To test the build process locally:

```bash
# Install cargo-bundle
cargo install cargo-bundle

# Create ICNS icon
./scripts/create_icns.sh

# Build for both architectures
cargo build --release --target x86_64-apple-darwin
cargo build --release --target aarch64-apple-darwin

# Create app bundles
cargo bundle --release --target x86_64-apple-darwin
cargo bundle --release --target aarch64-apple-darwin
```

## Notes

- The workflows use caching to speed up builds
- Build artifacts are retained for different periods (7 days for test builds, 30 days for releases)
- The universal binary is created only during releases to save build time
- All builds include the privileged helper and SMJobBless installer 