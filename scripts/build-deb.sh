#!/bin/bash
# Build script for Debian packages
# Usage: ./scripts/build-deb.sh [amd64|arm64]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default architecture
ARCH="${1:-amd64}"

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}Error: Must run from project root directory${NC}"
    echo "Usage: cd /path/to/softKMS && ./scripts/build-deb.sh"
    exit 1
fi

echo -e "${YELLOW}=== softKMS Debian Package Builder ===${NC}"
echo ""

# Check dependencies
echo "Checking build dependencies..."
MISSING_DEPS=""

# Check for actual commands (not package names)
for cmd in dh dch cargo rustc; do
    if ! command -v "$cmd" &> /dev/null; then
        case "$cmd" in
            dh) MISSING_DEPS="$MISSING_DEPS debhelper" ;;
            dch) MISSING_DEPS="$MISSING_DEPS devscripts" ;;
            cargo) MISSING_DEPS="$MISSING_DEPS cargo" ;;
            rustc) MISSING_DEPS="$MISSING_DEPS rustc" ;;
        esac
    fi
done

if [ -n "$MISSING_DEPS" ]; then
    echo -e "${RED}Missing dependencies:$MISSING_DEPS${NC}"
    echo "Install with: sudo apt-get install$MISSING_DEPS"
    exit 1
fi

# Check for debian directory
if [ ! -d "debian" ]; then
    echo -e "${RED}Error: debian/ directory not found${NC}"
    echo "This script should be run from the softKMS source directory"
    exit 1
fi

# Check if debian/changelog exists
if [ ! -f "debian/changelog" ]; then
    echo -e "${RED}Error: debian/changelog not found${NC}"
    exit 1
fi

# Get package version
PKG_VERSION=$(dpkg-parsechangelog -S Version)
echo -e "${GREEN}Package version: $PKG_VERSION${NC}"
echo "Target architecture: $ARCH"
echo ""

# Create build directory
BUILD_DIR="debian-build-$ARCH"
mkdir -p "$BUILD_DIR"

echo "Step 1: Vendor dependencies..."
if [ ! -d "debian/vendor" ]; then
    echo "Creating vendor directory..."
    cargo vendor debian/vendor
else
    echo -e "${YELLOW}Vendor directory exists, skipping...${NC}"
fi
echo -e "${GREEN}✓ Dependencies vendored${NC}"
echo ""

echo "Step 2: Building source package..."
dpkg-buildpackage -S -us -uc -d 2>&1 | tee "$BUILD_DIR/build.log"
echo -e "${GREEN}✓ Source package built${NC}"
echo ""

# Check if we're using cowbuilder (for clean builds)
if command -v cowbuilder &> /dev/null; then
    echo "Step 3: Building binary package in clean chroot (cowbuilder)..."
    
    # Check if chroot exists
    if ! sudo cowbuilder --list-chroots 2>/dev/null | grep -q "trixie-$ARCH"; then
        echo -e "${YELLOW}Creating cowbuilder chroot for trixie-$ARCH...${NC}"
        sudo cowbuilder create \
            --distribution trixie \
            --architecture "$ARCH" \
            --mirror http://deb.debian.org/debian \
            --debootstrapopts --variant=buildd
    fi
    
    # Build in chroot
    sudo cowbuilder build \
        --architecture "$ARCH" \
        --buildresult "$BUILD_DIR" \
        "../softkms_${PKG_VERSION}.dsc" 2>&1 | tee -a "$BUILD_DIR/build.log"
    
else
    echo "Step 3: Building binary package locally..."
    echo -e "${YELLOW}Note: Install cowbuilder for clean builds${NC}"
    
    # Build locally
    dpkg-buildpackage -b -us -uc -a"$ARCH" 2>&1 | tee -a "$BUILD_DIR/build.log"
    
    # Move packages to build directory
    mv ../*.deb "$BUILD_DIR/" 2>/dev/null || true
fi

echo -e "${GREEN}✓ Binary package built${NC}"
echo ""

# Verify packages
echo "Step 4: Verifying packages..."
cd "$BUILD_DIR"

for pkg in *.deb; do
    if [ -f "$pkg" ]; then
        echo "Checking $pkg..."
        dpkg-deb -I "$pkg" | grep -E "^ Package:|^ Version:|^ Architecture:"
        
        # Run lintian if available
        if command -v lintian &> /dev/null; then
            echo "Running lintian..."
            lintian "$pkg" || true
        fi
        echo ""
    fi
done

cd ..

echo -e "${GREEN}=== Build Complete ===${NC}"
echo ""
echo "Packages built:"
ls -lh "$BUILD_DIR/"*.deb 2>/dev/null || echo "No .deb files found"
echo ""
echo -e "${YELLOW}To test installation:${NC}"
echo "  sudo dpkg -i $BUILD_DIR/softkms_${PKG_VERSION}_${ARCH}.deb"
echo "  sudo apt-get install -f  # if dependencies missing"
echo ""
echo -e "${YELLOW}To start the service:${NC}"
echo "  sudo systemctl start softkms"
echo "  sudo systemctl enable softkms"
echo ""
echo -e "${YELLOW}Build log saved to: $BUILD_DIR/build.log${NC}"
