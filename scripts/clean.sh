#!/bin/bash
# Cleanup script for softKMS build artifacts
# Usage: ./scripts/clean.sh [options]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
DRY_RUN=false
VERBOSE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -n, --dry-run    Show what would be deleted without deleting"
            echo "  -v, --verbose    Show detailed output"
            echo "  -h, --help       Show this help message"
            echo ""
            echo "This script cleans up build artifacts from:"
            echo "  - Rust/Cargo builds"
            echo "  - Debian packaging"
            echo "  - Test artifacts"
            echo "  - Generated files"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage"
            exit 1
            ;;
    esac
done

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}Error: Must run from project root directory${NC}"
    exit 1
fi

echo -e "${BLUE}=== softKMS Cleanup ===${NC}"
echo ""

# Calculate initial size
if command -v du &> /dev/null; then
    INITIAL_SIZE=$(du -sh . 2>/dev/null | cut -f1)
    echo "Current directory size: $INITIAL_SIZE"
    echo ""
fi

# Function to safely remove
clean_path() {
    local path="$1"
    local description="$2"
    
    if [ -e "$path" ]; then
        if [ "$DRY_RUN" = true ]; then
            echo -e "${YELLOW}[DRY-RUN] Would delete:${NC} $description ($path)"
        else
            if [ "$VERBOSE" = true ]; then
                echo -e "${RED}Deleting:${NC} $description ($path)"
            fi
            rm -rf "$path"
        fi
    else
        if [ "$VERBOSE" = true ]; then
            echo -e "${GREEN}Already clean:${NC} $description"
        fi
    fi
}

echo "Cleaning Rust/Cargo artifacts..."
clean_path "target" "Rust build directory"
clean_path "cli/target" "CLI build directory"

echo ""
echo "Cleaning Debian packaging artifacts..."
clean_path "debian/tmp" "Debian temp files"
clean_path "debian/softkms" "Debian softkms staging"
clean_path "debian/softkms-pkcs11" "Debian softkms-pkcs11 staging"
clean_path "debian/.debhelper" "Debian helper files"
clean_path "debian/vendor" "Vendored dependencies"
clean_path "debian/cargo-home" "Cargo home for Debian builds"
clean_path "debian-build*" "Build directories"

echo ""
echo "Cleaning generated files..."
clean_path "debian/files" "Debian files list"
clean_path "debian/*.substvars" "Debian substitution variables"
clean_path "debian/*.debhelper.log" "Debian helper logs"
clean_path "debian/debhelper-build-stamp" "Debian build stamp"

echo ""
echo "Cleaning built packages..."
if [ -d ".." ]; then
    # Go to parent directory and clean
    pushd .. > /dev/null 2>&1 || exit 1
    clean_path "*.deb" "Built .deb packages"
    clean_path "*.changes" "Debian changes files"
    clean_path "*.buildinfo" "Debian build info files"
    clean_path "*.dsc" "Debian source control files"
    clean_path "*.tar.gz" "Tar archives"
    clean_path "*.tar.xz" "Tar archives"
    popd > /dev/null 2>&1 || exit 1
fi

echo ""
echo "Cleaning test artifacts..."
clean_path "*.profraw" "Profiling raw data"
clean_path "*.profdata" "Profiling data"
clean_path "tarpaulin-report.html" "Tarpaulin coverage report"

# Run cargo clean if available
if command -v cargo &> /dev/null; then
    if [ "$DRY_RUN" = false ]; then
        echo ""
        echo "Running cargo clean..."
        cargo clean 2>/dev/null || true
    else
        echo ""
        echo -e "${YELLOW}[DRY-RUN] Would run: cargo clean${NC}"
    fi
fi

echo ""
echo -e "${GREEN}=== Cleanup Complete ===${NC}"

# Calculate final size
if command -v du &> /dev/null; then
    FINAL_SIZE=$(du -sh . 2>/dev/null | cut -f1)
    echo "Final directory size: $FINAL_SIZE"
    
    # This is a rough estimate since we don't track exact bytes
    echo ""
    echo "Note: Significant space saved from target/ and debian/vendor/ directories"
fi

if [ "$DRY_RUN" = true ]; then
    echo ""
    echo -e "${YELLOW}This was a dry-run. No files were actually deleted.${NC}"
    echo "Run without -n flag to actually clean."
fi
