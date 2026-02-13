#!/bin/bash
# Test runner for softKMS
# Runs all test suites: unit, integration, and e2e

set -e

echo "==================================="
echo "softKMS Test Suite"
echo "==================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
UNIT_PASSED=0
UNIT_FAILED=0
INTEGRATION_PASSED=0
INTEGRATION_FAILED=0
E2E_PASSED=0
E2E_FAILED=0

# Function to run tests with timeout
run_tests() {
    local test_type=$1
    local test_args=$2
    local timeout_seconds=300
    
    echo ""
    echo "-----------------------------------"
    echo "Running $test_type tests..."
    echo "-----------------------------------"
    
    if timeout $timeout_seconds cargo test $test_args -- --nocapture; then
        echo -e "${GREEN}✓ $test_type tests passed${NC}"
        return 0
    else
        echo -e "${RED}✗ $test_type tests failed${NC}"
        return 1
    fi
}

# Check for required tools
echo "Checking prerequisites..."
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: cargo not found. Please install Rust.${NC}"
    exit 1
fi

# Build first
echo ""
echo "Building project..."
cargo build --release --quiet

# Run unit tests (in source files)
echo ""
echo "==================================="
echo "Unit Tests"
echo "==================================="
if run_tests "Unit" "--lib"; then
    UNIT_PASSED=1
else
    UNIT_FAILED=1
fi

# Run integration tests
echo ""
echo "==================================="
echo "Integration Tests"
echo "==================================="
if run_tests "Integration" "--test '*'"; then
    INTEGRATION_PASSED=1
else
    INTEGRATION_FAILED=1
fi

# Run e2e tests
echo ""
echo "==================================="
echo "E2E Tests"
echo "==================================="
if run_tests "E2E" "--test 'e2e::*'"; then
    E2E_PASSED=1
else
    E2E_FAILED=1
fi

# Summary
echo ""
echo "==================================="
echo "Test Summary"
echo "==================================="

TOTAL_PASSED=0
TOTAL_FAILED=0

if [ $UNIT_PASSED -eq 1 ]; then
    echo -e "${GREEN}✓ Unit Tests: PASSED${NC}"
    ((TOTAL_PASSED++))
else
    echo -e "${RED}✗ Unit Tests: FAILED${NC}"
    ((TOTAL_FAILED++))
fi

if [ $INTEGRATION_PASSED -eq 1 ]; then
    echo -e "${GREEN}✓ Integration Tests: PASSED${NC}"
    ((TOTAL_PASSED++))
else
    echo -e "${RED}✗ Integration Tests: FAILED${NC}"
    ((TOTAL_FAILED++))
fi

if [ $E2E_PASSED -eq 1 ]; then
    echo -e "${GREEN}✓ E2E Tests: PASSED${NC}"
    ((TOTAL_PASSED++))
else
    echo -e "${RED}✗ E2E Tests: FAILED${NC}"
    ((TOTAL_FAILED++))
fi

echo ""
echo "Total: $TOTAL_PASSED passed, $TOTAL_FAILED failed"

if [ $TOTAL_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
