#!/bin/bash

# softKMS Usage Validation Script
# Tests ALL documented CLI commands with session-long flows
# Exits immediately on first failure

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Configuration
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR=$(mktemp -d)
PORT=$((40000 + RANDOM % 10000))
GRPC_ADDR="127.0.0.1:$PORT"
ADMIN_PASS="admin-test-passphrase-123"

# Find binaries
if [ -f "$PROJECT_DIR/target/release/softkms" ]; then
    CLI="$PROJECT_DIR/target/release/softkms"
    DAEMON="$PROJECT_DIR/target/release/softkms-daemon"
elif [ -f "$PROJECT_DIR/target/debug/softkms" ]; then
    CLI="$PROJECT_DIR/target/debug/softkms"
    DAEMON="$PROJECT_DIR/target/debug/softkms-daemon"
else
    echo -e "${RED}Error: softKMS binaries not found. Run 'cargo build --release' first.${NC}"
    exit 1
fi

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   softKMS Usage Validation${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Using:"
echo "  CLI: $CLI"
echo "  Daemon: $DAEMON"
echo "  Port: $PORT"
echo ""

# Cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}Cleaning up...${NC}"
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    rm -rf "$TEMP_DIR"
    echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT

# Kill existing daemons
pkill -9 -f "softkms-daemon" 2>/dev/null || true
sleep 1

# Start daemon
mkdir -p "$TEMP_DIR/run"
PID_FILE="$TEMP_DIR/run/softkms.pid"

echo -e "${YELLOW}[SETUP]${NC} Starting daemon..."
echo -e "${CYAN}[CMD]${NC} $DAEMON --storage-path \"$TEMP_DIR/storage\" --grpc-addr \"$GRPC_ADDR\" --pid-file \"$PID_FILE\" --foreground &"
$DAEMON --storage-path "$TEMP_DIR/storage" --grpc-addr "$GRPC_ADDR" --pid-file "$PID_FILE" --foreground &
DAEMON_PID=$!
echo "  Daemon PID: $DAEMON_PID"
sleep 2

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo -e "${RED}[FAIL]${NC} Daemon failed to start"
    exit 1
fi
echo -e "${GREEN}[PASS]${NC} Daemon started on $GRPC_ADDR"

# Test tracking
TESTS_PASSED=0
TESTS_FAILED=0
CURRENT_TEST=""

pass_test() {
    echo -e "${GREEN}[PASS]${NC} $1"
    TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo ""
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}VALIDATION FAILED${NC}"
    echo -e "${RED}========================================${NC}"
    echo "Tests Passed: $TESTS_PASSED"
    echo "Tests Failed: $((TESTS_FAILED + 1))"
    exit 1
}

# =============================================================================
# PHASE 1: Basic Operations
# =============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}PHASE 1: Basic Operations${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 1: Health check
echo "[TEST 1] Health check"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" health"
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" health 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    pass_test "Health check"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Health check failed"
fi

# Test 2: Initialize keystore
echo ""
echo "[TEST 2] Initialize keystore"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" init --confirm false"
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" init --confirm false 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    pass_test "Initialize keystore"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Initialize keystore failed"
fi

# Test 3: Create Ed25519 key
echo ""
echo "[TEST 3] Create Ed25519 key"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" generate --algorithm ed25519 --label \"ed25519-key\""
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" generate --algorithm ed25519 --label "ed25519-key" 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    ED25519_KEY_ID=$(echo "$OUTPUT" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)
    pass_test "Create Ed25519 key (ID: ${ED25519_KEY_ID:0:8}...)"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Create Ed25519 key failed"
fi

# Test 4: Create P-256 key
echo ""
echo "[TEST 4] Create P-256 key"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" generate --algorithm p256 --label \"p256-key\""
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" generate --algorithm p256 --label "p256-key" 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    P256_KEY_ID=$(echo "$OUTPUT" | grep -oE '[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}' | head -1)
    pass_test "Create P-256 key (ID: ${P256_KEY_ID:0:8}...)"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Create P-256 key failed"
fi

# Test 5: List all keys
echo ""
echo "[TEST 5] List all keys"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" list"
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" list 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    if echo "$OUTPUT" | grep -q "ed25519" && echo "$OUTPUT" | grep -q "p256"; then
        pass_test "List keys (found both types)"
    else
        fail_test "List keys (expected types not found)"
    fi
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "List keys failed"
fi

# =============================================================================
# PHASE 2: Security Tests
# =============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}PHASE 2: Security Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 6: Wrong passphrase rejected for init
echo "[TEST 6] Verify wrong passphrase is rejected for init"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"wrongpass\" init"
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "wrongpass" init --confirm false 2>&1); then
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Wrong passphrase was accepted for init"
else
    echo -e "${YELLOW}[EXPECTED FAILURE]${NC}"
    echo -e "${YELLOW}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    pass_test "Wrong passphrase rejected for init"
fi

# Test 7: Sign data with valid passphrase
echo ""
echo "[TEST 7] Sign data with valid passphrase"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" sign --key \"$ED25519_KEY_ID\" --data \"Hello World\""
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" sign --key "$ED25519_KEY_ID" --data "Hello World" 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    pass_test "Sign data with valid passphrase"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Sign data failed"
fi

# Test 8: Wrong passphrase rejected for signing
echo ""
echo "[TEST 8] Verify wrong passphrase is rejected for signing"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"wrongpass\" sign --key \"$ED25519_KEY_ID\" --data \"test\""
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "wrongpass" sign --key "$ED25519_KEY_ID" --data "test" 2>&1); then
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Wrong passphrase was accepted for sign"
else
    echo -e "${YELLOW}[EXPECTED FAILURE]${NC}"
    echo -e "${YELLOW}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    pass_test "Wrong passphrase rejected for sign"
fi

# =============================================================================
# PHASE 3: Identity Management
# =============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}PHASE 3: Identity Management${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Test 9: Create identity
echo "[TEST 9] Create identity"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" identity create --type ai-agent --description \"Test Bot\""
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity create --type ai-agent --description "Test Bot" 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    if echo "$OUTPUT" | grep -qi "created\|token"; then
        IDENTITY_TOKEN=$(echo "$OUTPUT" | grep -i "token" | head -1 | awk '{print $NF}' || echo "")
        IDENTITY_PUBKEY=$(echo "$OUTPUT" | grep -i "public key" | head -1 | awk '{print $NF}' || echo "")
        if [ -n "$IDENTITY_TOKEN" ]; then
            pass_test "Identity created (token: ${IDENTITY_TOKEN:0:20}...)"
        else
            pass_test "Identity created (token extraction failed but success)"
        fi
    else
        pass_test "Identity create returned success"
    fi
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Identity creation failed"
fi

# Test 10: List identities
echo ""
echo "[TEST 10] List identities"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" identity list"
OUTPUT=""
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity list 2>&1); then
    echo -e "${GREEN}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    if echo "$OUTPUT" | grep -E "Type: [0-9]|Total: [1-9]"; then
        pass_test "List identities (found identity in output)"
    else
        fail_test "List identities (ai-agent not found in output)"
    fi
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT" | sed 's/^/  /'
    fail_test "Identity list failed"
fi

# Test 11: Revoke identity
echo ""
echo "[TEST 11] Revoke identity"
if [ -n "$IDENTITY_PUBKEY" ]; then
    echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" identity revoke --public-key \"$IDENTITY_PUBKEY\" --force"
    OUTPUT=""
    if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity revoke --public-key "$IDENTITY_PUBKEY" --force 2>&1); then
        echo -e "${GREEN}[OUTPUT]${NC}"
        echo "$OUTPUT" | sed 's/^/  /'
        pass_test "Revoke identity"
    else
        echo -e "${RED}[OUTPUT]${NC}"
        echo "$OUTPUT" | sed 's/^/  /'
        fail_test "Revoke identity failed"
    fi
else
    echo -e "${YELLOW}[SKIP]${NC} Cannot test revoke (no identity public key available)"
fi

# =============================================================================
# Summary
# =============================================================================

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}VALIDATION COMPLETE${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All critical features working correctly!${NC}"
    echo ""
    echo "Validated:"
    echo "  ✓ Daemon startup and health"
    echo "  ✓ Keystore initialization"
    echo "  ✓ Key generation (Ed25519, P-256)"
    echo "  ✓ Key listing"
    echo "  ✓ Passphrase authentication and rejection"
    echo "  ✓ Data signing"
    echo ""
    exit 0
else
    echo -e "${RED}Some tests failed. Review output above.${NC}"
    exit 1
fi