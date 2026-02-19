#!/bin/bash

# softKMS REST API E2E Validation Script
# Tests all REST API endpoints
# Exits immediately on first failure

set -e

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
GRPC_PORT=$((40000 + RANDOM % 10000))
REST_PORT=$((40000 + RANDOM % 10000))
while [ "$REST_PORT" -eq "$GRPC_PORT" ]; do
    REST_PORT=$((40000 + RANDOM % 10000))
done

GRPC_ADDR="127.0.0.1:$GRPC_PORT"
REST_ADDR="127.0.0.1:$REST_PORT"
REST_URL="http://$REST_ADDR"
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
echo -e "${BLUE}   softKMS REST API E2E Tests${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""
echo "Using:"
echo "  CLI: $CLI"
echo "  Daemon: $DAEMON"
echo "  gRPC: $GRPC_ADDR"
echo "  REST: $REST_ADDR"
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

echo -e "${YELLOW}[SETUP]${NC} Starting daemon with REST enabled..."
echo -e "${CYAN}[CMD]${NC} $DAEMON --storage-path \"$TEMP_DIR/storage\" --grpc-addr \"$GRPC_ADDR\" --rest-addr \"$REST_ADDR\" --pid-file \"$PID_FILE\" --foreground &"
$DAEMON --storage-path "$TEMP_DIR/storage" --grpc-addr "$GRPC_ADDR" --rest-addr "$REST_ADDR" --pid-file "$PID_FILE" --foreground &
DAEMON_PID=$!
echo "  Daemon PID: $DAEMON_PID"
sleep 3

if ! kill -0 $DAEMON_PID 2>/dev/null; then
    echo -e "${RED}[FAIL]${NC} Daemon failed to start"
    exit 1
fi
echo -e "${GREEN}[PASS]${NC} Daemon started on gRPC:$GRPC_ADDR REST:$REST_ADDR"
echo ""

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
    TESTS_FAILED=$((TESTS_FAILED + 1))
    exit 1
}

# =============================================================================
# TEST 1: Health endpoint (no auth required)
# =============================================================================
echo -e "${YELLOW}[TEST 1]${NC} Health endpoint"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$REST_URL/health")
if [ "$HTTP_CODE" -eq 200 ]; then
    pass_test "Health endpoint returns 200"
else
    fail_test "Health endpoint returned $HTTP_CODE, expected 200"
fi

# =============================================================================
# TEST 2: Status endpoint (no auth required)
# =============================================================================
echo -e "${YELLOW}[TEST 2]${NC} Status endpoint"
RESPONSE=$(curl -s "$REST_URL/v1/status")
if echo "$RESPONSE" | grep -q "version"; then
    pass_test "Status endpoint returns version info"
else
    fail_test "Status endpoint missing version field"
fi

# =============================================================================
# TEST 3: List keys without auth (should fail)
# =============================================================================
echo -e "${YELLOW}[TEST 3]${NC} List keys without authentication"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$REST_URL/v1/keys")
if [ "$HTTP_CODE" -eq 401 ]; then
    pass_test "List keys without auth returns 401"
else
    fail_test "List keys without auth returned $HTTP_CODE, expected 401"
fi

# =============================================================================
# TEST 4: List keys with invalid token (should fail)
# =============================================================================
echo -e "${YELLOW}[TEST 4]${NC} List keys with invalid token"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer invalid-token" "$REST_URL/v1/keys")
if [ "$HTTP_CODE" -eq 401 ]; then
    pass_test "List keys with invalid token returns 401"
else
    fail_test "List keys with invalid token returned $HTTP_CODE, expected 401"
fi

# =============================================================================
# TEST 5: Initialize keystore via gRPC
# =============================================================================
echo -e "${YELLOW}[TEST 5]${NC} Initialize keystore via gRPC"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" init --confirm false"
if OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" init --confirm false 2>&1); then
    pass_test "Keystore initialized successfully"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$OUTPUT"
    fail_test "Keystore initialization failed"
fi

# =============================================================================
# TEST 6: Create identity via gRPC
# =============================================================================
echo -e "${YELLOW}[TEST 6]${NC} Create identity via gRPC"
echo -e "${CYAN}[CMD]${NC} $CLI --server \"http://$GRPC_ADDR\" -p \"$ADMIN_PASS\" identity create --type ai-agent --description \"REST Test Identity\""
IDENTITY_OUTPUT=$($CLI --server "http://$GRPC_ADDR" -p "$ADMIN_PASS" identity create --type ai-agent --description "REST Test Identity" 2>&1) || true

# Extract token and public key
TOKEN=$(echo "$IDENTITY_OUTPUT" | grep -oE 'Token: [a-zA-Z0-9_-]+' | awk '{print $2}')
PUBKEY=$(echo "$IDENTITY_OUTPUT" | grep -oE 'Public Key: [a-zA-Z0-9_-]+' | awk '{print $3}')

if [ -n "$TOKEN" ] && [ -n "$PUBKEY" ]; then
    pass_test "Identity created successfully"
    echo "  Token: ${TOKEN:0:20}..."
    echo "  Public Key: ${PUBKEY:0:20}..."
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$IDENTITY_OUTPUT"
    fail_test "Identity creation failed"
fi

# =============================================================================
# TEST 7: List keys with valid token
# =============================================================================
echo -e "${YELLOW}[TEST 7]${NC} List keys with valid token"
RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$REST_URL/v1/keys")
if echo "$RESPONSE" | grep -q "keys"; then
    pass_test "List keys with valid token works"
else
    fail_test "List keys with valid token failed"
fi

# =============================================================================
# TEST 8: Create key via REST
# =============================================================================
echo -e "${YELLOW}[TEST 8]${NC} Create key via REST"
CREATE_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"algorithm": "ed25519", "label": "rest-test-key"}' \
    "$REST_URL/v1/keys")

KEY_ID=$(echo "$CREATE_RESPONSE" | grep -oE '"key_id":"[^"]+"' | cut -d'"' -f4)

if [ -n "$KEY_ID" ]; then
    pass_test "Key created via REST: $KEY_ID"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$CREATE_RESPONSE"
    fail_test "Key creation via REST failed"
fi

# =============================================================================
# TEST 9: Get key details via REST
# =============================================================================
echo -e "${YELLOW}[TEST 9]${NC} Get key details via REST"
GET_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$REST_URL/v1/keys/$KEY_ID")

if echo "$GET_RESPONSE" | grep -q "key_id"; then
    pass_test "Get key details works"
    echo "  Key ID: $(echo "$GET_RESPONSE" | grep -oE '"key_id":"[^"]+"' | cut -d'"' -f4)"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$GET_RESPONSE"
    fail_test "Get key details failed"
fi

# =============================================================================
# TEST 10: Sign data via REST
# =============================================================================
echo -e "${YELLOW}[TEST 10]${NC} Sign data via REST"
# Base64 encode test data
TEST_DATA="$(echo -n 'test data to sign' | base64)"
SIGN_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"data\": \"$TEST_DATA\"}" \
    "$REST_URL/v1/keys/$KEY_ID/sign")

if echo "$SIGN_RESPONSE" | grep -q "signature"; then
    pass_test "Sign via REST works"
    SIGNATURE=$(echo "$SIGN_RESPONSE" | grep -oE '"signature":"[^"]+"' | cut -d'"' -f4)
    echo "  Signature: ${SIGNATURE:0:40}..."
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$SIGN_RESPONSE"
    fail_test "Sign via REST failed"
fi

# =============================================================================
# TEST 11: Verify signature via REST
# =============================================================================
echo -e "${YELLOW}[TEST 11]${NC} Verify signature via REST"
VERIFY_RESPONSE=$(curl -s -X POST \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"data\": \"$TEST_DATA\", \"signature\": \"$SIGNATURE\"}" \
    "$REST_URL/v1/keys/$KEY_ID/verify")

if echo "$VERIFY_RESPONSE" | grep -q '"valid":true'; then
    pass_test "Verify signature via REST works"
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$VERIFY_RESPONSE"
    fail_test "Verify signature via REST failed"
fi

# =============================================================================
# TEST 12: Get identity info via REST
# =============================================================================
echo -e "${YELLOW}[TEST 12]${NC} Get identity info via REST"
IDENTITY_RESPONSE=$(curl -s -H "Authorization: Bearer $TOKEN" "$REST_URL/v1/identities/me")

if echo "$IDENTITY_RESPONSE" | grep -q "public_key"; then
    pass_test "Get identity info works"
    IDENTITY_PUBKEY=$(echo "$IDENTITY_RESPONSE" | grep -oE '"public_key":"[^"]+"' | cut -d'"' -f4)
    if [ "$IDENTITY_PUBKEY" = "$PUBKEY" ]; then
        pass_test "Identity public key matches"
    fi
else
    echo -e "${RED}[OUTPUT]${NC}"
    echo "$IDENTITY_RESPONSE"
    fail_test "Get identity info failed"
fi

# =============================================================================
# TEST 13: Custom x-softkms-token header
# =============================================================================
echo -e "${YELLOW}[TEST 13]${NC} Custom x-softkms-token header"
HEADER_RESPONSE=$(curl -s -H "x-softkms-token: $TOKEN" "$REST_URL/v1/keys")

if echo "$HEADER_RESPONSE" | grep -q "keys"; then
    pass_test "x-softkms-token header works"
else
    fail_test "x-softkms-token header failed"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}REST API E2E TESTS PASSED${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo ""
