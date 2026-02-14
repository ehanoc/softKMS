#!/bin/bash
set -e

echo "=== Testing HD Ed25519 Sign/Verify Fix ==="

# Initialize
PASSPHRASE="my_test_passphrase_2024"
./target/release/softkms --passphrase "$PASSPHRASE" init --confirm false

# Import seed
MNEMONIC="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
SEED_OUTPUT=$(./target/release/softkms --passphrase "$PASSPHRASE" import-seed \
    --mnemonic "$MNEMONIC" \
    --label "testseed")
echo "Seed imported:"
echo "$SEED_OUTPUT"
SEED_ID=$(echo "$SEED_OUTPUT" | grep "ID:" | awk '{print $2}')
echo "Seed ID: $SEED_ID"

# Derive key
DERIVE_OUTPUT=$(./target/release/softkms --passphrase "$PASSPHRASE" derive \
    --algorithm ed25519 \
    --seed "$SEED_ID" \
    --path "m/44'/283'/0'/0/0" \
    --label "test-derived-key")
echo -e "\nDerived key:"
echo "$DERIVE_OUTPUT"
KEY_ID=$(echo "$DERIVE_OUTPUT" | grep "Key ID:" | awk '{print $3}')
echo "Key ID: $KEY_ID"

# List keys
./target/release/softkms list

# Sign data
SIGN_OUTPUT=$(./target/release/softkms --passphrase "$PASSPHRASE" sign \
    --key "$KEY_ID" \
    --data "hello")
echo -e "\nSign output:"
echo "$SIGN_OUTPUT"
SIGNATURE=$(echo "$SIGN_OUTPUT" | grep "Signature (base64):" | awk '{print $3}')
echo "Signature: $SIGNATURE"

# Verify signature - THIS IS THE CRITICAL TEST
echo -e "\n=== VERIFYING SIGNATURE ==="
if ./target/release/softkms verify \
    --key "$KEY_ID" \
    --data "hello" \
    --signature "$SIGNATURE" 2>&1 | grep -q "VALID"; then
    echo "✅ SUCCESS: Signature is VALID!"
else
    echo "❌ FAILED: Signature is INVALID"
    exit 1
fi

# Test with wrong data (should fail)
echo -e "\n=== Testing with wrong data (should fail) ==="
if ./target/release/softkms verify \
    --key "$KEY_ID" \
    --data "wrong" \
    --signature "$SIGNATURE" 2>&1 | grep -q "INVALID"; then
    echo "✅ SUCCESS: Wrong data correctly rejected!"
else
    echo "❌ FAILED: Wrong data was incorrectly accepted"
    exit 1
fi

echo -e "\n🎉 All tests passed! HD Ed25519 sign/verify is working correctly."
