# PKCS#11 Usage Examples

This document provides practical examples of using softKMS as a PKCS#11 backend with common tools.

## Prerequisites

1. **Build softKMS**:
   ```bash
   cargo build
   ```

2. **Start the daemon**:
   ```bash
   ./target/debug/softkms-daemon &
   ```

3. **Initialize the keystore** (first time only):
   ```bash
   ./target/debug/softkms -p <your-passphrase> init --confirm false
   ```

## Testing with pkcs11-tool

### List Available Slots

```bash
pkcs11-tool --module target/debug/libsoftkms.so --list-slots
```

Expected output:
```
Available slots:
Slot 0: softKMS
```

### List Mechanisms

```bash
pkcs11-tool --module target/debug/libsoftkms.so --list-mechanisms
```

### Generate EC Key (P-256)

**Important**: Due to a known pkcs11-tool issue, you must specify the mechanism explicitly:

```bash
pkcs11-tool --module target/debug/libsoftkms.so \
  --token-label softKMS \
  --login --pin <your-passphrase> \
  --keypairgen \
  --key-type EC:prime256v1 \
  --label my-ec-key \
  -m 0x1050
```

### Sign Data

```bash
echo "Hello World" > data.txt

pkcs11-tool --module target/debug/libsoftkms.so \
  --token-label softKMS \
  --login --pin <your-passphrase> \
  --sign \
  --label my-ec-key \
  --input-file data.txt \
  --output-file signature.bin \
  -m 0x1001
```

### Verify Signature

```bash
pkcs11-tool --module target/debug/libsoftkms.so \
  --token-label softKMS \
  --login --pin <your-passphrase> \
  --verify \
  --label my-ec-key \
  --input-file data.txt \
  --signature-file signature.bin \
  -m 0x1001
```

## Using with OpenSSH

### Configure SSH to Use PKCS#11

```bash
export SSH_PKCS11_MODULE=target/debug/libsoftkms.so
```

### List SSH Keys

```bash
ssh-keygen -D target/debug/libsoftkms.so -l
```

### Use with SSH

```bash
ssh -I target/debug/libsoftkms.so user@hostname
```

## Using with Git

### Configure Git to Use SSH PKCS#11

```bash
export GIT_SSH_COMMAND="ssh -I target/debug/libsoftkms.so"
```

### Clone and Use

```bash
git clone git@github.com:user/repo.git
cd repo
# Commits will be signed if configured
```

## Using with OpenSSL

### Create Private Key (Export)

This demonstrates key usage - in production, keys stay in the HSM:

```bash
# Note: OpenSSL engine setup required for PKCS#11
# This is for demonstration of the concept
```

## Using with Our Custom Test Program

We provide a custom test program at `tests/pkcs11/test_pkcs11`:

```bash
cd tests/pkcs11
# Compile if needed:
# gcc -o test_pkcs11 test_pkcs11.c -ldl

./test_pkcs11
```

This test program directly uses the PKCS#11 API without relying on pkcs11-tool's mechanism validation.

## Troubleshooting

### Error: "Generate EC key mechanism 1040 not supported"

This is a known pkcs11-tool issue. Use explicit mechanism:

```bash
-m 0x1050
```

### Error: "CKR_KEY_HANDLE_INVALID"

The keystore may not be initialized. Run:

```bash
./target/debug/softkms -p <passphrase> init --confirm false
```

### Error: "Failed to connect to daemon"

Make sure the daemon is running:

```bash
pgrep softkms-daemon
# Or start it:
./target/debug/softkms-daemon &
```

## Complete Workflow Example

```bash
# 1. Start fresh
pkill softkms-daemon || true
rm -rf ~/.softKMS

# 2. Start daemon
./target/debug/softkms-daemon &
sleep 2

# 3. Initialize
./target/debug/softkms -p mysecret123 init --confirm false

# 4. Generate a key
pkcs11-tool --module target/debug/libsoftkms.so \
  --token-label softKMS \
  --login --pin mysecret123 \
  --keypairgen \
  --key-type EC:prime256v1 \
  --label github-key \
  -m 0x1050

# 5. Verify key exists
./target/debug/softkms -p mysecret123 list
```

## Security Notes

1. **Never share your passphrase**
2. **Keys remain in daemon** - they are not exported
3. **Use strong passphrases** in production
4. **Daemon runs locally** - not accessible over network by default
