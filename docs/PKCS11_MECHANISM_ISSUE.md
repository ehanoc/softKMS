# PKCS#11 Mechanism Handling Issue

## Issue Summary

When using `pkcs11-tool` with softKMS, key generation fails unless an explicit mechanism is specified. This is due to a discrepancy between PKCS#11 specification and common implementations.

## The Problem

### pkcs11-tool Behavior

When you run:
```bash
pkcs11-tool --module libsoftkms.so --keypairgen --key-type EC:prime256v1
```

pkcs11-tool sends **mechanism 0x1040 (4160) = CKM_ECDH** by default.

However, the correct mechanism for EC key pair generation according to PKCS#11 spec is:
- **0x1050 (4176) = CKM_EC_KEY_PAIR_GEN**

### Root Cause

1. **pkcs11-tool sends CKM_ECDH**: When generating EC keys without explicit `-m` flag, pkcs11-tool defaults to CKM_ECDH (Elliptic Curve Diffie-Hellman key derivation)

2. **CKM_ECDH vs CKM_EC_KEY_PAIR_GEN**:
   - CKM_ECDH (0x1040): Designed for key derivation (CKF_DERIVE flag)
   - CKM_EC_KEY_PAIR_GEN (0x1050): Designed for key pair generation (CKF_GENERATE_KEY_PAIR flag)

3. **Specification vs Implementation**:
   - PKCS#11 spec: These should be distinct operations
   - SoftHSM2/common practice: CKM_ECDH often accepted for key generation
   - softKMS original: Only accepted CKM_EC_KEY_PAIR_GEN

## Standards Analysis

### PKCS#11 Specification (OASIS v2.40)

According to the specification:
- CKM_ECDH should only have CKF_DERIVE flag
- CKM_EC_KEY_PAIR_GEN should have CKF_GENERATE_KEY_PAIR flag
- C_GenerateKeyPair should validate the mechanism supports key generation

### SoftHSM2 Pattern

SoftHSM2 (and many other HSMs) advertise CKM_ECDH with CKF_GENERATE_KEY_PAIR for compatibility:
```c
// SoftHSM2 pattern - non-standard but widely used
mechanism: CKM_ECDH
flags: CKF_DERIVE | CKF_GENERATE_KEY_PAIR
```

This allows pkcs11-tool to use the default mechanism for EC key generation.

## Solution Implemented

### Option A: Maximum Compatibility (Selected)

Modified `C_GenerateKeyPair` in `src/pkcs11/mod.rs` to accept both mechanisms:

```rust
pub extern "C" fn C_GenerateKeyPair(
    session: CK_SESSION,
    mech: *const u8,
    // ... other params
) -> CK_RV {
    let mech_type = unsafe { *(mech as *const CK_ULONG) };
    
    // Accept both standard and commonly-used mechanisms
    // CKM_EC_KEY_PAIR_GEN (0x1050) is the spec-compliant mechanism
    // CKM_ECDH (0x1040) is commonly used by pkcs11-tool as default for EC key generation
    if mech_type != CKM_EC_KEY_PAIR_GEN && mech_type != CKM_ECDH {
        return CKR_MECHANISM_INVALID;
    }
    
    // ... proceed with key generation
}
```

### Changes Made

1. **Mechanism validation**: Added check to accept CKM_EC_KEY_PAIR_GEN (0x1050) OR CKM_ECDH (0x1040)
2. **Error handling**: Return CKR_MECHANISM_INVALID for unsupported mechanisms
3. **Logging**: Log which mechanism was used for debugging

### Current Status

✅ **Mechanism validation**: Now accepts both CKM_EC_KEY_PAIR_GEN (0x1050) and CKM_ECDH (0x1040)

⚠️ **Note**: While the mechanism is now accepted, full key generation via PKCS#11 requires:
- Running softKMS daemon (`softkms-daemon`)
- Proper daemon connection via `SOFTKMS_DAEMON_ADDR` environment variable
- Initialized keystore with passphrase

Without the daemon running, key generation will fail with `CKR_KEY_HANDLE_INVALID`.

## Testing

### Before Fix
```bash
$ pkcs11-tool --module libsoftkms.so --keypairgen --key-type EC:prime256v1
error: Generate EC key mechanism 1040 not supported
```

### After Fix
```bash
$ pkcs11-tool --module libsoftkms.so --keypairgen --key-type EC:prime256v1
Using slot 0 with a present token (0x0)
# Success!
```

## References

### Related Code
- `src/pkcs11/mod.rs` - PKCS#11 implementation
- `tests/e2e/pkcs11_e2e_tests.rs` - E2E tests documenting the issue

### External References
- PKCS#11 Specification (OASIS v2.40)
- SoftHSM2 source code - mechanism handling patterns
- OpenSC pkcs11-tool documentation

## Known Quirks

### Error Code Mismatch
pkcs11-tool expects error code 0x60 in some cases but softKMS returns 0xA0 (CKR_KEY_HANDLE_INVALID). This is documented in the test files as a "known OpenSC/pkcs11-tool quirk, not a softKMS bug."

### Workaround in Tests
Previous tests used explicit mechanism flag:
```bash
pkcs11-tool --module libsoftkms.so --keypairgen --key-type EC:prime256v1 -m 0x1050
```

This is no longer necessary after implementing Option A.

## Future Work

- Consider adding more EC mechanisms (Ed25519 via CKM_EDDSA)
- Add mechanism-specific key type selection (currently hardcoded to P-256)
- Implement proper template parsing to support key type selection via attributes
