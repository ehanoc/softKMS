# softKMS Roadmap & TODO

## Strategic Vision

softKMS is a modern, Rust-based PKCS#11 implementation with identity-based access control. Target: Linux systems requiring secure key management with multi-tenant isolation.

---

## Phase 1: Security Hardening (Priority: HIGH)

### TODO
- [ ] TPM 2.0 binding for master key
  - Derive/unwrap master key using TPM
  - Prevent key extraction even with root access
  
- [ ] Memory hardening
  - `mlock`/`MLOCK` to prevent swapping to disk
  - Memory zeroing after key operations
  - Sensitive data in Stack
  
- [ ] Security audit
  - Professional code review
  - Penetration testing
  - FIPS 140-2 evaluation (optional)

---

## Phase 2: Linux Integration (Priority: HIGH)

### TODO
- [ ] systemd integration
  - Production-ready unit file with security options
  - Proper hardening (PrivateTmp, NoNewPrivileges, etc.)
  
- [ ] systemd-creds support
  - Accept TPM-encrypted credentials via systemd
  - Integrate with existing TPM-bound workflows
  
- [ ] Linux audit (auditd) logging
  - Native audit logging for all key operations
  - Compliance-ready trail
  
- [ ] Linux kernel keyring integration
  - Store wrapped keys in kernel keyring
  - Auto-expiration on logout

---

## Phase 3: Enterprise Features (Priority: MEDIUM)

### TODO
- [ ] Key rotation
  - Automatic key rotation policies
  - Re-encryption without service interruption
  
- [ ] Hardware token support
  - PIV compatibility
  - YubiKey integration
  
- [ ] Cluster/multi-node support
  - Distributed key management
  - Key replication
  
- [ ] Key policy engine
  - Usage policies per key
  - Rate limiting
  - Geo-fencing

---

## Phase 4: Cloud & Scale (Priority: MEDIUM)

### TODO
- [ ] Multi-tenant REST API
  - Namespaces per tenant
  - Tenant isolation
  
- [ ] TLS for REST API
  - HTTPS support
  - Certificate management
  
- [ ] Kubernetes operator
  - Operator for K8s deployment
  - CRD for key management

---

## Feature Comparison

| Feature | SoftHSM2 | softKMS (Current) | softKMS (Target) |
|---------|-----------|-------------------|-------------------|
| Language | C++ | Rust | Rust |
| Identity isolation | ❌ | ✅ | ✅ |
| TPM binding | ❌ | ❌ | ✅ |
| HD wallet | ❌ | ✅ | ✅ |
| systemd-creds | ❌ | ❌ | ✅ |
| Audit logging | ❌ | ❌ | ✅ |
| Memory hardening | ❌ | ❌ | ✅ |
| Keyring integration | ❌ | ❌ | ✅ |

---

## Competitive Differentiation

### Unique Value Props
1. **Identity-Based Isolation** - Keys owned by identities, not just admin
2. **HD Wallet Native** - Built-in BIP32/BIP44 for hierarchical keys  
3. **Rust Security** - Memory-safe, no buffer overflows
4. **Linux-First** - TPM, systemd, auditd integration
5. **Modern APIs** - Both gRPC (type-safe) and REST (remote access)

### Market Gap
No open-source PKCS#11 offers:
- ✅ Identity-based key ownership
- ✅ TPM-bound master key
- ✅ HD wallet derivation
- ✅ Native Rust security
- ✅ Linux-first design

---

## Notes

- Current implementation: REST runs in same process as gRPC (same memory space)
- No security regression from REST addition
- Remote access via REST with TLS planned for Phase 4

---

*Last updated: 2026-02-19*
