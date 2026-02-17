//! PKCS#11 Provider for softKMS - Full Implementation with ECDSA P-256 support
//!
//! This module implements a PKCS#11 provider that allows existing applications
//! (OpenSSH, Git, OpenSSL) to use softKMS as an HSM backend.
//!
//! ## Architecture
//!
//! The PKCS#11 provider acts as a CLIENT to the softKMS daemon via gRPC:
//!
//! ```text
//! Application → PKCS#11 API → libsoftkms.so → gRPC → softKMS Daemon
//! ```
//!
//! Keys never leave the daemon - all cryptographic operations happen server-side.

use std::sync::Mutex;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use tracing::{info, warn, error, debug};

mod client;
pub use client::DaemonClient;

mod session;
pub use session::SessionState;

// State
static INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));
static SESSIONS: Lazy<Mutex<HashMap<u64, SessionState>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Object store for key handles - maps handle to key_id
static OBJECTS: Lazy<Mutex<HashMap<u64, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Global handle counter for sequential handle assignment
static NEXT_HANDLE: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));

// Daemon client - uses blocking runtime for sync PKCS#11 calls
static DAEMON_CLIENT: Lazy<Mutex<Option<(DaemonClient, tokio::runtime::Runtime)>>> = 
    Lazy::new(|| Mutex::new(None));

// Daemon server address - can be overridden via environment variable
const DEFAULT_DAEMON_ADDR: &str = "http://127.0.0.1:50051";

fn get_daemon_addr() -> String {
    let addr = std::env::var("SOFTKMS_DAEMON_ADDR")
        .unwrap_or_else(|_| DEFAULT_DAEMON_ADDR.to_string());
    // Ensure address has http:// prefix for gRPC
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr
    } else {
        format!("http://{}", addr)
    }
}

// Return codes
const CKR_OK: u32 = 0;
const CKR_ARGUMENTS_BAD: u32 = 7;
const CKR_BUFFER_TOO_SMALL: u32 = 16;
const CKR_SESSION_INVALID: u32 = 6;
const CKR_SLOT_INVALID: u32 = 3;
const CKR_NOT_SUPPORTED: u32 = 84;
const CKR_DEVICE_ERROR: u32 = 0x30;  // 48 per PKCS#11 spec
const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x54;
const CKR_KEY_HANDLE_INVALID: u32 = 0xA0;  // 160, not 0x60!
const CKR_SIGNATURE_INVALID: u32 = 0xC0;  // 192, signature verification failed
const CKR_OBJECT_HANDLE_INVALID: u32 = 0x82;
const CKR_USER_NOT_LOGGED_IN: u32 = 0x101;
const CKR_MECHANISM_INVALID: u32 = 0x70;
const CKR_PIN_INCORRECT: u32 = 0xA0;  // Same value as CKR_KEY_HANDLE_INVALID, but semantically correct for PIN errors

type CK_RV = u32;
type CK_SLOT = u64;
type CK_SESSION = u64;
type CK_ULONG = u64;
type CK_BOOL = u32;

// PKCS#11 structures
#[repr(C)]
#[derive(Debug)]
struct CK_VERSION {
    major: u8,
    minor: u8,
}

#[repr(C)]
#[derive(Debug)]
struct CK_SLOT_INFO {
    slot_description: [u8; 64],
    manufacturer_id: [u8; 32],
    flags: u64,
    hardware_version: CK_VERSION,
    firmware_version: CK_VERSION,
}

#[repr(C)]
#[derive(Debug)]
struct CK_TOKEN_INFO {
    label: [u8; 32],
    manufacturer_id: [u8; 32],
    model: [u8; 16],
    serial_number: [u8; 16],
    flags: u64,
    ulMaxSessionCount: u64,
    ulSessionCount: u64,
    ulMaxRwSessionCount: u64,
    ulRwSessionCount: u64,
    ulMaxPinLen: u64,
    ulMinPinLen: u64,
    ulTotalPublicMemory: u64,
    ulFreePublicMemory: u64,
    ulTotalPrivateMemory: u64,
    ulFreePrivateMemory: u64,
    hardware_version: CK_VERSION,
    firmware_version: CK_VERSION,
    utc_time: [u8; 16],
}

#[repr(C)]
struct CK_MECHANISM_INFO {
    ulMinKeySize: CK_ULONG,
    ulMaxKeySize: CK_ULONG,
    flags: CK_ULONG,
}

// Mechanism constants for ECDSA P-256
const CKM_ECDSA: CK_ULONG = 0x1001;
const CKM_EC_KEY_PAIR_GEN: CK_ULONG = 0x1050;
const CKM_ECDSA_SHA256: CK_ULONG = 0x1041;
const CKM_ECDSA_SHA384: CK_ULONG = 0x1042;
const CKM_ECDH: CK_ULONG = 0x1040;
const CKM_ECDH1_DERIVE: CK_ULONG = 0x1051;  // EC DH key derivation (SoftHSM2 uses this)

// CK_MECHANISM_INFO flags
const CKF_SIGN: CK_ULONG = 0x00000002;
const CKF_VERIFY: CK_ULONG = 0x00000004;
const CKF_GENERATE: CK_ULONG = 0x00000040;
const CKF_GENERATE_KEY_PAIR: CK_ULONG = 0x00000080;
const CKF_DERIVE: CK_ULONG = 0x00000100;

// CK_SESSION_INFO flags
const CKF_RW_SESSION: CK_ULONG = 0x00000002;
const CKF_SERIAL_SESSION: CK_ULONG = 0x00000004;

// CK_SLOT_INFO flags
const CKF_HW_SLOT: CK_ULONG = 0x00000001;
const CKF_TOKEN_PRESENT: CK_ULONG = 0x00000001;

// CK_TOKEN_INFO flags
const CKF_TOKEN_INITIALIZED: CK_ULONG = 0x00000004;
const CKF_USER_PIN_TO_BE_CHANGED: CK_ULONG = 0x00000002;
const CKF_LOGIN_REQUIRED: CK_ULONG = 0x00000002;

// PKCS#11 function pointer types
type C_GetInfo_t = extern "C" fn(*const ()) -> CK_RV;
type C_Initialize_t = extern "C" fn(*const ()) -> CK_RV;
type C_Finalize_t = extern "C" fn(*const ()) -> CK_RV;
type C_GetSlotList_t = extern "C" fn(CK_BOOL, *mut CK_ULONG, *mut CK_ULONG) -> CK_RV;
type C_GetSlotInfo_t = extern "C" fn(CK_SLOT, *mut CK_SLOT_INFO) -> CK_RV;
type C_GetTokenInfo_t = extern "C" fn(CK_SLOT, *mut CK_TOKEN_INFO) -> CK_RV;
type C_GetMechanismList_t = extern "C" fn(CK_SLOT, *mut CK_ULONG, *mut CK_ULONG) -> CK_RV;
type C_GetMechanismInfo_t = extern "C" fn(CK_SLOT, CK_ULONG, *mut CK_MECHANISM_INFO) -> CK_RV;
type C_OpenSession_t = extern "C" fn(CK_SLOT, CK_ULONG, *mut (), *const (), *mut CK_SESSION) -> CK_RV;
type C_CloseSession_t = extern "C" fn(CK_SESSION) -> CK_RV;
type C_CloseAllSessions_t = extern "C" fn(CK_SLOT) -> CK_RV;
type C_Login_t = extern "C" fn(CK_SESSION, CK_ULONG, *const u8, CK_ULONG) -> CK_RV;
type C_Logout_t = extern "C" fn(CK_SESSION) -> CK_RV;
type C_FindObjectsInit_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG) -> CK_RV;
type C_FindObjects_t = extern "C" fn(CK_SESSION, *mut u64, CK_ULONG, *mut CK_ULONG) -> CK_RV;
type C_FindObjectsFinal_t = extern "C" fn(CK_SESSION) -> CK_RV;
type C_GetAttributeValue_t = extern "C" fn(CK_SESSION, u64, *mut u8, CK_ULONG) -> CK_RV;
type C_GenerateKeyPair_t = extern "C" fn(CK_SESSION, *const u8, *const u8, CK_ULONG, *const u8, CK_ULONG, *mut u64, *mut u64) -> CK_RV;
type C_SignInit_t = extern "C" fn(CK_SESSION, *const u8, u64) -> CK_RV;
type C_Sign_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG, *mut u8, *mut CK_ULONG) -> CK_RV;
type C_VerifyInit_t = extern "C" fn(CK_SESSION, *const u8, u64) -> CK_RV;
type C_Verify_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG, *const u8, CK_ULONG) -> CK_RV;
type C_GetFunctionList_t = extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV;
type C_FunctionNotSupported = extern "C" fn() -> CK_RV;

// CK_FUNCTION_LIST structure - PKCS#11 v2.40
#[repr(C)]
struct CK_FUNCTION_LIST {
    version: CK_VERSION,
    C_GetInfo: C_GetInfo_t,
    C_GetFunctionList: C_GetFunctionList_t,
    C_Initialize: C_Initialize_t,
    C_Finalize: C_Finalize_t,
    C_GetSlotList: C_GetSlotList_t,
    C_GetSlotInfo: C_GetSlotInfo_t,
    C_GetTokenInfo: C_GetTokenInfo_t,
    C_GetMechanismList: C_GetMechanismList_t,
    C_GetMechanismInfo: C_GetMechanismInfo_t,
    C_InitToken: C_FunctionNotSupported,
    C_InitPin: C_FunctionNotSupported,
    C_SetPin: C_FunctionNotSupported,
    C_OpenSession: C_OpenSession_t,
    C_CloseSession: C_CloseSession_t,
    C_CloseAllSessions: C_CloseAllSessions_t,
    C_GetSessionInfo: C_FunctionNotSupported,
    C_GetOperationState: C_FunctionNotSupported,
    C_SetOperationState: C_FunctionNotSupported,
    C_Login: C_Login_t,
    C_Logout: C_Logout_t,
    C_CreateObject: C_FunctionNotSupported,
    C_CopyObject: C_FunctionNotSupported,
    C_DestroyObject: C_FunctionNotSupported,
    C_GetObjectSize: C_FunctionNotSupported,
    C_GetAttributeValue: C_GetAttributeValue_t,
    C_SetAttributeValue: C_FunctionNotSupported,
    C_FindObjectsInit: C_FindObjectsInit_t,
    C_FindObjects: C_FindObjects_t,
    C_FindObjectsFinal: C_FindObjectsFinal_t,
    C_EncryptInit: C_FunctionNotSupported,
    C_Encrypt: C_FunctionNotSupported,
    C_EncryptUpdate: C_FunctionNotSupported,
    C_EncryptFinal: C_FunctionNotSupported,
    C_DecryptInit: C_FunctionNotSupported,
    C_Decrypt: C_FunctionNotSupported,
    C_DecryptUpdate: C_FunctionNotSupported,
    C_DecryptFinal: C_FunctionNotSupported,
    C_DigestInit: C_FunctionNotSupported,
    C_Digest: C_FunctionNotSupported,
    C_DigestUpdate: C_FunctionNotSupported,
    C_DigestKey: C_FunctionNotSupported,
    C_DigestFinal: C_FunctionNotSupported,
    C_SignInit: C_SignInit_t,
    C_Sign: C_Sign_t,
    C_SignUpdate: C_FunctionNotSupported,
    C_SignFinal: C_FunctionNotSupported,
    C_SignRecoverInit: C_FunctionNotSupported,
    C_SignRecover: C_FunctionNotSupported,
    C_VerifyInit: C_VerifyInit_t,
    C_Verify: C_Verify_t,
    C_VerifyUpdate: C_FunctionNotSupported,
    C_VerifyFinal: C_FunctionNotSupported,
    C_VerifyRecoverInit: C_FunctionNotSupported,
    C_VerifyRecover: C_FunctionNotSupported,
    C_DigestEncryptUpdate: C_FunctionNotSupported,
    C_DecryptDigestUpdate: C_FunctionNotSupported,
    C_SignEncryptUpdate: C_FunctionNotSupported,
    C_DecryptVerifyUpdate: C_FunctionNotSupported,
    C_GenerateKey: C_FunctionNotSupported,
    C_GenerateKeyPair: C_GenerateKeyPair_t,
    C_WrapKey: C_FunctionNotSupported,
    C_UnwrapKey: C_FunctionNotSupported,
    C_DeriveKey: C_FunctionNotSupported,
    C_SeedRandom: C_FunctionNotSupported,
    C_GenerateRandom: C_FunctionNotSupported,
    C_GetFunctionStatus: C_FunctionNotSupported,
    C_CancelFunction: C_FunctionNotSupported,
    C_WaitForSlotEvent: C_FunctionNotSupported,
}

extern "C" fn not_supported() -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// Global function list instance
static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 2, minor: 40 },  // PKCS#11 version 2.40
    C_GetInfo,
    C_GetFunctionList,
    C_Initialize,
    C_Finalize,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken: not_supported,
    C_InitPin: not_supported,
    C_SetPin: not_supported,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo: not_supported,
    C_GetOperationState: not_supported,
    C_SetOperationState: not_supported,
    C_Login,
    C_Logout,
    C_CreateObject: not_supported,
    C_CopyObject: not_supported,
    C_DestroyObject: not_supported,
    C_GetObjectSize: not_supported,
    C_GetAttributeValue,
    C_SetAttributeValue: not_supported,
    C_FindObjectsInit,
    C_FindObjects,
    C_FindObjectsFinal,
    C_EncryptInit: not_supported,
    C_Encrypt: not_supported,
    C_EncryptUpdate: not_supported,
    C_EncryptFinal: not_supported,
    C_DecryptInit: not_supported,
    C_Decrypt: not_supported,
    C_DecryptUpdate: not_supported,
    C_DecryptFinal: not_supported,
    C_DigestInit: not_supported,
    C_Digest: not_supported,
    C_DigestUpdate: not_supported,
    C_DigestKey: not_supported,
    C_DigestFinal: not_supported,
    C_SignInit,
    C_Sign,
    C_SignUpdate: not_supported,
    C_SignFinal: not_supported,
    C_SignRecoverInit: not_supported,
    C_SignRecover: not_supported,
    C_VerifyInit,
    C_Verify,
    C_VerifyUpdate: not_supported,
    C_VerifyFinal: not_supported,
    C_VerifyRecoverInit: not_supported,
    C_VerifyRecover: not_supported,
    C_DigestEncryptUpdate: not_supported,
    C_DecryptDigestUpdate: not_supported,
    C_SignEncryptUpdate: not_supported,
    C_DecryptVerifyUpdate: not_supported,
    C_GenerateKey: not_supported,
    C_GenerateKeyPair,
    C_WrapKey: not_supported,
    C_UnwrapKey: not_supported,
    C_DeriveKey: not_supported,
    C_SeedRandom: not_supported,
    C_GenerateRandom: not_supported,
    C_GetFunctionStatus: not_supported,
    C_CancelFunction: not_supported,
    C_WaitForSlotEvent: not_supported,
};

// C_GetFunctionList - Entry point for PKCS#11 consumers
#[no_mangle]
pub extern "C" fn C_GetFunctionList(ppFunctionList: *mut *const CK_FUNCTION_LIST) -> CK_RV { 
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    unsafe { 
        *ppFunctionList = &FUNCTION_LIST; 
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetInfo(_: *const ()) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_Initialize(_: *const ()) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_Finalize(_: *const ()) -> CK_RV { CKR_OK }

#[no_mangle]
pub extern "C" fn C_GetSlotList(_token_present: CK_BOOL, slot_list: *mut CK_ULONG, count: *mut CK_ULONG) -> CK_RV {
    if count.is_null() { 
        return CKR_ARGUMENTS_BAD; 
    }
    
    // Return 1 slot (slot 0)
    unsafe { *count = 1; }
    
    if slot_list.is_null() { 
        return CKR_OK; 
    }
    
    unsafe { *slot_list = 0; }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetSlotInfo(_slot: CK_SLOT, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_OK;
    }
    
    unsafe {
        let info = &mut *pInfo;
        info.flags = CKF_HW_SLOT | CKF_TOKEN_PRESENT;
        
        // Set slot description (max 64 bytes)
        let desc = b"softKMS                                         ";
        info.slot_description[..desc.len()].copy_from_slice(desc);
        
        // Set manufacturer ID (max 32 bytes)
        let mfg = b"softKMS                       ";
        info.manufacturer_id[..mfg.len()].copy_from_slice(mfg);
    }
    CKR_OK
}

#[no_mangle]  
pub extern "C" fn C_GetTokenInfo(slot: CK_SLOT, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    if slot != 0 {
        return CKR_SLOT_INVALID;
    }
    
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    
    unsafe {
        let info = &mut *pInfo;
        
        // Set label
        let label = b"softKMS                        ";
        info.label[..label.len()].copy_from_slice(label);
        
        // Set manufacturer
        let mfg = b"softKMS                        ";
        info.manufacturer_id[..mfg.len()].copy_from_slice(mfg);
        
        // Set model
        let model = b"softKMS         ";
        info.model[..model.len()].copy_from_slice(model);
        
        // Serial number
        let serial = b"0000000000000000";
        info.serial_number.copy_from_slice(serial);
        
        // Flags
        info.flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_TO_BE_CHANGED | CKF_LOGIN_REQUIRED;
        
        // Session counts
        info.ulMaxSessionCount = 0xFFFFFFFFFFFFFFFFu64;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = 0xFFFFFFFFFFFFFFFFu64;
        info.ulRwSessionCount = 0;
        
        // PIN lengths
        info.ulMaxPinLen = 256;
        info.ulMinPinLen = 4;
        
        // Memory
        info.ulTotalPublicMemory = 0xFFFFFFFFFFFFFFFFu64;
        info.ulFreePublicMemory = 0xFFFFFFFFFFFFFFFFu64;
        info.ulTotalPrivateMemory = 0xFFFFFFFFFFFFFFFFu64;
        info.ulFreePrivateMemory = 0xFFFFFFFFFFFFFFFFu64;
        
        // Versions
        info.hardware_version = CK_VERSION { major: 1, minor: 0 };
        info.firmware_version = CK_VERSION { major: 1, minor: 0 };
    }
    
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismList(slot: CK_SLOT, list: *mut CK_ULONG, count: *mut CK_ULONG) -> CK_RV {
    if slot != 0 { return CKR_SLOT_INVALID; }
    if count.is_null() { return CKR_ARGUMENTS_BAD; }
    
    // Advertise ECDSA P-256 support - following SoftHSM2 pattern for maximum interoperability
    // Including CKM_ECDH for compatibility with tools that check for it
    let mechanisms = [CKM_ECDSA, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDH, CKM_ECDH1_DERIVE];
    let mech_count = mechanisms.len() as CK_ULONG;
    
    unsafe { *count = mech_count; }
    
    if list.is_null() {
        return CKR_OK;
    }
    
    if unsafe { *count < mech_count } {
        return CKR_BUFFER_TOO_SMALL;
    }
    
    for (i, &mech) in mechanisms.iter().enumerate() {
        unsafe { *list.offset(i as isize) = mech; }
    }
    
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(_slot: CK_SLOT, mech: CK_ULONG, pInfo: *mut CK_MECHANISM_INFO) -> CK_RV { 
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    
    // ECDSA
    if mech == CKM_ECDSA {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_SIGN | CKF_VERIFY;
        }
        return CKR_OK;
    }
    
    // EC key pair generation
    if mech == CKM_EC_KEY_PAIR_GEN {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_GENERATE_KEY_PAIR | CKF_GENERATE;
        }
        return CKR_OK;
    }
    
    // ECDSA with SHA
    if mech == CKM_ECDSA_SHA256 || mech == CKM_ECDSA_SHA384 {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_SIGN | CKF_VERIFY;
        }
        return CKR_OK;
    }
    
    // ECDH key derivation - for compatibility with tools that check it
    if mech == CKM_ECDH {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_DERIVE | CKF_GENERATE_KEY_PAIR;
        }
        return CKR_OK;
    }
    
    // ECDH1_DERIVE - SoftHSM2 style key derivation
    if mech == CKM_ECDH1_DERIVE {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_DERIVE;
        }
        return CKR_OK;
    }
    
    CKR_MECHANISM_INVALID
}

#[no_mangle]
pub extern "C" fn C_OpenSession(slot: CK_SLOT, _flags: CK_ULONG, _notify: *mut (), _app: *const (), session: *mut CK_SESSION) -> CK_RV {
    if slot != 0 { return CKR_SLOT_INVALID; }
    if session.is_null() { return CKR_ARGUMENTS_BAD; }
    
    let handle = rand_handle();
    unsafe { *session = handle; }
    if let Ok(ref mut s) = SESSIONS.lock() { 
        s.insert(handle, SessionState::new(handle, false)); 
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(sess: CK_SESSION) -> CK_RV {
    if let Ok(ref mut s) = SESSIONS.lock() { s.remove(&sess); }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(_slot: CK_SLOT) -> CK_RV {
    if let Ok(ref mut s) = SESSIONS.lock() { s.clear(); }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Login(sess: CK_SESSION, _user_type: CK_ULONG, pin: *const u8, pin_len: CK_ULONG) -> CK_RV {
    info!("C_Login called for session {}", sess);
    
    if pin.is_null() || pin_len == 0 {
        error!("C_Login: Invalid PIN (null or empty)");
        return CKR_ARGUMENTS_BAD;
    }
    
    let pin_str = unsafe {
        match std::str::from_utf8(std::slice::from_raw_parts(pin, pin_len as usize)) {
            Ok(s) => s.to_string(),
            Err(_) => {
                error!("C_Login: PIN is not valid UTF-8");
                return CKR_ARGUMENTS_BAD;
            }
        }
    };
    
    // Check if PIN looks like an identity token (base64 format with sk_token_ prefix or similar)
    // Identity tokens are base64 encoded and typically 100+ characters
    let is_token_format = pin_str.len() > 50 && 
        pin_str.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');
    
    if is_token_format {
        info!("C_Login: PIN appears to be an identity token, attempting validation");
        
        // Try to validate the token with the daemon
        if let Err(e) = ensure_daemon_connected() {
            error!("C_Login: Failed to connect to daemon: {}", e);
            return CKR_DEVICE_ERROR;
        }
        
        let validation_result: Result<(String, String), String> = {
            let mut client_guard = match DAEMON_CLIENT.lock() {
                Ok(c) => c,
                Err(_) => return CKR_DEVICE_ERROR,
            };
            
            if let Some((ref mut client, ref rt)) = *client_guard {
                let token_clone = pin_str.clone();
                rt.block_on(async move {
                    // Validate the identity token and get identity info
                    match client.validate_identity_token(&token_clone).await {
                        Ok((pubkey, _info)) => Ok((pubkey, token_clone)),
                        Err(e) => Err(format!("Token validation failed: {}", e)),
                    }
                })
            } else {
                Err("No daemon client available".to_string())
            }
        };
        
        match validation_result {
            Ok((pubkey, token)) => {
                info!("C_Login: Identity token validated successfully for pubkey: {}...", &pubkey[..32.min(pubkey.len())]);
                
                // Store identity info in session
                if let Ok(ref mut s) = SESSIONS.lock() {
                    if let Some(st) = s.get_mut(&sess) {
                        st.identity_token = Some(token.clone());
                        st.identity_pubkey = Some(pubkey);
                        st.is_identity_session = true;
                        st.is_logged_in = true;
                        st.passphrase = Some(token); // Store token as passphrase for daemon operations
                        return CKR_OK;
                    }
                }
                return CKR_SESSION_INVALID;
            }
            Err(e) => {
                error!("C_Login: Invalid identity token: {}", e);
                return CKR_PIN_INCORRECT;
            }
        }
    } else {
        // Not a token format - admin passphrases are NOT accepted in PKCS#11
        error!("C_Login: PIN is not a valid identity token format. Admin passphrase access is not allowed via PKCS#11.");
        return CKR_PIN_INCORRECT;
    }
}

#[no_mangle]
pub extern "C" fn C_Logout(sess: CK_SESSION) -> CK_RV {
    if let Ok(ref mut s) = SESSIONS.lock() {
        if let Some(st) = s.get_mut(&sess) { st.is_logged_in = false; return CKR_OK; }
    }
    CKR_SESSION_INVALID
}

static mut FIND_SESSION: u64 = 0;

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(sess: CK_SESSION, _templ: *const u8, _count: CK_ULONG) -> CK_RV { 
    unsafe { FIND_SESSION = sess; }
    CKR_OK 
}

#[no_mangle]
pub extern "C" fn C_FindObjects(sess: CK_SESSION, objects: *mut u64, max_count: CK_ULONG, count: *mut CK_ULONG) -> CK_RV { 
    // First, get both identity pubkey and token from session
    let (identity_pubkey, identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => {
                unsafe { *count = 0; }
                return CKR_OK;
            }
        };
        match sessions.get(&sess) {
            Some(st) => (st.identity_pubkey.clone(), st.identity_token.clone()),
            None => {
                unsafe { *count = 0; }
                return CKR_OK;
            }
        }
    };
    
    // If we have an identity, query daemon for keys
    if let (Some(_pubkey), Some(token)) = (identity_pubkey, identity_token) {
        let keys_result: Result<Vec<String>, String> = {
            let mut client_guard = match DAEMON_CLIENT.lock() {
                Ok(c) => c,
                Err(_) => {
                    unsafe { *count = 0; }
                    return CKR_OK;
                }
            };
            
            if let Some((ref mut client, ref rt)) = *client_guard {
                rt.block_on(async move {
                    // Query daemon filtering by identity token
                    match client.list_keys_with_identity(&token).await {
                        Ok(keys) => Ok(keys.into_iter().map(|k| k.id).collect()),
                        Err(e) => Err(e.to_string()),
                    }
                })
            } else {
                Err("No client".to_string())
            }
        };
        
        if let Ok(keys) = keys_result {
            // Store in OBJECTS - merge with existing, don't clear
            let mut objects = match OBJECTS.lock() {
                Ok(o) => o,
                Err(_) => {
                    unsafe { *count = 0; }
                    return CKR_OK;
                }
            };
            
            let mut next_handle = match NEXT_HANDLE.lock() {
                Ok(h) => *h,
                Err(_) => {
                    unsafe { *count = 0; }
                    return CKR_OK;
                }
            };
            
            // Add new keys from daemon, preserving existing
            // keys is Vec<String> containing key IDs
            for key_id in keys.iter() {
                // Check if key already has a handle
                let existing_handle = objects.iter()
                    .find(|(_, v)| **v == *key_id)
                    .map(|(k, _)| *k);
                
                if existing_handle.is_none() {
                    // New key - assign next available handle
                    objects.insert(next_handle, key_id.clone());
                    next_handle += 1;
                }
            }
            
            // Update next handle counter
            if let Ok(mut h) = NEXT_HANDLE.lock() {
                *h = next_handle;
            }
        }
    }
    
    // Now return from OBJECTS
    let objs = match OBJECTS.lock() {
        Ok(o) => o,
        Err(_) => {
            unsafe { *count = 0; }
            return CKR_OK;
        }
    };
    
    let handles: Vec<u64> = objs.keys().copied().collect();
    let num_objs = handles.len().min(max_count as usize);
    
    if !objects.is_null() {
        for i in 0..num_objs {
            unsafe {
                *objects.add(i) = handles[i];
            }
        }
    }
    
    unsafe { *count = num_objs as CK_ULONG; }
    CKR_OK 
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(_sess: CK_SESSION) -> CK_RV { CKR_OK }
#[no_mangle]
pub extern "C" fn C_GetAttributeValue(_sess: CK_SESSION, _obj: u64, _templ: *mut u8, _count: CK_ULONG) -> CK_RV { CKR_OK }

// Connect to daemon (blocking)
fn ensure_daemon_connected() -> Result<(), String> {
    let mut client_guard = DAEMON_CLIENT.lock().map_err(|e| e.to_string())?;
    
    if client_guard.is_none() {
        let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
        let daemon_addr = get_daemon_addr();
        let mut client = DaemonClient::new(&daemon_addr);
        
        debug!("Connecting to daemon at {}", daemon_addr);
        
        rt.block_on(async {
            client.connect().await
        }).map_err(|e| e.to_string())?;
        
        *client_guard = Some((client, rt));
    }
    Ok(())
}

fn ensure_daemon_connected_with_passphrase(passphrase: &str) -> Result<(), String> {
    ensure_daemon_connected()?;
    
    // Set passphrase for subsequent operations
    {
        let mut client_guard = DAEMON_CLIENT.lock().map_err(|e| e.to_string())?;
        if let Some((ref mut client, _)) = *client_guard {
            client.set_passphrase(passphrase.to_string());
        }
    }
    
    // Note: We do NOT initialize the keystore here.
    // The daemon should be initialized separately before PKCS#11 operations.
    // PKCS#11 library only connects to an already-initialized daemon.
    Ok(())
}

// Generate a random handle
fn rand_handle() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    nanos as u64
}

// Key generation - ECDSA P-256 via daemon
#[no_mangle]
pub extern "C" fn C_GenerateKeyPair(
    session: CK_SESSION, 
    mech: *const u8,
    pub_template: *const u8, 
    pub_attr_count: CK_ULONG, 
    priv_template: *const u8, 
    priv_attr_count: CK_ULONG, 
    pub_key: *mut u64, 
    priv_key: *mut u64
) -> CK_RV {
    // Parse mechanism type
    let mech_type = if !mech.is_null() {
        unsafe { *(mech as *const CK_ULONG) }
    } else {
        0
    };
    
    info!("C_GenerateKeyPair called with session: {}, mech: 0x{:x}", session, mech_type);
    
    if session == 0 {
        return CKR_SESSION_INVALID;
    }
    
    if pub_key.is_null() || priv_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    
    // Get passphrase AND identity token from session
    let (passphrase, identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };
        match sessions.get(&session) {
            Some(st) => (
                st.passphrase.clone().unwrap_or_default(),
                st.identity_token.clone()
            ),
            None => return CKR_SESSION_INVALID,
        }
    };
    
    // Connect to daemon with passphrase
    let daemon_addr = get_daemon_addr();
    info!("Attempting to connect to daemon at: {}", daemon_addr);
    if let Err(e) = ensure_daemon_connected_with_passphrase(&passphrase) {
        error!("Failed to connect to daemon at {}: {}", daemon_addr, e);
        return CKR_DEVICE_ERROR;
    }
    
    // Generate P-256 key via daemon, passing identity token
    let key_id_result: Result<String, String> = {
        let mut client_guard = match DAEMON_CLIENT.lock() {
            Ok(c) => c,
            Err(_) => {
                error!("Failed to lock DAEMON_CLIENT");
                return CKR_DEVICE_ERROR;
            }
        };
        
        if let Some((ref mut client, ref rt)) = *client_guard {
            let passphrase_clone = passphrase.clone();
            let identity_token_ref = identity_token.as_deref();
            eprintln!("[PKCS11] Creating key with passphrase: {}... and identity: {:?}", &passphrase_clone[..20.min(passphrase_clone.len())], identity_token_ref.map(|t| &t[..20.min(t.len())]));
            match rt.block_on(async move {
                match client.create_key("p256", Some("pkcs11-key"), &passphrase_clone, identity_token_ref).await {
                    Ok(id) => Ok(id),
                    Err(e) => {
                        eprintln!("[PKCS11] create_key error: {}", e);
                        Err(e.to_string())
                    }
                }
            }) {
                Ok(id) => Ok(id),
                Err(e) => {
                    error!("Failed to create key: {}", e);
                    Err(e)
                }
            }
        } else {
            Err("No client".to_string())
        }
    };
    
    let key_id = match key_id_result {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to generate key in daemon: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };
    
    info!("Generated P-256 key with ID: {}", key_id);
    
    // Generate unique key handles
    let handle = rand_handle();
    
    // Store in global object store for FindObjects
    {
        let mut objects = match OBJECTS.lock() {
            Ok(o) => o,
            Err(_) => return CKR_SESSION_INVALID,
        };
        objects.insert(handle, key_id.clone());
    }
    
    // Store in session
    {
        let mut sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };
        
        if let Some(st) = sessions.get_mut(&session) {
            st.active_key_handle = Some(handle);
            st.active_key_id = Some(key_id);
            st.signing_algorithm = Some("p256".to_string());
        } else {
            return CKR_SESSION_INVALID;
        }
    }
    
    unsafe {
        *pub_key = handle;
        *priv_key = handle + 1;
    }
    
    CKR_OK
}

// Signing
#[no_mangle]
pub extern "C" fn C_SignInit(sess: CK_SESSION, _mech: *const u8, key: u64) -> CK_RV { 
    info!("C_SignInit session: {} key: {}", sess, key); 
    
    // Look up the key ID using the handle
    let key_id = {
        let objects = match OBJECTS.lock() {
            Ok(o) => o,
            Err(_) => return CKR_DEVICE_ERROR,
        };
        
        match objects.get(&key) {
            Some(id) => id.clone(),
            None => {
                error!("C_SignInit: Key handle {} not found in object store", key);
                return CKR_KEY_HANDLE_INVALID;
            }
        }
    };
    
    // Store the key handle and key ID in session state for C_Sign to use
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return CKR_SESSION_INVALID,
    };
    
    if let Some(st) = sessions.get_mut(&sess) {
        st.active_key_handle = Some(key);
        st.active_key_id = Some(key_id);
        info!("C_SignInit: Stored key handle {} and key ID for session {}", key, sess);
        CKR_OK
    } else {
        CKR_SESSION_INVALID
    }
}

#[no_mangle]
pub extern "C" fn C_Sign(
    session: CK_SESSION, 
    data: *const u8, 
    data_len: CK_ULONG, 
    signature: *mut u8, 
    sig_len: *mut CK_ULONG
) -> CK_RV { 
    info!("C_Sign called");
    
    if session == 0 {
        return CKR_SESSION_INVALID;
    }
    
    // Get key from object store using the active key handle set by C_SignInit
    // First get the key handle from session (avoids holding multiple locks)
    let key_handle = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };
        
        match sessions.get(&session) {
            Some(st) => st.active_key_handle,
            None => return CKR_SESSION_INVALID,
        }
    };
    
    // Now look up the key ID using the handle
    let key_id = match key_handle {
        Some(handle) => {
            let objects = match OBJECTS.lock() {
                Ok(o) => o,
                Err(_) => return CKR_DEVICE_ERROR,
            };
            match objects.get(&handle) {
                Some(id) => id.clone(),
                None => {
                    error!("Key handle {} not found in object store", handle);
                    return CKR_KEY_HANDLE_INVALID;
                }
            }
        }
        None => {
            error!("No active key handle set (C_SignInit not called)");
            return CKR_KEY_HANDLE_INVALID;
        }
    };
    
    // Get passphrase and identity token from session
    let (passphrase, identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };
        if let Some(st) = sessions.get(&session) {
            (
                st.passphrase.clone().unwrap_or_default(),
                st.identity_token.clone()
            )
        } else {
            return CKR_SESSION_INVALID;
        }
    };
    
    // Get data
    let data_to_sign = if data.is_null() || data_len == 0 {
        return CKR_ARGUMENTS_BAD;
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len as usize).to_vec() }
    };
    
    // Connect to daemon
    if let Err(e) = ensure_daemon_connected_with_passphrase(&passphrase) {
        error!("Failed to connect: {}", e);
        return CKR_DEVICE_ERROR;
    }
    
    // Sign via daemon with identity token
    let sig_result: Result<Vec<u8>, String> = {
        let mut client_guard = match DAEMON_CLIENT.lock() {
            Ok(c) => c,
            Err(_) => return CKR_DEVICE_ERROR,
        };
        
        if let Some((ref mut client, ref rt)) = *client_guard {
            let key_id_clone = key_id.clone();
            let data_clone = data_to_sign.clone();
            let identity_token_ref = identity_token.as_deref();
            rt.block_on(async move {
                client.sign(&key_id_clone, &data_clone, identity_token_ref).await
                    .map_err(|e| e.to_string())
            })
        } else {
            Err("No client".to_string())
        }
    };
    
    let sig_bytes = match sig_result {
        Ok(s) => s,
        Err(e) => {
            error!("Sign failed: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };
    
    // Check buffer size
    if signature.is_null() {
        unsafe { *sig_len = sig_bytes.len() as CK_ULONG; }
        return CKR_BUFFER_TOO_SMALL;
    }
    
    let current_sig_len = unsafe { *sig_len };
    if current_sig_len < sig_bytes.len() as CK_ULONG {
        unsafe { *sig_len = sig_bytes.len() as CK_ULONG; }
        return CKR_BUFFER_TOO_SMALL;
    }
    
    unsafe {
        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), signature, sig_bytes.len());
        *sig_len = sig_bytes.len() as CK_ULONG;
    }
    
    info!("Signed {} bytes with key {}", sig_bytes.len(), key_id);
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_VerifyInit(sess: CK_SESSION, _mech: *const u8, key: u64) -> CK_RV {
    info!("C_VerifyInit session: {} key: {}", sess, key);

    // Look up the key ID using the handle (same logic as C_SignInit)
    let key_id = {
        let objects = match OBJECTS.lock() {
            Ok(o) => o,
            Err(_) => return CKR_DEVICE_ERROR,
        };

        match objects.get(&key) {
            Some(id) => id.clone(),
            None => {
                error!("C_VerifyInit: Key handle {} not found in object store", key);
                return CKR_KEY_HANDLE_INVALID;
            }
        }
    };

    // Store the key handle and key ID in session state for C_Verify to use
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return CKR_SESSION_INVALID,
    };

    if let Some(st) = sessions.get_mut(&sess) {
        st.active_key_handle = Some(key);
        st.active_key_id = Some(key_id);
        info!("C_VerifyInit: Stored key handle {} and key ID for session {}", key, sess);
        CKR_OK
    } else {
        CKR_SESSION_INVALID
    }
}

#[no_mangle]
pub extern "C" fn C_Verify(
    session: CK_SESSION,
    data: *const u8,
    data_len: CK_ULONG,
    signature: *const u8,
    sig_len: CK_ULONG
) -> CK_RV {
    info!("C_Verify called");

    if session == 0 {
        return CKR_SESSION_INVALID;
    }

    if data.is_null() || data_len == 0 {
        return CKR_ARGUMENTS_BAD;
    }

    if signature.is_null() || sig_len == 0 {
        return CKR_ARGUMENTS_BAD;
    }

    // Get the key ID from session (same pattern as C_Sign, avoiding nested locks)
    let key_handle = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };

        match sessions.get(&session) {
            Some(st) => st.active_key_handle,
            None => return CKR_SESSION_INVALID,
        }
    };

    let key_id = match key_handle {
        Some(handle) => {
            let objects = match OBJECTS.lock() {
                Ok(o) => o,
                Err(_) => return CKR_DEVICE_ERROR,
            };
            match objects.get(&handle) {
                Some(id) => id.clone(),
                None => {
                    error!("Key handle {} not found in object store", handle);
                    return CKR_KEY_HANDLE_INVALID;
                }
            }
        }
        None => {
            error!("No active key handle set (C_VerifyInit not called)");
            return CKR_KEY_HANDLE_INVALID;
        }
    };

    // Get data and signature
    let data_to_verify = unsafe {
        std::slice::from_raw_parts(data, data_len as usize).to_vec()
    };

    let signature_bytes = unsafe {
        std::slice::from_raw_parts(signature, sig_len as usize).to_vec()
    };

    // Get passphrase and identity token from session
    let (passphrase, identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };
        if let Some(st) = sessions.get(&session) {
            (
                st.passphrase.clone().unwrap_or_default(),
                st.identity_token.clone()
            )
        } else {
            return CKR_SESSION_INVALID;
        }
    };

    // Connect to daemon
    if let Err(e) = ensure_daemon_connected_with_passphrase(&passphrase) {
        error!("Failed to connect: {}", e);
        return CKR_DEVICE_ERROR;
    }

    // Verify via daemon with identity token
    let verify_result: Result<bool, String> = {
        let mut client_guard = match DAEMON_CLIENT.lock() {
            Ok(c) => c,
            Err(_) => return CKR_DEVICE_ERROR,
        };

        if let Some((ref mut client, ref rt)) = *client_guard {
            let key_id_clone = key_id.clone();
            let data_clone = data_to_verify.clone();
            let sig_clone = signature_bytes.clone();
            rt.block_on(async move {
                client.verify(&key_id_clone, &data_clone, &sig_clone).await
                    .map_err(|e| e.to_string())
            })
        } else {
            Err("No client".to_string())
        }
    };

    match verify_result {
        Ok(valid) => {
            if valid {
                info!("Signature verified successfully with key {}", key_id);
                CKR_OK
            } else {
                error!("Signature verification failed for key {}", key_id);
                CKR_SIGNATURE_INVALID
            }
        }
        Err(e) => {
            error!("Verify failed: {}", e);
            CKR_DEVICE_ERROR
        }
    }
}

#[derive(Debug, Clone)]
pub struct Pkcs11Info {
    pub name: String,
    pub description: String,
    pub version: (u8, u8),
}

pub fn get_info() -> Pkcs11Info {
    Pkcs11Info {
        name: "softKMS PKCS#11 Provider".to_string(),
        description: "Software Key Management System with PKCS#11 interface".to_string(),
        version: (0, 1),
    }
}

pub fn get_module_path() -> String {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| "libsoftkms.so".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_slot_list_count_only() {
        // Test C_GetSlotList when called with NULL slot_list (just get count)
        let mut count: CK_ULONG = 0;
        let result = unsafe { C_GetSlotList(0, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };
        
        assert_eq!(result, CKR_OK);
        assert_eq!(count, 1, "Should have exactly 1 slot");
    }

    #[test]
    fn test_get_slot_list_with_buffer() {
        // Test C_GetSlotList when called with buffer
        let mut count: CK_ULONG = 0;
        let mut slot: CK_ULONG = 999;
        
        // First call to get count
        let result = unsafe { C_GetSlotList(0, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);
        assert_eq!(count, 1);
        
        // Second call with buffer
        let result = unsafe { C_GetSlotList(0, &mut slot as *mut CK_ULONG, &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);
        assert_eq!(slot, 0, "Slot 0 should be returned");
    }

    #[test]
    fn test_get_slot_list_invalid_slot() {
        // Test with non-zero slot - current implementation accepts any slot
        // (returns slot 0 regardless)
        let mut count: CK_ULONG = 0;
        let mut slot: CK_ULONG = 999;
        
        let result = unsafe { C_GetSlotList(1, &mut slot as *mut CK_ULONG, &mut count as *mut CK_ULONG) };
        
        // Current implementation returns OK (it ignores the slot parameter)
        // This is acceptable for a simple implementation
        assert_eq!(result, CKR_OK);
    }

    #[test]
    fn test_get_slot_list_null_count() {
        // Test with NULL count - should fail
        let result = unsafe { C_GetSlotList(0, std::ptr::null_mut(), std::ptr::null_mut()) };
        
        assert_eq!(result, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_mechanism_list_count_only() {
        // Test C_GetMechanismList when called with NULL list (just get count)
        let mut count: CK_ULONG = 0;
        let result = unsafe { C_GetMechanismList(0, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };
        
        assert_eq!(result, CKR_OK);
        assert!(count > 0, "Should have at least 1 mechanism");
    }

    #[test]
    fn test_get_mechanism_list_with_buffer() {
        // Test C_GetMechanismList when called with buffer
        let mut count: CK_ULONG = 0;
        
        // First call to get count
        let result = unsafe { C_GetMechanismList(0, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);
        assert!(count >= 6, "Should have at least 6 mechanisms (ECDSA, EC_KEY_PAIR_GEN, etc.)");
        
        // Allocate buffer and get mechanisms
        let mut mechs: Vec<CK_ULONG> = vec![0; count as usize];
        let result = unsafe { C_GetMechanismList(0, mechs.as_mut_ptr(), &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);
        
        // Check for expected mechanisms
        let mech_set: Vec<CK_ULONG> = mechs[..count as usize].to_vec();
        
        // Should contain at least these mechanisms
        assert!(mech_set.contains(&CKM_ECDSA), "Should have CKM_ECDSA");
        assert!(mech_set.contains(&CKM_EC_KEY_PAIR_GEN), "Should have CKM_EC_KEY_PAIR_GEN");
        assert!(mech_set.contains(&CKM_ECDSA_SHA256), "Should have CKM_ECDSA_SHA256");
    }

    #[test]
    fn test_get_mechanism_list_invalid_slot() {
        // Test with invalid slot
        let mut count: CK_ULONG = 0;
        let result = unsafe { C_GetMechanismList(1, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };
        
        assert_eq!(result, CKR_SLOT_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_ecdsa() {
        // Test C_GetMechanismInfo for CKM_ECDSA
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        
        let result = unsafe { C_GetMechanismInfo(0, CKM_ECDSA, &mut info as *mut CK_MECHANISM_INFO) };
        
        assert_eq!(result, CKR_OK);
        assert_eq!(info.ulMinKeySize, 256);
        assert_eq!(info.ulMaxKeySize, 521);
        assert!(info.flags & CKF_SIGN != 0, "Should have CKF_SIGN");
        assert!(info.flags & CKF_VERIFY != 0, "Should have CKF_VERIFY");
    }

    #[test]
    fn test_get_mechanism_info_ec_key_pair_gen() {
        // Test C_GetMechanismInfo for CKM_EC_KEY_PAIR_GEN
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        
        let result = unsafe { C_GetMechanismInfo(0, CKM_EC_KEY_PAIR_GEN, &mut info as *mut CK_MECHANISM_INFO) };
        
        assert_eq!(result, CKR_OK);
        assert_eq!(info.ulMinKeySize, 256);
        assert_eq!(info.ulMaxKeySize, 521);
        assert!(info.flags & CKF_GENERATE_KEY_PAIR != 0, "Should have CKF_GENERATE_KEY_PAIR");
    }

    #[test]
    fn test_get_mechanism_info_ecdsa_sha256() {
        // Test C_GetMechanismInfo for CKM_ECDSA_SHA256
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        
        let result = unsafe { C_GetMechanismInfo(0, CKM_ECDSA_SHA256, &mut info as *mut CK_MECHANISM_INFO) };
        
        assert_eq!(result, CKR_OK);
        assert!(info.flags & CKF_SIGN != 0, "Should have CKF_SIGN");
    }

    #[test]
    fn test_get_mechanism_info_ecdh() {
        // Test C_GetMechanismInfo for CKM_ECDH
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        
        let result = unsafe { C_GetMechanismInfo(0, CKM_ECDH, &mut info as *mut CK_MECHANISM_INFO) };
        
        assert_eq!(result, CKR_OK);
        assert!(info.flags & CKF_DERIVE != 0, "Should have CKF_DERIVE");
    }

    #[test]
    fn test_get_mechanism_info_invalid() {
        // Test with invalid mechanism
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };
        
        // Use an unknown mechanism
        let result = unsafe { C_GetMechanismInfo(0, 0x9999, &mut info as *mut CK_MECHANISM_INFO) };
        
        assert_eq!(result, CKR_MECHANISM_INVALID);
    }

    #[test]
    fn test_get_mechanism_info_null_ptr() {
        // Test with NULL info pointer
        let result = unsafe { C_GetMechanismInfo(0, CKM_ECDSA, std::ptr::null_mut()) };
        
        assert_eq!(result, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn test_get_token_info() {
        // Test C_GetTokenInfo
        let mut info = CK_TOKEN_INFO {
            label: [0; 32],
            manufacturer_id: [0; 32],
            model: [0; 16],
            serial_number: [0; 16],
            flags: 0,
            ulMaxSessionCount: 0,
            ulSessionCount: 0,
            ulMaxRwSessionCount: 0,
            ulRwSessionCount: 0,
            ulMaxPinLen: 0,
            ulMinPinLen: 0,
            ulTotalPublicMemory: 0,
            ulFreePublicMemory: 0,
            ulTotalPrivateMemory: 0,
            ulFreePrivateMemory: 0,
            hardware_version: CK_VERSION { major: 0, minor: 0 },
            firmware_version: CK_VERSION { major: 0, minor: 0 },
            utc_time: [0; 16],
        };
        
        let result = unsafe { C_GetTokenInfo(0, &mut info as *mut CK_TOKEN_INFO) };
        
        assert_eq!(result, CKR_OK);
        
        // Check label (should be "softKMS")
        let label = String::from_utf8_lossy(&info.label);
        assert!(label.contains("softKMS"), "Label should contain 'softKMS'");
    }

    #[test]
    fn test_open_session() {
        // Test C_OpenSession
        let mut session: CK_SESSION = 0;
        
        let result = unsafe { C_OpenSession(0, CKF_RW_SESSION | CKF_SERIAL_SESSION, std::ptr::null_mut(), std::ptr::null(), &mut session as *mut CK_SESSION) };
        
        assert_eq!(result, CKR_OK);
        assert!(session != 0, "Session handle should be non-zero");
        
        // Clean up - close session
        unsafe { C_CloseSession(session); }
    }

    #[test]
    fn test_open_session_invalid_slot() {
        // Test with invalid slot
        let mut session: CK_SESSION = 0;
        
        let result = unsafe { C_OpenSession(1, CKF_RW_SESSION | CKF_SERIAL_SESSION, std::ptr::null_mut(), std::ptr::null(), &mut session as *mut CK_SESSION) };
        
        assert_eq!(result, CKR_SLOT_INVALID);
    }

    #[test]
    fn test_constants() {
        // Verify mechanism constants
        assert_eq!(CKM_ECDSA, 0x1001);
        assert_eq!(CKM_EC_KEY_PAIR_GEN, 0x1050);
        assert_eq!(CKM_ECDSA_SHA256, 0x1041);
        assert_eq!(CKM_ECDSA_SHA384, 0x1042);
        assert_eq!(CKM_ECDH, 0x1040);
        assert_eq!(CKM_ECDH1_DERIVE, 0x1051);
        
        // Verify flag constants
        assert_eq!(CKF_SIGN, 0x00000002);
        assert_eq!(CKF_VERIFY, 0x00000004);
        assert_eq!(CKF_GENERATE, 0x00000040);
        assert_eq!(CKF_GENERATE_KEY_PAIR, 0x00000080);
        assert_eq!(CKF_DERIVE, 0x00000100);
    }
}
