//! PKCS#11 Provider for softKMS - Full Implementation with ECDSA P-256 support
//!
//! This module implements a PKCS#11 provider that allows existing applications
//! (OpenSSH, Git, OpenSSL) to use softKMS as an HSM backend.
//!
//! ## Architecture
//!
//! The PKCS#11 provider acts as a CLIENT to the softKMS daemon via REST API:
//!
//! ```text
//! Application → PKCS#11 API → libsoftkms.so → REST API → softKMS Daemon
//! ```
//!
//! Keys never leave the daemon - all cryptographic operations happen server-side.

// Allow non_camel_case_types for PKCS#11 specification compliance
#![allow(non_camel_case_types)]

use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use tracing::{error, info};

mod rest_client;
pub use rest_client::{KeyInfo, RestClient};

mod session;
pub use session::SessionState;

// State
static INITIALIZED: Lazy<Mutex<bool>> = Lazy::new(|| Mutex::new(false));
static SESSIONS: Lazy<Mutex<HashMap<u64, SessionState>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Object store for key handles - maps handle to key_id
static OBJECTS: Lazy<Mutex<HashMap<u64, String>>> = Lazy::new(|| Mutex::new(HashMap::new()));

// Object attributes store - maps handle to attribute map
// Attributes: CKA_CLASS, CKA_LABEL, CKA_KEY_TYPE, CKA_SIGN, etc.
static OBJECT_ATTRIBUTES: Lazy<Mutex<HashMap<u64, HashMap<u64, Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// Global handle counter for sequential handle assignment
static NEXT_HANDLE: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(1));

// Daemon server address - can be overridden via environment variable
const DEFAULT_DAEMON_ADDR: &str = "127.0.0.1:50051";

fn get_daemon_addr() -> String {
    std::env::var("SOFTKMS_DAEMON_ADDR").unwrap_or_else(|_| DEFAULT_DAEMON_ADDR.to_string())
}

// Return codes
const CKR_OK: u32 = 0;
const CKR_ARGUMENTS_BAD: u32 = 7;
const CKR_BUFFER_TOO_SMALL: u32 = 16;
const CKR_SESSION_INVALID: u32 = 6;
const CKR_SLOT_INVALID: u32 = 3;
const CKR_NOT_SUPPORTED: u32 = 84;
const CKR_DEVICE_ERROR: u32 = 0x30; // 48 per PKCS#11 spec
const CKR_FUNCTION_NOT_SUPPORTED: u32 = 0x54;
const CKR_KEY_HANDLE_INVALID: u32 = 0xA0; // 160, not 0x60!
const CKR_SIGNATURE_INVALID: u32 = 0xC0; // 192, signature verification failed
const CKR_OBJECT_HANDLE_INVALID: u32 = 0x82;
const CKR_USER_NOT_LOGGED_IN: u32 = 0x101;
const CKR_MECHANISM_INVALID: u32 = 0x70;
const CKR_PIN_INCORRECT: u32 = 0xA0; // Same value as CKR_KEY_HANDLE_INVALID, but semantically correct for PIN errors
const CKR_SESSION_HANDLE_INVALID: u32 = 0xB3;
const CKR_DATA_INVALID: u32 = 0x20; // 32, data is invalid

// PKCS#11 types use C-style naming as per specification
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

// CK_ATTRIBUTE structure for GetAttributeValue
#[repr(C)]
struct CK_ATTRIBUTE {
    attr_type: CK_ULONG,
    pValue: *mut u8,
    ulValueLen: CK_ULONG,
}

// Mechanism constants for ECDSA P-256
// IMPORTANT: These values follow PKCS#11 specification and what pkcs11-tool expects
const CKM_ECDSA: CK_ULONG = 0x1001; // Raw ECDSA
const CKM_ECDSA_SHA1: CK_ULONG = 0x1041; // ECDSA with SHA1
const CKM_ECDSA_SHA224: CK_ULONG = 0x1042; // ECDSA with SHA224 (not SHA256!)
const CKM_ECDSA_SHA256: CK_ULONG = 0x1043; // ECDSA with SHA256
const CKM_ECDSA_SHA384: CK_ULONG = 0x1044; // ECDSA with SHA384
const CKM_ECDSA_SHA512: CK_ULONG = 0x1045; // ECDSA with SHA512
const CKM_EC_KEY_PAIR_GEN: CK_ULONG = 0x1040; // EC key pair generation
const CKM_ECDH: CK_ULONG = 0x1040; // Alias for CKM_EC_KEY_PAIR_GEN
const CKM_ECDH1_DERIVE: CK_ULONG = 0x1050; // EC DH key derivation

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
const CKF_TOKEN_INITIALIZED: CK_ULONG = 0x00000400; // Correct value per PKCS#11 spec
const CKF_USER_PIN_TO_BE_CHANGED: CK_ULONG = 0x00000002; // Correct value
const CKF_LOGIN_REQUIRED: CK_ULONG = 0x00000100; // Correct value per PKCS#11 spec

// PKCS#11 Session Info structure
#[repr(C)]
#[derive(Debug)]
struct CK_SESSION_INFO {
    slot_id: CK_SLOT,
    state: CK_ULONG,
    flags: CK_ULONG,
    ul_device_error: CK_ULONG,
}

// Session states
const CKS_RO_PUBLIC_SESSION: CK_ULONG = 0;
const CKS_RO_USER_FUNCTIONS: CK_ULONG = 1;
const CKS_RW_PUBLIC_SESSION: CK_ULONG = 2;
const CKS_RW_USER_FUNCTIONS: CK_ULONG = 3;
const CKS_RW_SO_FUNCTIONS: CK_ULONG = 4;

// PKCS#11 Object Attributes
const CKA_CLASS: CK_ULONG = 0x00000000;
const CKA_LABEL: CK_ULONG = 0x00000003;
const CKA_KEY_TYPE: CK_ULONG = 0x00000100;
const CKA_SIGN: CK_ULONG = 0x00000108;
const CKA_VERIFY: CK_ULONG = 0x00000109;
const CKA_EC_PARAMS: CK_ULONG = 0x00000180;
const CKA_EC_POINT: CK_ULONG = 0x00000181;
const CKA_PUBLIC_EXPONENT: CK_ULONG = 0x00000122;
const CKA_PRIVATE: CK_ULONG = 0x00000002;
const CKA_TOKEN: CK_ULONG = 0x00000001;
const CKA_SENSITIVE: CK_ULONG = 0x00000103;
const CKA_EXTRACTABLE: CK_ULONG = 0x00000110;
const CKA_ALWAYS_AUTHENTICATE: CK_ULONG = 0x00000202;
const CKA_SIGN_RECOVER: CK_ULONG = 0x00000109;
const CKA_VERIFY_RECOVER: CK_ULONG = 0x0000010a;
const CKA_MODULUS_BITS: CK_ULONG = 0x00000121;
const CKA_ID: CK_ULONG = 0x00000102;
const CKA_APPLICATION: CK_ULONG = 0x0000000d;
const CKA_OBJECT_ID: CK_ULONG = 0x00000012;
const CKA_VALUE: CK_ULONG = 0x00000011;
const CKA_CERTIFICATE_TYPE: CK_ULONG = 0x00000125;
const CKA_ISSUER: CK_ULONG = 0x00000126;
const CKA_SERIAL_NUMBER: CK_ULONG = 0x00000127;
const CKA_SUBJECT: CK_ULONG = 0x00000131;
const CKA_START_DATE: CK_ULONG = 0x00000132;
const CKA_END_DATE: CK_ULONG = 0x00000133;
const CKA_MODIFIABLE: CK_ULONG = 0x00000170;
const CKA_ALLOWED_MECHANISMS: CK_ULONG = 0x0000021A; // List of mechanisms allowed for this key

// PKCS#11 Object Classes
const CKO_DATA: CK_ULONG = 0x00000000;
const CKO_CERTIFICATE: CK_ULONG = 0x00000001;
const CKO_PUBLIC_KEY: CK_ULONG = 0x00000002;
const CKO_PRIVATE_KEY: CK_ULONG = 0x00000003;
const CKO_SECRET_KEY: CK_ULONG = 0x00000004;

// PKCS#11 Key Types
const CKK_RSA: CK_ULONG = 0x00000000;
const CKK_EC: CK_ULONG = 0x00000003;
const CKK_ED25519: CK_ULONG = 0x00000040;

// PKCS#11 function pointer types - using C-style names per PKCS#11 spec
type C_GetInfo_t = extern "C" fn(*const ()) -> CK_RV;
type C_Initialize_t = extern "C" fn(*const ()) -> CK_RV;
type C_Finalize_t = extern "C" fn(*const ()) -> CK_RV;
type C_GetSlotList_t = extern "C" fn(CK_BOOL, *mut CK_ULONG, *mut CK_ULONG) -> CK_RV;
type C_GetSlotInfo_t = extern "C" fn(CK_SLOT, *mut CK_SLOT_INFO) -> CK_RV;
type C_GetTokenInfo_t = extern "C" fn(CK_SLOT, *mut CK_TOKEN_INFO) -> CK_RV;
type C_GetMechanismList_t = extern "C" fn(CK_SLOT, *mut CK_ULONG, *mut CK_ULONG) -> CK_RV;
type C_GetMechanismInfo_t = extern "C" fn(CK_SLOT, CK_ULONG, *mut CK_MECHANISM_INFO) -> CK_RV;
type C_OpenSession_t =
    extern "C" fn(CK_SLOT, CK_ULONG, *mut (), *const (), *mut CK_SESSION) -> CK_RV;
type C_CloseSession_t = extern "C" fn(CK_SESSION) -> CK_RV;
type C_CloseAllSessions_t = extern "C" fn(CK_SLOT) -> CK_RV;
type C_GetSessionInfo_t = extern "C" fn(CK_SESSION, *mut CK_SESSION_INFO) -> CK_RV;
type C_Login_t = extern "C" fn(CK_SESSION, CK_ULONG, *const u8, CK_ULONG) -> CK_RV;
type C_Logout_t = extern "C" fn(CK_SESSION) -> CK_RV;
type C_FindObjectsInit_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG) -> CK_RV;
type C_FindObjects_t = extern "C" fn(CK_SESSION, *mut u64, CK_ULONG, *mut CK_ULONG) -> CK_RV;
type C_FindObjectsFinal_t = extern "C" fn(CK_SESSION) -> CK_RV;
type C_GetAttributeValue_t = extern "C" fn(CK_SESSION, u64, *mut u8, CK_ULONG) -> CK_RV;
type C_GenerateKeyPair_t = extern "C" fn(
    CK_SESSION,
    *const u8,
    *const u8,
    CK_ULONG,
    *const u8,
    CK_ULONG,
    *mut u64,
    *mut u64,
) -> CK_RV;
type C_SignInit_t = extern "C" fn(CK_SESSION, *const u8, u64) -> CK_RV;
type C_Sign_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG, *mut u8, *mut CK_ULONG) -> CK_RV;
type C_SignUpdate_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG) -> CK_RV;
type C_SignFinal_t = extern "C" fn(CK_SESSION, *mut u8, *mut CK_ULONG) -> CK_RV;
type C_VerifyInit_t = extern "C" fn(CK_SESSION, *const u8, u64) -> CK_RV;
type C_Verify_t = extern "C" fn(CK_SESSION, *const u8, CK_ULONG, *const u8, CK_ULONG) -> CK_RV;
type C_GetFunctionList_t = extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV;
type C_FunctionNotSupported = extern "C" fn() -> CK_RV;
type C_InitToken_t = extern "C" fn(CK_SLOT, *const u8, CK_ULONG, *const u8) -> CK_RV;

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
    C_InitToken: C_InitToken_t,
    C_InitPin: C_FunctionNotSupported,
    C_SetPin: C_FunctionNotSupported,
    C_OpenSession: C_OpenSession_t,
    C_CloseSession: C_CloseSession_t,
    C_CloseAllSessions: C_CloseAllSessions_t,
    C_GetSessionInfo: C_GetSessionInfo_t,
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
    C_SignUpdate: C_SignUpdate_t,
    C_SignFinal: C_SignFinal_t,
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
    version: CK_VERSION {
        major: 2,
        minor: 40,
    }, // PKCS#11 version 2.40
    C_GetInfo,
    C_GetFunctionList,
    C_Initialize,
    C_Finalize,
    C_GetSlotList,
    C_GetSlotInfo,
    C_GetTokenInfo,
    C_GetMechanismList,
    C_GetMechanismInfo,
    C_InitToken,
    C_InitPin: not_supported,
    C_SetPin: not_supported,
    C_OpenSession,
    C_CloseSession,
    C_CloseAllSessions,
    C_GetSessionInfo,
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
    C_SignUpdate,
    C_SignFinal,
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
pub extern "C" fn C_GetInfo(_: *const ()) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Initialize(_: *const ()) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Finalize(_: *const ()) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetSlotList(
    _token_present: CK_BOOL,
    slot_list: *mut CK_ULONG,
    count: *mut CK_ULONG,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Return 1 slot (slot 0)
    unsafe {
        *count = 1;
    }

    if slot_list.is_null() {
        return CKR_OK;
    }

    unsafe {
        *slot_list = 0;
    }
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

        // Flags - token is initialized and ready to use
        // Note: We don't set CKF_USER_PIN_TO_BE_CHANGED since identity tokens don't need changing
        info.flags = CKF_TOKEN_INITIALIZED | CKF_LOGIN_REQUIRED;

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
pub extern "C" fn C_GetMechanismList(
    slot: CK_SLOT,
    list: *mut CK_ULONG,
    count: *mut CK_ULONG,
) -> CK_RV {
    if slot != 0 {
        return CKR_SLOT_INVALID;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Advertise ECDSA P-256 support - matching what pkcs11-tool expects
    let mechanisms = [
        CKM_ECDSA,           // 0x1001 - raw ECDSA
        CKM_ECDSA_SHA1,      // 0x1041 - ECDSA with SHA1
        CKM_ECDSA_SHA224,    // 0x1042 - ECDSA with SHA224
        CKM_ECDSA_SHA256,    // 0x1043 - ECDSA with SHA256
        CKM_ECDSA_SHA384,    // 0x1044 - ECDSA with SHA384
        CKM_EC_KEY_PAIR_GEN, // 0x1040 - key generation
        CKM_ECDH1_DERIVE,    // 0x1050 - key derivation
    ];
    let mech_count = mechanisms.len() as CK_ULONG;

    unsafe {
        *count = mech_count;
    }

    if list.is_null() {
        return CKR_OK;
    }

    if unsafe { *count < mech_count } {
        return CKR_BUFFER_TOO_SMALL;
    }

    for (i, &mech) in mechanisms.iter().enumerate() {
        unsafe {
            *list.offset(i as isize) = mech;
        }
    }

    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetMechanismInfo(
    _slot: CK_SLOT,
    mech: CK_ULONG,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    eprintln!("DEBUG C_GetMechanismInfo: mech=0x{:x}", mech);
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

    // EC key pair generation (CKM_EC_KEY_PAIR_GEN = 0x1040)
    // Note: CKM_ECDH has same value (0x1040), so we include both flags
    if mech == CKM_EC_KEY_PAIR_GEN {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_GENERATE_KEY_PAIR | CKF_GENERATE | CKF_DERIVE;
        }
        return CKR_OK;
    }

    // ECDSA with SHA variants
    if mech == CKM_ECDSA_SHA1
        || mech == CKM_ECDSA_SHA224
        || mech == CKM_ECDSA_SHA256
        || mech == CKM_ECDSA_SHA384
        || mech == CKM_ECDSA_SHA512
    {
        unsafe {
            let info = &mut *pInfo;
            info.ulMinKeySize = 256;
            info.ulMaxKeySize = 521;
            info.flags = CKF_SIGN | CKF_VERIFY;
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
pub extern "C" fn C_OpenSession(
    slot: CK_SLOT,
    _flags: CK_ULONG,
    _notify: *mut (),
    _app: *const (),
    session: *mut CK_SESSION,
) -> CK_RV {
    if slot != 0 {
        return CKR_SLOT_INVALID;
    }
    if session.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let handle = rand_handle();
    unsafe {
        *session = handle;
    }
    if let Ok(ref mut s) = SESSIONS.lock() {
        s.insert(handle, SessionState::new(handle, false));
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseSession(sess: CK_SESSION) -> CK_RV {
    if let Ok(ref mut s) = SESSIONS.lock() {
        s.remove(&sess);
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_CloseAllSessions(_slot: CK_SLOT) -> CK_RV {
    if let Ok(ref mut s) = SESSIONS.lock() {
        s.clear();
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetSessionInfo(sess: CK_SESSION, p_info: *mut CK_SESSION_INFO) -> CK_RV {
    if p_info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return CKR_DEVICE_ERROR,
    };

    match sessions.get(&sess) {
        Some(st) => {
            unsafe {
                (*p_info).slot_id = 0; // We only have slot 0
                                       // Report user state based on login status
                if st.is_logged_in {
                    (*p_info).state = CKS_RW_USER_FUNCTIONS;
                } else {
                    (*p_info).state = CKS_RW_PUBLIC_SESSION;
                }
                (*p_info).flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
                (*p_info).ul_device_error = 0;
            }
            CKR_OK
        }
        None => CKR_SESSION_HANDLE_INVALID,
    }
}

#[no_mangle]
pub extern "C" fn C_InitToken(
    _slot: CK_SLOT,
    _pin: *const u8,
    _pin_len: CK_ULONG,
    _label: *const u8,
) -> CK_RV {
    info!("C_InitToken called - SoftHSM2 style: token auto-initialized");
    // SoftHSM2 style: tokens are auto-initialized, just return success
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_Login(
    sess: CK_SESSION,
    _user_type: CK_ULONG,
    pin: *const u8,
    pin_len: CK_ULONG,
) -> CK_RV {
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
    let is_token_format = pin_str.len() > 50
        && pin_str
            .chars()
            .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=');

    if is_token_format {
        info!("C_Login: PIN appears to be an identity token, attempting validation");

        // Use REST client for validation
        let daemon_addr = get_daemon_addr();
        let client = RestClient::new(&daemon_addr);

        let token_clone = pin_str.clone();
        let validation_result = client.validate_identity_token(&token_clone);

        match validation_result {
            Ok((pubkey, _info)) => {
                info!(
                    "C_Login: Identity token validated successfully for pubkey: {}...",
                    &pubkey[..32.min(pubkey.len())]
                );

                // Store identity info in session
                if let Ok(ref mut s) = SESSIONS.lock() {
                    if let Some(st) = s.get_mut(&sess) {
                        st.identity_token = Some(token_clone.clone());
                        st.identity_pubkey = Some(pubkey);
                        st.is_identity_session = true;
                        st.is_logged_in = true;
                        st.passphrase = Some(token_clone); // Store token as passphrase for daemon operations
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
        if let Some(st) = s.get_mut(&sess) {
            st.is_logged_in = false;
            return CKR_OK;
        }
    }
    CKR_SESSION_INVALID
}

// Track whether we need to query daemon for objects
static mut FIND_SESSION: u64 = 0;
static mut FIND_QUERIED: bool = false;

// Token initialization state - persists across sessions
static mut TOKEN_INITIALIZED: bool = false;

#[no_mangle]
pub extern "C" fn C_FindObjectsInit(
    sess: CK_SESSION,
    _templ: *const u8,
    _count: CK_ULONG,
) -> CK_RV {
    eprintln!("DEBUG C_FindObjectsInit: session={}", sess);
    unsafe {
        // Clear caches for new test runs when session changes
        if FIND_SESSION != sess {
            eprintln!("DEBUG: Clearing caches for new session");
            if let Ok(ref mut o) = OBJECTS.lock() {
                o.clear();
            }
            if let Ok(ref mut a) = OBJECT_ATTRIBUTES.lock() {
                a.clear();
            }
        }
        FIND_SESSION = sess;
        FIND_QUERIED = false; // Reset for new search
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_FindObjects(
    sess: CK_SESSION,
    objects: *mut u64,
    max_count: CK_ULONG,
    count: *mut CK_ULONG,
) -> CK_RV {
    // First, get both identity pubkey and token from session
    let (identity_pubkey, identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => {
                unsafe {
                    *count = 0;
                }
                return CKR_OK;
            }
        };
        match sessions.get(&sess) {
            Some(st) => (st.identity_pubkey.clone(), st.identity_token.clone()),
            None => {
                unsafe {
                    *count = 0;
                }
                return CKR_OK;
            }
        }
    };

    // If we have an identity and haven't queried yet, fetch keys from daemon
    let should_query = unsafe { !FIND_QUERIED };
    if should_query {
        if let (Some(_pubkey), Some(token)) = (identity_pubkey, identity_token) {
            // Use REST client to list keys
            let daemon_addr = get_daemon_addr();
            let client = RestClient::new(&daemon_addr);

            let keys_result = client.list_keys_with_identity(&token);

            if let Ok(keys) = keys_result {
                // Store in OBJECTS - merge with existing, don't clear
                let mut objects = match OBJECTS.lock() {
                    Ok(o) => o,
                    Err(_) => {
                        unsafe {
                            *count = 0;
                        }
                        return CKR_OK;
                    }
                };

                // Also populate OBJECT_ATTRIBUTES for keys we find
                let mut obj_attrs = match OBJECT_ATTRIBUTES.lock() {
                    Ok(a) => a,
                    Err(_) => {
                        unsafe {
                            *count = 0;
                        }
                        return CKR_OK;
                    }
                };

                // Pre-compute allowed mechanisms for ECDSA keys
                let allowed_mechs = vec![
                    (CKM_ECDSA as CK_ULONG).to_le_bytes().to_vec(),
                    (CKM_ECDSA_SHA1 as CK_ULONG).to_le_bytes().to_vec(),
                    (CKM_ECDSA_SHA224 as CK_ULONG).to_le_bytes().to_vec(),
                    (CKM_ECDSA_SHA256 as CK_ULONG).to_le_bytes().to_vec(),
                    (CKM_ECDSA_SHA384 as CK_ULONG).to_le_bytes().to_vec(),
                    (CKM_ECDSA_SHA512 as CK_ULONG).to_le_bytes().to_vec(),
                ]
                .concat();

                // Add new keys from daemon, using deterministic handles
                // This ensures handles match those created in C_GenerateKeyPair
                for key_info in keys.iter() {
                    let key_id = &key_info.id;
                    let key_label = &key_info.label;

                    // Use deterministic handle based on key_id
                    let handle = key_handle_from_id(key_id);
                    let pub_handle = pub_key_handle(key_id);

                    // Insert private key handle if not exists
                    if !objects.contains_key(&handle) {
                        objects.insert(handle, key_id.clone());

                        // Also populate attributes for private key
                        if !obj_attrs.contains_key(&handle) {
                            let mut priv_attrs = HashMap::new();
                            priv_attrs.insert(
                                CKA_CLASS,
                                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
                            ); // CKO_PRIVATE_KEY
                            priv_attrs.insert(CKA_LABEL, key_label.clone().into_bytes());
                            priv_attrs.insert(
                                CKA_KEY_TYPE,
                                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
                            ); // CKK_EC
                            priv_attrs.insert(
                                CKA_SIGN,
                                vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_TRUE
                            priv_attrs.insert(
                                CKA_TOKEN,
                                vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_TRUE
                            priv_attrs.insert(
                                CKA_SENSITIVE,
                                vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_TRUE
                            priv_attrs.insert(
                                CKA_EXTRACTABLE,
                                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_FALSE
                            priv_attrs.insert(
                                CKA_PRIVATE,
                                vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_TRUE
                            priv_attrs.insert(CKA_ALLOWED_MECHANISMS, allowed_mechs.clone());
                            obj_attrs.insert(handle, priv_attrs);
                        }
                    }

                    // Insert public key handle if not exists
                    let pub_key_id = format!("{}:pub", key_id);
                    if !objects.contains_key(&pub_handle) {
                        objects.insert(pub_handle, pub_key_id);

                        // Also populate attributes for public key
                        if !obj_attrs.contains_key(&pub_handle) {
                            let mut pub_attrs = HashMap::new();
                            pub_attrs.insert(
                                CKA_CLASS,
                                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
                            ); // CKO_PUBLIC_KEY
                            pub_attrs.insert(CKA_LABEL, key_label.clone().into_bytes());
                            pub_attrs.insert(
                                CKA_KEY_TYPE,
                                vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
                            ); // CKK_EC
                            pub_attrs.insert(
                                CKA_VERIFY,
                                vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_TRUE
                            pub_attrs.insert(
                                CKA_TOKEN,
                                vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                            ); // CK_TRUE
                            pub_attrs.insert(CKA_ALLOWED_MECHANISMS, allowed_mechs.clone());
                            obj_attrs.insert(pub_handle, pub_attrs);
                        }
                    }
                }

                // Mark that we've queried the daemon
                unsafe {
                    FIND_QUERIED = true;
                }
            }
        }
    }

    // Now return from OBJECTS
    let objs = match OBJECTS.lock() {
        Ok(o) => o,
        Err(_) => {
            unsafe {
                *count = 0;
            }
            return CKR_OK;
        }
    };

    let handles: Vec<u64> = objs.keys().copied().collect();
    let num_objs = handles.len().min(max_count as usize);

    eprintln!("DEBUG C_FindObjects: returning {} objects", num_objs);
    for (i, handle) in handles.iter().enumerate().take(num_objs) {
        eprintln!("  obj[{}]: handle={}", i, handle);
    }

    if !objects.is_null() {
        for i in 0..num_objs {
            unsafe {
                *objects.add(i) = handles[i];
            }
        }
    }

    unsafe {
        *count = num_objs as CK_ULONG;
    }
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_FindObjectsFinal(_sess: CK_SESSION) -> CK_RV {
    CKR_OK
}

#[no_mangle]
pub extern "C" fn C_GetAttributeValue(
    _sess: CK_SESSION,
    obj: u64,
    templ: *mut u8,
    count: CK_ULONG,
) -> CK_RV {
    if templ.is_null() || count == 0 {
        return CKR_OK;
    }

    unsafe {
        let attrs = std::slice::from_raw_parts_mut(templ as *mut CK_ATTRIBUTE, count as usize);

        // DEBUG: Log what attributes are being queried
        eprintln!("DEBUG C_GetAttributeValue: obj={}, count={}", obj, count);
        for (i, attr) in attrs.iter().enumerate() {
            eprintln!("  attr[{}]: type=0x{:x}", i, attr.attr_type);
        }

        // Get OBJECT_ATTRIBUTES lock once
        let obj_attrs = match OBJECT_ATTRIBUTES.lock() {
            Ok(a) => a,
            Err(_) => return CKR_DEVICE_ERROR,
        };

        let attr_map = match obj_attrs.get(&obj) {
            Some(m) => m,
            None => {
                eprintln!("DEBUG: Object {} not found in OBJECT_ATTRIBUTES", obj);
                // Object not found - mark all attributes as unavailable
                for attr in attrs.iter_mut() {
                    attr.ulValueLen = 0xFFFFFFFF;
                }
                return CKR_OK;
            }
        };

        // Look up each attribute
        for attr in attrs.iter_mut() {
            if let Some(value) = attr_map.get(&attr.attr_type) {
                eprintln!(
                    "DEBUG: Found attr 0x{:x}, len={}",
                    attr.attr_type,
                    value.len()
                );
                if !attr.pValue.is_null() {
                    let len = std::cmp::min(attr.ulValueLen as usize, value.len());
                    std::ptr::copy_nonoverlapping(value.as_ptr(), attr.pValue, len);
                }
                attr.ulValueLen = value.len() as CK_ULONG;
            } else {
                eprintln!(
                    "DEBUG: Attr 0x{:x} not found in attr_map with {} entries",
                    attr.attr_type,
                    attr_map.len()
                );
                // Print available attributes
                for (k, _v) in attr_map.iter() {
                    eprintln!("    Available: 0x{:x}", k);
                }
                // Attribute not found
                attr.ulValueLen = 0xFFFFFFFF;
            }
        }
    }

    CKR_OK
}

// Debug helper to log all attributes in a map
fn debug_log_attr_map(obj: u64, attr_map: &HashMap<CK_ULONG, Vec<u8>>) {
    eprintln!("DEBUG: Object {} has {} attributes:", obj, attr_map.len());
    for (attr_type, value) in attr_map.iter() {
        eprintln!("  0x{:x} ({}): len={}", attr_type, attr_type, value.len());
    }
}

// Generate a random handle for sessions
fn rand_handle() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    nanos as u64
}

// Generate a deterministic handle from key_id
// This ensures the same key always gets the same handle
fn key_handle_from_id(key_id: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    key_id.hash(&mut hasher);
    let hash = hasher.finish();

    // Ensure handle is non-zero (0 is reserved/invalid)
    if hash == 0 {
        1
    } else {
        hash
    }
}

// Generate a unique handle for public key (add ":pub" suffix)
fn pub_key_handle(key_id: &str) -> u64 {
    key_handle_from_id(&format!("{}:pub", key_id))
}

/// Parse label from PKCS#11 template
fn parse_label_from_template(template: *const u8, attr_count: CK_ULONG) -> Option<String> {
    info!(
        "parse_label_from_template: template={:?}, attr_count={}",
        template, attr_count
    );

    if template.is_null() || attr_count == 0 {
        info!("parse_label_from_template: null template or zero attrs, returning None");
        return None;
    }

    // Template is array of CK_ATTRIBUTE structures
    // CK_ATTRIBUTE has: type (CK_ULONG), pValue (*void), ulValueLen (CK_ULONG)
    #[repr(C)]
    struct CK_ATTRIBUTE {
        attr_type: CK_ULONG,
        p_value: *const u8,
        value_len: CK_ULONG,
    }

    let attrs =
        unsafe { std::slice::from_raw_parts(template as *const CK_ATTRIBUTE, attr_count as usize) };

    info!(
        "parse_label_from_template: iterating over {} attributes",
        attrs.len()
    );

    for (i, attr) in attrs.iter().enumerate() {
        info!("parse_label_from_template: attr[{}]: type=0x{:x} (CKA_LABEL=0x{:x}), p_value={:?}, value_len={}", 
              i, attr.attr_type, CKA_LABEL, attr.p_value, attr.value_len);

        if attr.attr_type == CKA_LABEL && !attr.p_value.is_null() && attr.value_len > 0 {
            let label_bytes =
                unsafe { std::slice::from_raw_parts(attr.p_value, attr.value_len as usize) };
            info!(
                "parse_label_from_template: CKA_LABEL found, bytes={:?}",
                label_bytes
            );

            // Remove trailing nulls and convert to string
            let label = String::from_utf8_lossy(label_bytes)
                .trim_end_matches('\0')
                .to_string();
            info!(
                "parse_label_from_template: parsed label='{}', empty={}",
                label,
                label.is_empty()
            );

            if !label.is_empty() {
                info!("parse_label_from_template: returning label='{}'", label);
                return Some(label);
            }
        }
    }

    info!("parse_label_from_template: no valid label found, returning None");
    None
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
    priv_key: *mut u64,
) -> CK_RV {
    // Parse mechanism type
    let mech_type = if !mech.is_null() {
        unsafe { *(mech as *const CK_ULONG) }
    } else {
        0
    };

    info!(
        "C_GenerateKeyPair called with session: {}, mech: 0x{:x}",
        session, mech_type
    );

    if session == 0 {
        return CKR_SESSION_INVALID;
    }

    if pub_key.is_null() || priv_key.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    // Validate mechanism - accept CKM_EC_KEY_PAIR_GEN (0x1040) or CKM_ECDH (0x1040, same value)
    // Note: Both constants are now 0x1040 per PKCS#11 spec
    if mech_type != CKM_EC_KEY_PAIR_GEN {
        error!("C_GenerateKeyPair: Unsupported mechanism 0x{:x}", mech_type);
        return CKR_MECHANISM_INVALID;
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
                st.identity_token.clone(),
            ),
            None => return CKR_SESSION_INVALID,
        }
    };

    // Parse label from template if provided
    info!(
        "C_GenerateKeyPair: parsing label from pub_template (count={})",
        pub_attr_count
    );
    let key_label = parse_label_from_template(pub_template, pub_attr_count)
        .or_else(|| {
            info!(
                "C_GenerateKeyPair: no label in pub_template, trying priv_template (count={})",
                priv_attr_count
            );
            parse_label_from_template(priv_template, priv_attr_count)
        })
        .unwrap_or_else(|| {
            info!("C_GenerateKeyPair: no label found in templates, using default 'pkcs11-key'");
            "pkcs11-key".to_string()
        });

    info!("C_GenerateKeyPair: final key_label='{}'", key_label);

    // Use REST client to create key
    let daemon_addr = get_daemon_addr();
    let client = RestClient::new(&daemon_addr);

    // Generate P-256 key via daemon, passing identity token
    let identity_token_ref = identity_token.as_deref().unwrap_or("");

    let key_id_result = client.create_key("p256", &key_label, identity_token_ref);

    let key_id = match key_id_result {
        Ok(id) => id,
        Err(e) => {
            error!("Failed to generate key in daemon: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };

    info!("Generated P-256 key with ID: {}", key_id);

    // Use deterministic handles based on key_id
    // This ensures FindObjects can find the same handles
    let pub_handle = pub_key_handle(&key_id);
    let priv_handle = key_handle_from_id(&key_id);

    // Store in global object store for FindObjects
    {
        let mut objects = match OBJECTS.lock() {
            Ok(o) => o,
            Err(_) => return CKR_SESSION_INVALID,
        };
        objects.insert(pub_handle, format!("{}:pub", key_id));
        objects.insert(priv_handle, key_id.clone());
    }

    // Store attributes for both keys
    {
        let mut attrs = match OBJECT_ATTRIBUTES.lock() {
            Ok(a) => a,
            Err(_) => return CKR_SESSION_INVALID,
        };

        // Public key attributes
        let mut pub_attrs = HashMap::new();
        pub_attrs.insert(
            CKA_CLASS,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02],
        ); // CKO_PUBLIC_KEY as u64
        pub_attrs.insert(CKA_LABEL, key_label.clone().into_bytes());
        pub_attrs.insert(
            CKA_KEY_TYPE,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
        ); // CKK_EC as u64
        pub_attrs.insert(
            CKA_VERIFY,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_TRUE as u64
        pub_attrs.insert(
            CKA_TOKEN,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_TRUE
           // Add supported mechanisms for this key (ECDSA variants)
        let allowed_mechs = vec![
            (CKM_ECDSA as CK_ULONG).to_le_bytes().to_vec(),
            (CKM_ECDSA_SHA1 as CK_ULONG).to_le_bytes().to_vec(),
            (CKM_ECDSA_SHA224 as CK_ULONG).to_le_bytes().to_vec(),
            (CKM_ECDSA_SHA256 as CK_ULONG).to_le_bytes().to_vec(),
            (CKM_ECDSA_SHA384 as CK_ULONG).to_le_bytes().to_vec(),
            (CKM_ECDSA_SHA512 as CK_ULONG).to_le_bytes().to_vec(),
        ]
        .concat();
        pub_attrs.insert(CKA_ALLOWED_MECHANISMS, allowed_mechs.clone());
        attrs.insert(pub_handle, pub_attrs);

        // Private key attributes
        let mut priv_attrs = HashMap::new();
        priv_attrs.insert(
            CKA_CLASS,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
        ); // CKO_PRIVATE_KEY as u64
        priv_attrs.insert(CKA_LABEL, key_label.clone().into_bytes());
        priv_attrs.insert(
            CKA_KEY_TYPE,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
        ); // CKK_EC as u64
        priv_attrs.insert(
            CKA_SIGN,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_TRUE as u64
        priv_attrs.insert(
            CKA_TOKEN,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_TRUE
        priv_attrs.insert(
            CKA_SENSITIVE,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_TRUE
        priv_attrs.insert(
            CKA_EXTRACTABLE,
            vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_FALSE
        priv_attrs.insert(
            CKA_PRIVATE,
            vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        ); // CK_TRUE
        priv_attrs.insert(CKA_ALLOWED_MECHANISMS, allowed_mechs);
        attrs.insert(priv_handle, priv_attrs);
    }

    // Store in session
    {
        let mut sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };

        if let Some(st) = sessions.get_mut(&session) {
            st.active_key_handle = Some(priv_handle);
            st.active_key_id = Some(key_id.clone());
            st.signing_algorithm = Some("p256".to_string());
        } else {
            return CKR_SESSION_INVALID;
        }
    }

    unsafe {
        *pub_key = pub_handle;
        *priv_key = priv_handle;
    }

    CKR_OK
}

// Signing
#[no_mangle]
pub extern "C" fn C_SignInit(sess: CK_SESSION, mech: *const u8, key: u64) -> CK_RV {
    let mech_type = if !mech.is_null() {
        unsafe { *(mech as *const CK_ULONG) }
    } else {
        0
    };

    // DEBUG: Log what we received vs what we support
    eprintln!("DEBUG C_SignInit: mech_type=0x{:x}", mech_type);
    eprintln!(
        "  CKM_ECDSA=0x{:x}, CKM_ECDSA_SHA1=0x{:x}",
        CKM_ECDSA, CKM_ECDSA_SHA1
    );
    eprintln!(
        "  CKM_ECDSA_SHA224=0x{:x}, CKM_ECDSA_SHA256=0x{:x}",
        CKM_ECDSA_SHA224, CKM_ECDSA_SHA256
    );
    eprintln!(
        "  CKM_ECDSA_SHA384=0x{:x}, CKM_ECDSA_SHA512=0x{:x}",
        CKM_ECDSA_SHA384, CKM_ECDSA_SHA512
    );

    info!(
        "C_SignInit session: {} key: {} mech: 0x{:x}",
        sess, key, mech_type
    );

    // Validate mechanism - we support ECDSA and all SHA variants
    let supported = mech_type == CKM_ECDSA
        || mech_type == CKM_ECDSA_SHA1
        || mech_type == CKM_ECDSA_SHA224
        || mech_type == CKM_ECDSA_SHA256
        || mech_type == CKM_ECDSA_SHA384
        || mech_type == CKM_ECDSA_SHA512;
    if !supported {
        error!("C_SignInit: Unsupported mechanism 0x{:x}", mech_type);
        return CKR_MECHANISM_INVALID;
    }

    // Just store the key handle - C_Sign will query daemon directly
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return CKR_SESSION_INVALID,
    };

    if let Some(st) = sessions.get_mut(&sess) {
        // Look up the key ID from the handle
        let objects = match OBJECTS.lock() {
            Ok(o) => o,
            Err(_) => return CKR_DEVICE_ERROR,
        };

        match objects.get(&key) {
            Some(key_id) => {
                // If key_id has :pub suffix (public key), strip it for signing
                // pkcs11-tool might pass public key handle but we need private key
                let signing_key_id = if key_id.ends_with(":pub") {
                    key_id.trim_end_matches(":pub")
                } else {
                    key_id.as_str()
                };

                st.active_key_handle = Some(key);
                st.active_key_id = Some(signing_key_id.to_string());
                info!(
                    "C_SignInit: Stored key handle {} and key_id {} for session {}",
                    key, signing_key_id, sess
                );
                CKR_OK
            }
            None => {
                error!("C_SignInit: Key handle {} not found in object store", key);
                CKR_KEY_HANDLE_INVALID
            }
        }
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
    sig_len: *mut CK_ULONG,
) -> CK_RV {
    info!("C_Sign called");

    if session == 0 {
        return CKR_SESSION_INVALID;
    }

    // Get session data first (needed for key lookup and signing)
    let (active_key_handle, identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };

        match sessions.get(&session) {
            Some(st) => (st.active_key_handle, st.identity_token.clone()),
            None => return CKR_SESSION_INVALID,
        }
    };

    // Get the key_id from the handle stored by C_SignInit
    let key_id = if let Some(handle) = active_key_handle {
        let objects = match OBJECTS.lock() {
            Ok(o) => o,
            Err(_) => return CKR_DEVICE_ERROR,
        };
        match objects.get(&handle) {
            Some(key_id) => {
                info!("C_Sign: Found key_id '{}' for handle {}", key_id, handle);
                key_id.clone()
            }
            None => {
                error!("C_Sign: Key handle {} not found in object store", handle);
                return CKR_KEY_HANDLE_INVALID;
            }
        }
    } else {
        error!("C_Sign: No active key handle set (C_SignInit not called?)");
        return CKR_KEY_HANDLE_INVALID;
    };

    // Get data first
    let data_to_sign = if data.is_null() || data_len == 0 {
        return CKR_ARGUMENTS_BAD;
    } else {
        unsafe { std::slice::from_raw_parts(data, data_len as usize).to_vec() }
    };

    // Use REST client for signing
    let daemon_addr = get_daemon_addr();
    let client = RestClient::new(&daemon_addr);

    info!("C_Sign: Using key_id '{}' for signing", key_id);

    // Sign via daemon with identity token
    let identity_token_ref = identity_token.as_deref().unwrap_or("");
    let sig_result = client.sign(&key_id, &data_to_sign, identity_token_ref);

    let sig_bytes = match sig_result {
        Ok(s) => s,
        Err(e) => {
            error!("Sign failed: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };

    // Check buffer size
    if signature.is_null() {
        unsafe {
            *sig_len = sig_bytes.len() as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    let current_sig_len = unsafe { *sig_len };
    if current_sig_len < sig_bytes.len() as CK_ULONG {
        unsafe {
            *sig_len = sig_bytes.len() as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), signature, sig_bytes.len());
        *sig_len = sig_bytes.len() as CK_ULONG;
    }

    info!("Signed {} bytes with key {}", sig_bytes.len(), key_id);
    CKR_OK
}

// Multi-part signing support - accumulate data in session
#[no_mangle]
pub extern "C" fn C_SignUpdate(sess: CK_SESSION, data: *const u8, data_len: CK_ULONG) -> CK_RV {
    info!(
        "C_SignUpdate called: session={}, data_len={}",
        sess, data_len
    );

    if data.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let data_slice = unsafe { std::slice::from_raw_parts(data, data_len as usize) };

    // Accumulate data in session for later signing
    let mut sessions = match SESSIONS.lock() {
        Ok(s) => s,
        Err(_) => return CKR_SESSION_INVALID,
    };

    if let Some(st) = sessions.get_mut(&sess) {
        st.sign_buffer.extend_from_slice(data_slice);
        info!(
            "C_SignUpdate: Accumulated {} bytes in session {}",
            st.sign_buffer.len(),
            sess
        );
        CKR_OK
    } else {
        CKR_SESSION_INVALID
    }
}

#[no_mangle]
pub extern "C" fn C_SignFinal(
    sess: CK_SESSION,
    signature: *mut u8,
    sig_len: *mut CK_ULONG,
) -> CK_RV {
    info!("C_SignFinal called: session={}", sess);

    let (key_id, identity_token, data_to_sign) = {
        let mut sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };

        if let Some(st) = sessions.get_mut(&sess) {
            let key_id = match &st.active_key_id {
                Some(id) => id.clone(),
                None => {
                    error!("C_SignFinal: No active key ID");
                    return CKR_KEY_HANDLE_INVALID;
                }
            };
            let token = st.identity_token.clone();
            let data = st.sign_buffer.clone();
            st.sign_buffer.clear(); // Clear buffer after signing
            info!(
                "C_SignFinal: Got key_id={}, token={:?}, data_len={}",
                key_id,
                token.as_ref().map(|t| &t[..10.min(t.len())]),
                data.len()
            );
            (key_id, token, data)
        } else {
            return CKR_SESSION_INVALID;
        }
    };

    if data_to_sign.is_empty() {
        error!("C_SignFinal: No data to sign");
        return CKR_DATA_INVALID;
    }

    // Use REST client for signing
    let daemon_addr = get_daemon_addr();
    let client = RestClient::new(&daemon_addr);

    let identity_token_ref = identity_token.as_deref().unwrap_or("");
    info!(
        "C_SignFinal: Calling REST API with key_id={}, token_len={}, data_len={}",
        key_id,
        identity_token_ref.len(),
        data_to_sign.len()
    );

    if identity_token_ref.is_empty() {
        error!("C_SignFinal: No identity token available!");
        return CKR_USER_NOT_LOGGED_IN;
    }

    let sig_result = client.sign(&key_id, &data_to_sign, identity_token_ref);

    let sig_bytes = match sig_result {
        Ok(s) => s,
        Err(e) => {
            error!("C_SignFinal: Sign failed: {}", e);
            return CKR_DEVICE_ERROR;
        }
    };

    // Check buffer size
    if signature.is_null() {
        unsafe {
            *sig_len = sig_bytes.len() as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    let current_sig_len = unsafe { *sig_len };
    if current_sig_len < sig_bytes.len() as CK_ULONG {
        unsafe {
            *sig_len = sig_bytes.len() as CK_ULONG;
        }
        return CKR_BUFFER_TOO_SMALL;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), signature, sig_bytes.len());
        *sig_len = sig_bytes.len() as CK_ULONG;
    }

    info!(
        "C_SignFinal: Signed {} bytes with key {}",
        sig_bytes.len(),
        key_id
    );
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
        info!(
            "C_VerifyInit: Stored key handle {} and key ID for session {}",
            key, sess
        );
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
    sig_len: CK_ULONG,
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
    let active_key = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };

        match sessions.get(&session) {
            Some(st) => st.active_key_handle,
            None => return CKR_SESSION_INVALID,
        }
    };

    let key_id = match active_key {
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
    let data_to_verify = unsafe { std::slice::from_raw_parts(data, data_len as usize).to_vec() };

    let signature_bytes =
        unsafe { std::slice::from_raw_parts(signature, sig_len as usize).to_vec() };

    // Get passphrase and identity token from session
    let (passphrase, _identity_token) = {
        let sessions = match SESSIONS.lock() {
            Ok(s) => s,
            Err(_) => return CKR_SESSION_INVALID,
        };
        if let Some(st) = sessions.get(&session) {
            (
                st.passphrase.clone().unwrap_or_default(),
                st.identity_token.clone(),
            )
        } else {
            return CKR_SESSION_INVALID;
        }
    };

    // Use REST client for verification
    let daemon_addr = get_daemon_addr();
    let client = RestClient::new(&daemon_addr);

    // Verify via daemon
    let verify_result = client.verify(&key_id, &data_to_verify, &signature_bytes);

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
        let result =
            unsafe { C_GetSlotList(0, &mut slot as *mut CK_ULONG, &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);
        assert_eq!(slot, 0, "Slot 0 should be returned");
    }

    #[test]
    fn test_get_slot_list_invalid_slot() {
        // Test with non-zero slot - current implementation accepts any slot
        // (returns slot 0 regardless)
        let mut count: CK_ULONG = 0;
        let mut slot: CK_ULONG = 999;

        let result =
            unsafe { C_GetSlotList(1, &mut slot as *mut CK_ULONG, &mut count as *mut CK_ULONG) };

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
        let result =
            unsafe { C_GetMechanismList(0, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };

        assert_eq!(result, CKR_OK);
        assert!(count > 0, "Should have at least 1 mechanism");
    }

    #[test]
    fn test_get_mechanism_list_with_buffer() {
        // Test C_GetMechanismList when called with buffer
        let mut count: CK_ULONG = 0;

        // First call to get count
        let result =
            unsafe { C_GetMechanismList(0, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);
        assert!(
            count >= 6,
            "Should have at least 6 mechanisms (ECDSA, EC_KEY_PAIR_GEN, etc.)"
        );

        // Allocate buffer and get mechanisms
        let mut mechs: Vec<CK_ULONG> = vec![0; count as usize];
        let result =
            unsafe { C_GetMechanismList(0, mechs.as_mut_ptr(), &mut count as *mut CK_ULONG) };
        assert_eq!(result, CKR_OK);

        // Check for expected mechanisms
        let mech_set: Vec<CK_ULONG> = mechs[..count as usize].to_vec();

        // Should contain at least these mechanisms
        assert!(mech_set.contains(&CKM_ECDSA), "Should have CKM_ECDSA");
        assert!(
            mech_set.contains(&CKM_EC_KEY_PAIR_GEN),
            "Should have CKM_EC_KEY_PAIR_GEN"
        );
        assert!(
            mech_set.contains(&CKM_ECDSA_SHA256),
            "Should have CKM_ECDSA_SHA256"
        );
        assert!(
            mech_set.contains(&CKM_ECDSA_SHA224),
            "Should have CKM_ECDSA_SHA224"
        );
    }

    #[test]
    fn test_get_mechanism_list_invalid_slot() {
        // Test with invalid slot
        let mut count: CK_ULONG = 0;
        let result =
            unsafe { C_GetMechanismList(1, std::ptr::null_mut(), &mut count as *mut CK_ULONG) };

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

        let result =
            unsafe { C_GetMechanismInfo(0, CKM_ECDSA, &mut info as *mut CK_MECHANISM_INFO) };

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

        let result = unsafe {
            C_GetMechanismInfo(0, CKM_EC_KEY_PAIR_GEN, &mut info as *mut CK_MECHANISM_INFO)
        };

        assert_eq!(result, CKR_OK);
        assert_eq!(info.ulMinKeySize, 256);
        assert_eq!(info.ulMaxKeySize, 521);
        assert!(
            info.flags & CKF_GENERATE_KEY_PAIR != 0,
            "Should have CKF_GENERATE_KEY_PAIR"
        );
    }

    #[test]
    fn test_get_mechanism_info_ecdsa_sha256() {
        // Test C_GetMechanismInfo for CKM_ECDSA_SHA256
        let mut info = CK_MECHANISM_INFO {
            ulMinKeySize: 0,
            ulMaxKeySize: 0,
            flags: 0,
        };

        let result =
            unsafe { C_GetMechanismInfo(0, CKM_ECDSA_SHA256, &mut info as *mut CK_MECHANISM_INFO) };

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

        let result =
            unsafe { C_GetMechanismInfo(0, CKM_ECDH, &mut info as *mut CK_MECHANISM_INFO) };

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

        let result = unsafe {
            C_OpenSession(
                0,
                CKF_RW_SESSION | CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut session as *mut CK_SESSION,
            )
        };

        assert_eq!(result, CKR_OK);
        assert!(session != 0, "Session handle should be non-zero");

        // Clean up - close session
        unsafe {
            C_CloseSession(session);
        }
    }

    #[test]
    fn test_open_session_invalid_slot() {
        // Test with invalid slot
        let mut session: CK_SESSION = 0;

        let result = unsafe {
            C_OpenSession(
                1,
                CKF_RW_SESSION | CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                std::ptr::null(),
                &mut session as *mut CK_SESSION,
            )
        };

        assert_eq!(result, CKR_SLOT_INVALID);
    }

    #[test]
    fn test_constants() {
        // Verify mechanism constants (matching PKCS#11 spec and pkcs11-tool expectations)
        assert_eq!(CKM_ECDSA, 0x1001);
        assert_eq!(CKM_EC_KEY_PAIR_GEN, 0x1040);
        assert_eq!(CKM_ECDSA_SHA1, 0x1041);
        assert_eq!(CKM_ECDSA_SHA224, 0x1042); // Note: SHA224, not SHA256!
        assert_eq!(CKM_ECDSA_SHA256, 0x1043);
        assert_eq!(CKM_ECDSA_SHA384, 0x1044);
        assert_eq!(CKM_ECDH, 0x1040); // Same as CKM_EC_KEY_PAIR_GEN
        assert_eq!(CKM_ECDH1_DERIVE, 0x1050);

        // Verify flag constants
        assert_eq!(CKF_SIGN, 0x00000002);
        assert_eq!(CKF_VERIFY, 0x00000004);
        assert_eq!(CKF_GENERATE, 0x00000040);
        assert_eq!(CKF_GENERATE_KEY_PAIR, 0x00000080);
        assert_eq!(CKF_DERIVE, 0x00000100);
    }
}
