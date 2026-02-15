#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef unsigned long CK_ULONG;
typedef unsigned long CK_SESSION;
typedef unsigned long CK_RV;
typedef unsigned long CK_OBJECT_HANDLE;

typedef CK_RV (*C_Initialize_t)(void *);
typedef CK_RV (*C_Finalize_t)(void *);
typedef CK_RV (*C_GetSlotList_t)(unsigned char, unsigned long *, CK_ULONG *);
typedef CK_RV (*C_GetSlotInfo_t)(unsigned long, void *);
typedef CK_RV (*C_GetTokenInfo_t)(unsigned long, void *);
typedef CK_RV (*C_GetMechanismList_t)(unsigned long, unsigned long *, CK_ULONG *);
typedef CK_RV (*C_OpenSession_t)(unsigned long, unsigned long, void *, void *, unsigned long *);
typedef CK_RV (*C_CloseSession_t)(CK_SESSION);
typedef CK_RV (*C_Login_t)(CK_SESSION, unsigned long, unsigned char *, CK_ULONG);
typedef CK_RV (*C_Logout_t)(CK_SESSION);
typedef CK_RV (*C_FindObjectsInit_t)(CK_SESSION, unsigned char *, CK_ULONG);
typedef CK_RV (*C_FindObjects_t)(CK_SESSION, CK_OBJECT_HANDLE *, CK_ULONG, CK_ULONG *);
typedef CK_RV (*C_FindObjectsFinal_t)(CK_SESSION);
typedef CK_RV (*C_GenerateKeyPair_t)(CK_SESSION, unsigned char *, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG, CK_OBJECT_HANDLE *, CK_OBJECT_HANDLE *);
typedef CK_RV (*C_SignInit_t)(CK_SESSION, unsigned char *, CK_ULONG);
typedef CK_RV (*C_Sign_t)(CK_SESSION, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG *);
typedef CK_RV (*C_VerifyInit_t)(CK_SESSION, unsigned char *, CK_ULONG);
typedef CK_RV (*C_Verify_t)(CK_SESSION, unsigned char *, CK_ULONG, unsigned char *, CK_ULONG);

const char *get_module_path() {
    const char *custom_path = getenv("SOFTKMS_PKCS11_MODULE");
    if (custom_path) return custom_path;
    return "./target/debug/libsoftkms.so";
}

const char *get_passphrase() {
    const char *pass = getenv("SOFTKMS_PASSPHRASE");
    if (pass) return pass;
    return "test";
}

void print_rv(const char *func, CK_RV rv) {
    const char *status;
    if (rv == 0) status = "OK";
    else if (rv == 0x54) status = "NOT_SUPPORTED";
    else if (rv == 0x06) status = "SESSION_INVALID";
    else if (rv == 0x60) status = "KEY_HANDLE_INVALID";
    else if (rv == 0x07) status = "ARGUMENTS_BAD";
    else if (rv == 0x03) status = "SLOT_INVALID";
    else status = "UNKNOWN";
    printf("%s: rv=0x%lx (%s)\n", func, rv, status);
}

int main(int argc, char *argv[]) {
    int test_genkey = 1;
    int test_sign = 1;
    int test_verify = 0;  // Not implemented yet
    int test_list = 0;    // Not implemented yet
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--genkey") == 0) test_genkey = 1;
        else if (strcmp(argv[i], "--sign") == 0) test_sign = 1;
        else if (strcmp(argv[i], "--no-genkey") == 0) test_genkey = 0;
        else if (strcmp(argv[i], "--no-sign") == 0) test_sign = 0;
        else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --genkey    Generate Ed25519 key pair (default)\n");
            printf("  --sign      Test signing (requires --genkey)\n");
            printf("  --no-genkey Skip key generation\n");
            printf("  --no-sign   Skip signing test\n");
            printf("\nEnvironment variables:\n");
            printf("  SOFTKMS_PKCS11_MODULE    Path to libsoftkms.so\n");
            printf("  SOFTKMS_PASSPHRASE      Passphrase for keystore (default: 'test')\n");
            return 0;
        }
    }
    
    const char *module_path = get_module_path();
    const char *passphrase = get_passphrase();
    
    printf("=== softKMS PKCS#11 Test ===\n");
    printf("Module: %s\n", module_path);
    printf("Passphrase: %s\n\n", passphrase);
    
    void *handle = dlopen(module_path, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "ERROR: Failed to load module: %s\n", dlerror());
        return 1;
    }
    
    // Load functions
    C_Initialize_t C_Initialize = dlsym(handle, "C_Initialize");
    C_Finalize_t C_Finalize = dlsym(handle, "C_Finalize");
    C_GetSlotList_t C_GetSlotList = dlsym(handle, "C_GetSlotList");
    C_GetMechanismList_t C_GetMechanismList = dlsym(handle, "C_GetMechanismList");
    C_OpenSession_t C_OpenSession = dlsym(handle, "C_OpenSession");
    C_CloseSession_t C_CloseSession = dlsym(handle, "C_CloseSession");
    C_Login_t C_Login = dlsym(handle, "C_Login");
    C_Logout_t C_Logout = dlsym(handle, "C_Logout");
    C_GenerateKeyPair_t C_GenerateKeyPair = dlsym(handle, "C_GenerateKeyPair");
    C_SignInit_t C_SignInit = dlsym(handle, "C_SignInit");
    C_Sign_t C_Sign = dlsym(handle, "C_Sign");
    
    printf("Functions loaded successfully\n\n");
    
    // Initialize
    printf("--- Initialization ---\n");
    print_rv("C_Initialize", C_Initialize(NULL));
    
    // Get slot list
    CK_ULONG slot_count = 0;
    print_rv("C_GetSlotList", C_GetSlotList(0, NULL, &slot_count));
    printf("  Found %lu slots\n", slot_count);
    
    // Get mechanism list
    CK_ULONG mech_count = 0;
    print_rv("C_GetMechanismList", C_GetMechanismList(0, NULL, &mech_count));
    printf("  Supported mechanisms: %lu\n", mech_count);
    
    // Open session
    printf("\n--- Session ---\n");
    CK_SESSION session = 0;
    print_rv("C_OpenSession", C_OpenSession(0, 4, NULL, NULL, &session));  // CKF_RW_SESSION | CKF_SERIAL_SESSION
    printf("  Session handle: %lu\n", session);
    
    // Login
    print_rv("C_Login", C_Login(session, 0, (unsigned char *)passphrase, strlen(passphrase)));
    
    CK_OBJECT_HANDLE pub_key = 0, priv_key = 0;
    
    // Generate key pair
    if (test_genkey) {
        printf("\n--- Key Generation ---\n");
        CK_RV rv = C_GenerateKeyPair(session, NULL, NULL, 0, NULL, 0, &pub_key, &priv_key);
        print_rv("C_GenerateKeyPair", rv);
        printf("  Public key handle: %lu\n", pub_key);
        printf("  Private key handle: %lu\n", priv_key);
        
        if (rv != 0) {
            fprintf(stderr, "Key generation failed!\n");
            C_CloseSession(session);
            C_Finalize(NULL);
            dlclose(handle);
            return 1;
        }
    }
    
    // Sign
    if (test_sign && pub_key != 0) {
        printf("\n--- Signing ---\n");
        
        // SignInit
        print_rv("C_SignInit", C_SignInit(session, NULL, 0));
        
        // Prepare data to sign
        unsigned char data[] = "Hello from softKMS PKCS#11!";
        unsigned char signature[128];
        CK_ULONG sig_len = sizeof(signature);
        
        // Sign
        print_rv("C_Sign", C_Sign(session, data, sizeof(data) - 1, signature, &sig_len));
        printf("  Data signed: \"%s\"\n", data);
        printf("  Signature length: %lu bytes\n", sig_len);
        
        // Print signature as hex
        printf("  Signature (hex): ");
        for (CK_ULONG i = 0; i < sig_len && i < 16; i++) {
            printf("%02x", signature[i]);
        }
        if (sig_len > 16) printf("...");
        printf("\n");
    }
    
    // Logout and close
    printf("\n--- Cleanup ---\n");
    print_rv("C_Logout", C_Logout(session));
    print_rv("C_CloseSession", C_CloseSession(session));
    print_rv("C_Finalize", C_Finalize(NULL));
    
    dlclose(handle);
    
    printf("\n=== Test Complete ===\n");
    return 0;
}
