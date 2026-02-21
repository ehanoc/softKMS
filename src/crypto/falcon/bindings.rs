pub use libc::{c_int, c_uint, c_void, size_t};

#[repr(C)]
pub struct shake256_context {
    pub opaque_contents: [u64; 26],
}

pub const FALCON_SIG_COMPRESSED: c_int = 1;
pub const FALCON_SIG_PADDED: c_int = 2;
pub const FALCON_SIG_CT: c_int = 3;

pub const FALCON_ERR_OK: c_int = 0;
pub const FALCON_ERR_RANDOM: c_int = -1;
pub const FALCON_ERR_SIZE: c_int = -2;
pub const FALCON_ERR_FORMAT: c_int = -3;
pub const FALCON_ERR_BADSIG: c_int = -4;
pub const FALCON_ERR_BADARG: c_int = -5;
pub const FALCON_ERR_INTERNAL: c_int = -6;

pub const FALCON_LOGN_512: c_uint = 9;
pub const FALCON_LOGN_1024: c_uint = 10;

// From standard Falcon C library
pub const FALCON512_PRIVKEY_SIZE: size_t = 1281;
pub const FALCON512_PUBKEY_SIZE: size_t = 897;
pub const FALCON512_SIG_MAXSIZE: size_t = 752;
pub const FALCON512_TMPSIZE_KEYGEN: size_t = 15879;
pub const FALCON512_TMPSIZE_SIGN: size_t = 39943;
pub const FALCON512_TMPSIZE_VERIFY: size_t = 4097;

pub const FALCON1024_PRIVKEY_SIZE: size_t = 2305;
pub const FALCON1024_PUBKEY_SIZE: size_t = 1793;
pub const FALCON1024_SIG_MAXSIZE: size_t = 1462;
pub const FALCON1024_TMPSIZE_KEYGEN: size_t = 31751;
pub const FALCON1024_TMPSIZE_SIGN: size_t = 79879;
pub const FALCON1024_TMPSIZE_VERIFY: size_t = 8193;

extern "C" {
    pub fn shake256_init_prng_from_seed(
        sc: *mut shake256_context,
        seed: *const c_void,
        seed_len: size_t,
    );

    pub fn shake256_init_prng_from_system(sc: *mut shake256_context) -> c_int;

    pub fn falcon_keygen_make(
        rng: *mut shake256_context,
        logn: c_uint,
        privkey: *mut libc::c_void,
        privkey_len: size_t,
        pubkey: *mut libc::c_void,
        pubkey_len: size_t,
        tmp: *mut libc::c_void,
        tmp_len: size_t,
    ) -> c_int;

    pub fn falcon_sign_dyn(
        rng: *mut shake256_context,
        sig: *mut libc::c_void,
        sig_len: *mut size_t,
        sig_type: c_int,
        privkey: *const libc::c_void,
        privkey_len: size_t,
        data: *const libc::c_void,
        data_len: size_t,
        tmp: *mut libc::c_void,
        tmp_len: size_t,
    ) -> c_int;

    pub fn falcon_verify(
        sig: *const libc::c_void,
        sig_len: size_t,
        sig_type: c_int,
        pubkey: *const libc::c_void,
        pubkey_len: size_t,
        data: *const libc::c_void,
        data_len: size_t,
        tmp: *mut libc::c_void,
        tmp_len: size_t,
    ) -> c_int;

    pub fn falcon_get_logn(obj: *const libc::c_void, len: size_t) -> c_int;
}
