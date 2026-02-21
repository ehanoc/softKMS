pub mod bindings;
pub mod buffer;

use crate::{Error, Result};
use bindings::*;
use buffer::FalconBuffer;
use libc::c_void;
use secrecy::{ExposeSecret, Secret};
use std::mem::MaybeUninit;

#[derive(Debug, Clone)]
pub enum FalconVariant {
    Falcon512,
    Falcon1024,
}

impl FalconVariant {
    pub fn logn(&self) -> c_uint {
        match self {
            FalconVariant::Falcon512 => FALCON_LOGN_512,
            FalconVariant::Falcon1024 => FALCON_LOGN_1024,
        }
    }

    pub fn privkey_size(&self) -> size_t {
        match self {
            FalconVariant::Falcon512 => FALCON512_PRIVKEY_SIZE,
            FalconVariant::Falcon1024 => FALCON1024_PRIVKEY_SIZE,
        }
    }

    pub fn pubkey_size(&self) -> size_t {
        match self {
            FalconVariant::Falcon512 => FALCON512_PUBKEY_SIZE,
            FalconVariant::Falcon1024 => FALCON1024_PUBKEY_SIZE,
        }
    }

    pub fn sig_maxsize(&self) -> size_t {
        match self {
            FalconVariant::Falcon512 => FALCON512_SIG_MAXSIZE,
            FalconVariant::Falcon1024 => FALCON1024_SIG_MAXSIZE,
        }
    }

    pub fn tmpsize_keygen(&self) -> size_t {
        match self {
            FalconVariant::Falcon512 => FALCON512_TMPSIZE_KEYGEN,
            FalconVariant::Falcon1024 => FALCON1024_TMPSIZE_KEYGEN,
        }
    }

    pub fn tmpsize_sign(&self) -> size_t {
        match self {
            FalconVariant::Falcon512 => FALCON512_TMPSIZE_SIGN,
            FalconVariant::Falcon1024 => FALCON1024_TMPSIZE_SIGN,
        }
    }

    pub fn tmpsize_verify(&self) -> size_t {
        match self {
            FalconVariant::Falcon512 => FALCON512_TMPSIZE_VERIFY,
            FalconVariant::Falcon1024 => FALCON1024_TMPSIZE_VERIFY,
        }
    }
}

pub struct FalconEngine {
    variant: FalconVariant,
}

impl FalconEngine {
    pub fn new(variant: FalconVariant) -> Self {
        Self { variant }
    }

    pub fn generate_key(&self) -> Result<(Secret<Vec<u8>>, Vec<u8>)> {
        let mut rng = unsafe { MaybeUninit::<shake256_context>::zeroed().assume_init() };

        // Initialize RNG from system randomness
        let rng_result = unsafe { shake256_init_prng_from_system(&mut rng) };

        if rng_result != FALCON_ERR_OK {
            return Err(Error::Crypto(format!(
                "RNG initialization failed: {}",
                rng_result
            )));
        }

        let mut privkey = FalconBuffer::new(self.variant.privkey_size());
        let mut pubkey = FalconBuffer::new(self.variant.pubkey_size());
        let mut tmp = FalconBuffer::new(self.variant.tmpsize_keygen());

        let result = unsafe {
            falcon_keygen_make(
                &mut rng,
                self.variant.logn(),
                privkey.as_mut_ptr(),
                self.variant.privkey_size(),
                pubkey.as_mut_ptr(),
                self.variant.pubkey_size(),
                tmp.as_mut_ptr(),
                self.variant.tmpsize_keygen(),
            )
        };

        if result != FALCON_ERR_OK {
            return Err(Error::Crypto(format!("Falcon keygen failed: {}", result)));
        }

        let secret_key = Secret::new(privkey.as_slice().to_vec());
        let public_key = pubkey.as_slice().to_vec();

        Ok((secret_key, public_key))
    }

    pub fn sign(&self, secret_key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
        let mut rng = unsafe { MaybeUninit::<shake256_context>::zeroed().assume_init() };

        // Initialize RNG from system randomness
        let rng_result = unsafe { shake256_init_prng_from_system(&mut rng) };

        if rng_result != FALCON_ERR_OK {
            return Err(Error::Crypto(format!(
                "RNG initialization failed: {}",
                rng_result
            )));
        }

        let mut privkey = FalconBuffer::new(secret_key.len());
        privkey.as_mut_slice().copy_from_slice(secret_key);

        let mut sig = FalconBuffer::new(self.variant.sig_maxsize());
        let mut sig_len: size_t = self.variant.sig_maxsize();
        let mut tmp = FalconBuffer::new(self.variant.tmpsize_sign());

        let result = unsafe {
            falcon_sign_dyn(
                &mut rng,
                sig.as_mut_ptr(),
                &mut sig_len,
                FALCON_SIG_COMPRESSED,
                privkey.as_ptr(),
                self.variant.privkey_size(),
                data.as_ptr() as *const c_void,
                data.len(),
                tmp.as_mut_ptr(),
                self.variant.tmpsize_sign(),
            )
        };

        if result != FALCON_ERR_OK {
            return Err(Error::Crypto(format!("Falcon sign failed: {}", result)));
        }

        Ok(sig.as_slice()[..sig_len as usize].to_vec())
    }

    pub fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool> {
        let mut tmp = FalconBuffer::new(self.variant.tmpsize_verify());

        let result = unsafe {
            falcon_verify(
                signature.as_ptr() as *const c_void,
                signature.len(),
                FALCON_SIG_COMPRESSED,
                public_key.as_ptr() as *const c_void,
                public_key.len(),
                data.as_ptr() as *const c_void,
                data.len(),
                tmp.as_mut_ptr(),
                self.variant.tmpsize_verify(),
            )
        };

        match result {
            FALCON_ERR_OK => Ok(true),
            FALCON_ERR_BADSIG => Ok(false),
            other => Err(Error::Crypto(format!("Falcon verify failed: {}", other))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon512_keygen() {
        let engine = FalconEngine::new(FalconVariant::Falcon512);
        let (sk, pk) = engine.generate_key().unwrap();

        assert_eq!(sk.expose_secret().len(), FALCON512_PRIVKEY_SIZE);
        assert_eq!(pk.len(), FALCON512_PUBKEY_SIZE);
    }

    #[test]
    fn test_falcon1024_keygen() {
        let engine = FalconEngine::new(FalconVariant::Falcon1024);
        let (sk, pk) = engine.generate_key().unwrap();

        assert_eq!(sk.expose_secret().len(), FALCON1024_PRIVKEY_SIZE);
        assert_eq!(pk.len(), FALCON1024_PUBKEY_SIZE);
    }

    #[test]
    fn test_falcon512_sign_verify() {
        let engine = FalconEngine::new(FalconVariant::Falcon512);
        let (sk, pk) = engine.generate_key().unwrap();

        let data = b"test message";
        let sig = engine.sign(sk.expose_secret(), data).unwrap();

        assert!(engine.verify(&pk, data, &sig).unwrap());
        assert!(!engine.verify(&pk, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_falcon1024_sign_verify() {
        let engine = FalconEngine::new(FalconVariant::Falcon1024);
        let (sk, pk) = engine.generate_key().unwrap();

        let data = b"test message";
        let sig = engine.sign(sk.expose_secret(), data).unwrap();

        assert!(engine.verify(&pk, data, &sig).unwrap());
        assert!(!engine.verify(&pk, b"wrong message", &sig).unwrap());
    }
}
