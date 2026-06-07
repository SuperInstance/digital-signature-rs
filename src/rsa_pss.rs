//! Simplified RSA-PSS style signature scheme.
//!
//! Uses textbook RSA with a simple PSS-like padding scheme.
//!
//! **WARNING**: This is a simplified educational implementation. Real RSA-PSS
//! uses proper padding (MGF1), proper key generation, and much larger keys.

use crate::keygen::{simple_hash, mod_exp};

/// RSA public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    /// Modulus n = p * q.
    pub n: u64,
    /// Public exponent e.
    pub e: u64,
}

/// RSA private key.
#[derive(Debug, Clone)]
pub struct RsaPrivateKey {
    /// Modulus n = p * q.
    pub n: u64,
    /// Private exponent d.
    pub d: u64,
}

/// RSA key pair.
#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    /// Public key.
    pub public: RsaPublicKey,
    /// Private key.
    pub private: RsaPrivateKey,
    /// First prime factor.
    pub p: u64,
    /// Second prime factor.
    pub q: u64,
}

impl RsaKeyPair {
    /// Generate an RSA key pair from two primes and a public exponent.
    ///
    /// The primes p and q should be distinct. The public exponent e must be
    /// coprime to (p-1)(q-1).
    pub fn generate(p: u64, q: u64, e: u64) -> Option<Self> {
        let n = p * q;
        let phi = (p - 1) * (q - 1);

        // Ensure e and phi are coprime
        if gcd(e, phi) != 1 {
            return None;
        }

        let d = mod_inverse(e, phi)?;

        Some(Self {
            public: RsaPublicKey { n, e },
            private: RsaPrivateKey { n, d },
            p,
            q,
        })
    }

    /// Small demo key pair.
    pub fn demo() -> Self {
        // p=61, q=53, e=17
        Self::generate(61, 53, 17).expect("demo key generation failed")
    }
}

/// An RSA-PSS style signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsaSignature {
    /// The signature value (padded hash signed with private key).
    pub value: u64,
}

/// RSA-PSS style signer.
#[derive(Debug, Clone)]
pub struct RsaPssSigner;

impl RsaPssSigner {
    /// Create a new signer.
    pub fn new() -> Self {
        Self
    }

    /// PSS-style encode: hash the message and add simple padding.
    fn pss_encode(message: &[u8], n: u64) -> u64 {
        let h = simple_hash(message);
        // Simple padding: XOR hash with a salt derived from n
        let salt = simple_hash(&n.to_be_bytes());
        (h ^ salt) % n
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8], keypair: &RsaKeyPair) -> RsaSignature {
        let encoded = Self::pss_encode(message, keypair.public.n);
        let sig = mod_exp(encoded, keypair.private.d, keypair.public.n);
        RsaSignature { value: sig }
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], sig: &RsaSignature, pk: &RsaPublicKey) -> bool {
        // Decrypt signature with public key
        let decrypted = mod_exp(sig.value, pk.e, pk.n);
        // Re-encode message and compare
        let expected = Self::pss_encode(message, pk.n);
        decrypted == expected
    }
}

impl Default for RsaPssSigner {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute GCD of two numbers.
fn gcd(a: u64, b: u64) -> u64 {
    let mut a = a;
    let mut b = b;
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Modular inverse using extended Euclidean algorithm.
fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let mut old_r = a as i128;
    let mut r = m as i128;
    let mut old_s = 1i128;
    let mut s = 0i128;

    while r != 0 {
        let q = old_r / r;
        let temp_r = r;
        r = old_r - q * r;
        old_r = temp_r;
        let temp_s = s;
        s = old_s - q * s;
        old_s = temp_s;
    }

    if old_r != 1 {
        return None;
    }

    let result = ((old_s % m as i128) + m as i128) as u64 % m;
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_valid() {
        let kp = RsaKeyPair::demo();
        let signer = RsaPssSigner::new();

        let sig = signer.sign(b"hello world", &kp);
        assert!(signer.verify(b"hello world", &sig, &kp.public));
    }

    #[test]
    fn tampered_message_fails() {
        let kp = RsaKeyPair::demo();
        let signer = RsaPssSigner::new();

        let sig = signer.sign(b"original", &kp);
        assert!(!signer.verify(b"modified", &sig, &kp.public));
    }

    #[test]
    fn wrong_key_fails() {
        let kp1 = RsaKeyPair::demo();
        let kp2 = RsaKeyPair::generate(59, 47, 17).unwrap();
        let signer = RsaPssSigner::new();

        let sig = signer.sign(b"msg", &kp1);
        assert!(!signer.verify(b"msg", &sig, &kp2.public));
    }

    #[test]
    fn different_keys_different_sigs() {
        let kp1 = RsaKeyPair::demo();
        let kp2 = RsaKeyPair::generate(59, 47, 17).unwrap();
        let signer = RsaPssSigner::new();

        let sig1 = signer.sign(b"same", &kp1);
        let sig2 = signer.sign(b"same", &kp2);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn demo_key_pair() {
        let kp = RsaKeyPair::demo();
        assert_eq!(kp.public.n, 61 * 53);
        assert_eq!(kp.public.e, 17);
        assert!(kp.private.d > 0);
    }

    #[test]
    fn key_pair_non_coprime_fails() {
        // e=2 and phi=(11-1)*(7-1)=60, gcd(2,60)=2 != 1
        let result = RsaKeyPair::generate(11, 7, 2);
        assert!(result.is_none());
    }

    #[test]
    fn gcd_basic() {
        assert_eq!(gcd(12, 8), 4);
        assert_eq!(gcd(17, 13), 1);
    }

    #[test]
    fn mod_inverse_basic() {
        let inv = mod_inverse(17, 60).unwrap();
        assert_eq!((17 * inv) % 60, 1);
    }

    #[test]
    fn sign_verify_multiple_messages() {
        let kp = RsaKeyPair::demo();
        let signer = RsaPssSigner::new();

        let msgs: &[&[u8]] = &[b"msg1", b"msg2", b"a longer test message"];
        for msg in msgs {
            let sig = signer.sign(msg, &kp);
            assert!(signer.verify(msg, &sig, &kp.public));
        }
    }

    #[test]
    fn signature_deterministic() {
        let kp = RsaKeyPair::demo();
        let signer = RsaPssSigner::new();

        let sig1 = signer.sign(b"same message", &kp);
        let sig2 = signer.sign(b"same message", &kp);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn rsa_encryption_decryption() {
        let kp = RsaKeyPair::demo();
        let msg = 42u64;
        let encrypted = mod_exp(msg, kp.public.e, kp.public.n);
        let decrypted = mod_exp(encrypted, kp.private.d, kp.public.n);
        assert_eq!(decrypted, msg);
    }
}
