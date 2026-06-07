//! ElGamal signature scheme.
//!
//! Based on the difficulty of the discrete logarithm problem in Z*_p.
//!
//! **WARNING**: Educational implementation only.

use crate::keygen::{hash_message_nonce, mod_exp, simple_hash};

/// ElGamal public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalPublicKey {
    /// Prime modulus p.
    pub p: u64,
    /// Generator g.
    pub g: u64,
    /// Public value y = g^x mod p.
    pub y: u64,
}

/// ElGamal private key.
#[derive(Debug, Clone)]
pub struct ElGamalPrivateKey {
    /// Prime modulus p.
    pub p: u64,
    /// Generator g.
    pub g: u64,
    /// Private exponent x.
    pub x: u64,
}

/// An ElGamal signature (r, s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElGamalSignature {
    /// r = g^k mod p.
    pub r: u64,
    /// s such that h(m) = x*r + k*s mod (p-1).
    pub s: u64,
}

/// ElGamal key pair.
#[derive(Debug, Clone)]
pub struct ElGamalKeyPair {
    /// The public key.
    pub public: ElGamalPublicKey,
    /// The private key.
    pub private: ElGamalPrivateKey,
}

impl ElGamalKeyPair {
    /// Generate a key pair from parameters and a seed.
    ///
    /// - `p`: prime modulus
    /// - `g`: generator
    /// - `seed`: seed for private key derivation
    pub fn generate(p: u64, g: u64, seed: u64) -> Self {
        // Private key: 1 < x < p-1
        let x = (seed % (p - 3)) + 2;
        let y = mod_exp(g, x, p);

        Self {
            public: ElGamalPublicKey { p, g, y },
            private: ElGamalPrivateKey { p, g, x },
        }
    }
}

/// ElGamal signer.
#[derive(Debug, Clone)]
pub struct ElGamalSigner {
    p: u64,
    g: u64,
}

impl ElGamalSigner {
    /// Create a new signer with the given parameters.
    pub fn new(p: u64, g: u64) -> Self {
        Self { p, g }
    }

    /// Sign a message.
    ///
    /// Uses a deterministic k derived from the message hash and private key.
    /// Retries with incremented k until a valid inverse is found.
    pub fn sign(&self, message: &[u8], keypair: &ElGamalKeyPair) -> ElGamalSignature {
        let p = self.p;
        let p1 = p - 1;

        // Deterministic k: hash of message and private key
        let h = simple_hash(message);
        let base_k = hash_message_nonce(message, keypair.private.x);

        // Find a k that is coprime with p-1
        let mut k = (base_k % (p1 - 2)) + 2;
        let k_inv = loop {
            if let Some(inv) = mod_inverse(k, p1) {
                break inv;
            }
            k = (k % (p1 - 2)) + 2;
            if k == (base_k % (p1 - 2)) + 2 {
                k = (k + 1) % (p1 - 2) + 2;
            }
        };

        let r = mod_exp(self.g, k, p);

        // s = (h - x*r) * k^(-1) mod (p-1)
        let xr = (keypair.private.x * r) % p1;
        let h_mod = h % p1;
        let diff = (h_mod + p1 - xr) % p1;

        let s = (diff * k_inv) % p1;

        ElGamalSignature { r, s }
    }

    /// Verify a signature.
    pub fn verify(&self, message: &[u8], sig: &ElGamalSignature, pk: &ElGamalPublicKey) -> bool {
        let p = self.p;
        let p1 = p - 1;

        if sig.r == 0 || sig.r >= p || sig.s >= p1 {
            return false;
        }

        let h = simple_hash(message) % p1;

        // Verify: g^h ≡ y^r * r^s (mod p)
        let lhs = mod_exp(self.g, h, p);
        let yr = mod_exp(pk.y, sig.r, p);
        let rs = mod_exp(sig.r, sig.s, p);
        let rhs = (yr * rs) % p;

        lhs == rhs
    }
}

/// Compute modular inverse using extended Euclidean algorithm.
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

    fn test_params() -> (u64, u64) {
        (23, 5) // p=23, g=5
    }

    #[test]
    fn sign_verify_valid() {
        let (p, g) = test_params();
        let signer = ElGamalSigner::new(p, g);
        let kp = ElGamalKeyPair::generate(p, g, 42);

        let msg = b"test message";
        let sig = signer.sign(msg, &kp);
        assert!(signer.verify(msg, &sig, &kp.public));
    }

    #[test]
    fn tampered_message_fails() {
        let (p, g) = test_params();
        let signer = ElGamalSigner::new(p, g);
        let kp = ElGamalKeyPair::generate(p, g, 42);

        let sig = signer.sign(b"original", &kp);
        assert!(!signer.verify(b"tampered", &sig, &kp.public));
    }

    #[test]
    fn different_keys_different_sigs() {
        let (p, g) = test_params();
        let signer = ElGamalSigner::new(p, g);
        let kp1 = ElGamalKeyPair::generate(p, g, 1);
        let kp2 = ElGamalKeyPair::generate(p, g, 2);

        let msg = b"same message";
        let sig1 = signer.sign(msg, &kp1);
        let sig2 = signer.sign(msg, &kp2);

        assert_ne!(sig1.r, sig2.r);
    }

    #[test]
    fn wrong_key_fails() {
        let (p, g) = test_params();
        let signer = ElGamalSigner::new(p, g);
        let kp1 = ElGamalKeyPair::generate(p, g, 1);
        let kp2 = ElGamalKeyPair::generate(p, g, 2);

        let sig = signer.sign(b"msg", &kp1);
        assert!(!signer.verify(b"msg", &sig, &kp2.public));
    }

    #[test]
    fn keypair_generation() {
        let kp = ElGamalKeyPair::generate(23, 5, 42);
        assert!(kp.private.x > 1);
        assert!(kp.private.x < 22);
        assert!(kp.public.y > 0);
        assert!(kp.public.y < 23);
    }

    #[test]
    fn public_key_consistency() {
        let kp = ElGamalKeyPair::generate(23, 5, 7);
        let expected_y = mod_exp(5, kp.private.x, 23);
        assert_eq!(kp.public.y, expected_y);
    }

    #[test]
    fn mod_inverse_basic() {
        let inv = mod_inverse(3, 11).unwrap();
        assert_eq!((3 * inv) % 11, 1);
    }

    #[test]
    fn sign_verify_multiple_messages() {
        let (p, g) = test_params();
        let signer = ElGamalSigner::new(p, g);
        let kp = ElGamalKeyPair::generate(p, g, 42);

        let msgs: &[&[u8]] = &[b"msg1", b"msg2", b"msg3", b"another"];
        for msg in msgs {
            let sig = signer.sign(msg, &kp);
            assert!(signer.verify(msg, &sig, &kp.public), "failed for {:?}", msg);
        }
    }
}
