//! Schnorr signature scheme.
//!
//! Provably secure in the random oracle model under the discrete logarithm assumption.
//!
//! **WARNING**: Educational implementation only.

use crate::keygen::{hash_pair, mod_exp};

/// Schnorr parameters (group parameters).
#[derive(Debug, Clone)]
pub struct SchnorrParams {
    /// Prime modulus p.
    pub p: u64,
    /// Generator g.
    pub g: u64,
    /// Subgroup order q (p-1 for simplicity).
    pub q: u64,
}

impl SchnorrParams {
    /// Demo parameters (p=23, g=5).
    pub fn demo() -> Self {
        Self {
            p: 23,
            g: 5,
            q: 22,
        }
    }

    /// Medium parameters.
    pub fn medium() -> Self {
        Self {
            p: 100003,
            g: 2,
            q: 100002,
        }
    }
}

/// Schnorr public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrPublicKey {
    /// y = g^x mod p.
    pub y: u64,
}

/// Schnorr private key.
#[derive(Debug, Clone)]
pub struct SchnorrPrivateKey {
    /// Secret exponent x.
    pub x: u64,
}

/// Schnorr key pair.
#[derive(Debug, Clone)]
pub struct SchnorrKeyPair {
    /// Public key.
    pub public: SchnorrPublicKey,
    /// Private key.
    pub private: SchnorrPrivateKey,
}

impl SchnorrKeyPair {
    /// Generate a key pair from seed.
    pub fn generate(params: &SchnorrParams, seed: u64) -> Self {
        let x = (seed % (params.q - 2)) + 1;
        let y = mod_exp(params.g, x, params.p);
        Self {
            public: SchnorrPublicKey { y },
            private: SchnorrPrivateKey { x },
        }
    }
}

/// A Schnorr signature (e, s).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrSignature {
    /// Challenge e = H(g^k, message).
    pub e: u64,
    /// Response s = k - x*e mod q.
    pub s: u64,
}

/// Schnorr signer/verifier.
#[derive(Debug, Clone)]
pub struct SchnorrSigner {
    params: SchnorrParams,
}

impl SchnorrSigner {
    /// Create a new signer with the given parameters.
    pub fn new(params: &SchnorrParams) -> Self {
        Self {
            params: params.clone(),
        }
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8], keypair: &SchnorrKeyPair) -> SchnorrSignature {
        let p = self.params.p;
        let g = self.params.g;
        let q = self.params.q;

        // Deterministic k from message and private key
        let msg_hash = crate::keygen::simple_hash(message);
        let k = (hash_pair(msg_hash, keypair.private.x) % (q - 2)) + 1;

        // r = g^k mod p
        let r = mod_exp(g, k, p);

        // e = H(r, message) mod q
        let msg_u64 = crate::keygen::simple_hash(message);
        let e = hash_pair(r, msg_u64) % q;

        // s = (k - x*e) mod q
        let xe = (keypair.private.x * e) % q;
        let s = (k + q - xe) % q;

        SchnorrSignature { e, s }
    }

    /// Verify a signature.
    pub fn verify(
        &self,
        message: &[u8],
        sig: &SchnorrSignature,
        pk: &SchnorrPublicKey,
    ) -> bool {
        let p = self.params.p;
        let g = self.params.g;
        let q = self.params.q;

        // Recompute r_v = g^s * y^e mod p
        let gs = mod_exp(g, sig.s, p);
        let ye = mod_exp(pk.y, sig.e, p);
        let r_v = (gs * ye) % p;

        // Recompute e_v = H(r_v, message) mod q
        let msg_u64 = crate::keygen::simple_hash(message);
        let e_v = hash_pair(r_v, msg_u64) % q;

        sig.e == e_v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_valid() {
        let params = SchnorrParams::demo();
        let kp = SchnorrKeyPair::generate(&params, 42);
        let signer = SchnorrSigner::new(&params);

        let sig = signer.sign(b"hello", &kp);
        assert!(signer.verify(b"hello", &sig, &kp.public));
    }

    #[test]
    fn tampered_message_fails() {
        let params = SchnorrParams::demo();
        let kp = SchnorrKeyPair::generate(&params, 42);
        let signer = SchnorrSigner::new(&params);

        let sig = signer.sign(b"original", &kp);
        assert!(!signer.verify(b"tampered", &sig, &kp.public));
    }

    #[test]
    fn wrong_key_fails() {
        let params = SchnorrParams::demo();
        let kp1 = SchnorrKeyPair::generate(&params, 1);
        let kp2 = SchnorrKeyPair::generate(&params, 2);
        let signer = SchnorrSigner::new(&params);

        let sig = signer.sign(b"msg", &kp1);
        assert!(!signer.verify(b"msg", &sig, &kp2.public));
    }

    #[test]
    fn different_keys_different_sigs() {
        let params = SchnorrParams::demo();
        let kp1 = SchnorrKeyPair::generate(&params, 1);
        let kp2 = SchnorrKeyPair::generate(&params, 2);
        let signer = SchnorrSigner::new(&params);

        let sig1 = signer.sign(b"same", &kp1);
        let sig2 = signer.sign(b"same", &kp2);
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn keypair_generation() {
        let params = SchnorrParams::demo();
        let kp = SchnorrKeyPair::generate(&params, 42);
        assert!(kp.private.x > 0);
        assert!(kp.public.y > 0);
        assert!(kp.public.y < params.p);
    }

    #[test]
    fn keypair_consistency() {
        let params = SchnorrParams::demo();
        let kp = SchnorrKeyPair::generate(&params, 7);
        let expected_y = mod_exp(params.g, kp.private.x, params.p);
        assert_eq!(kp.public.y, expected_y);
    }

    #[test]
    fn medium_params_sign_verify() {
        let params = SchnorrParams::medium();
        let kp = SchnorrKeyPair::generate(&params, 12345);
        let signer = SchnorrSigner::new(&params);

        let sig = signer.sign(b"medium test", &kp);
        assert!(signer.verify(b"medium test", &sig, &kp.public));
    }

    #[test]
    fn multiple_messages() {
        let params = SchnorrParams::demo();
        let kp = SchnorrKeyPair::generate(&params, 42);
        let signer = SchnorrSigner::new(&params);

        let msgs: &[&[u8]] = &[b"a", b"b", b"c", b"longer message here"];
        for msg in msgs {
            let sig = signer.sign(msg, &kp);
            assert!(signer.verify(msg, &sig, &kp.public));
        }
    }

    #[test]
    fn same_message_same_sig() {
        let params = SchnorrParams::demo();
        let kp = SchnorrKeyPair::generate(&params, 42);
        let signer = SchnorrSigner::new(&params);

        let sig1 = signer.sign(b"deterministic", &kp);
        let sig2 = signer.sign(b"deterministic", &kp);
        assert_eq!(sig1, sig2);
    }
}
