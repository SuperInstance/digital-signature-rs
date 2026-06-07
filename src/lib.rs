//! # digital-signature-rs
//!
//! Pure-Rust implementations of digital signature schemes with no external dependencies.
//!
//! **WARNING**: These are educational/reference implementations. Use well-audited
//! libraries like `ed25519-dalek` or `ring` for production cryptography.
//!
//! ## Schemes
//!
//! - **ElGamal Signature** — based on discrete logarithm problem
//! - **Schnorr Signature** — provably secure in the random oracle model
//! - **RSA-PSS Style** — simplified RSA-based signature with padding
//!
//! ## Quick Start
//!
//! ```
//! use digital_signature_rs::schnorr::{SchnorrKeyPair, SchnorrSigner, SchnorrParams};
//! use digital_signature_rs::keygen::simple_hash;
//!
//! let params = SchnorrParams::demo();
//! let kp = SchnorrKeyPair::generate(&params, 42);
//! let signer = SchnorrSigner::new(&params);
//!
//! let message = b"hello world";
//! let signature = signer.sign(message, &kp);
//! assert!(signer.verify(message, &signature, &kp.public));
//! ```

pub mod elgamal;
pub mod keygen;
pub mod rsa_pss;
pub mod schnorr;
pub mod verify;
