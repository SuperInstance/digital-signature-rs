//! Signature verification utilities.

use crate::keygen::simple_hash;

/// Verify that a message has not been tampered with by comparing hashes.
pub fn verify_hash(message: &[u8], expected_hash: u64) -> bool {
    simple_hash(message) == expected_hash
}

/// Compute a message hash.
pub fn message_hash(message: &[u8]) -> u64 {
    simple_hash(message)
}

/// Verify a hash-based commitment.
pub fn verify_commitment(message: &[u8], nonce: u64, commitment: u64) -> bool {
    let mut data = Vec::with_capacity(message.len() + 8);
    data.extend_from_slice(message);
    data.extend_from_slice(&nonce.to_be_bytes());
    simple_hash(&data) == commitment
}

/// Create a hash-based commitment.
pub fn create_commitment(message: &[u8], nonce: u64) -> u64 {
    let mut data = Vec::with_capacity(message.len() + 8);
    data.extend_from_slice(message);
    data.extend_from_slice(&nonce.to_be_bytes());
    simple_hash(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_hash_correct() {
        let msg = b"hello";
        let h = message_hash(msg);
        assert!(verify_hash(msg, h));
    }

    #[test]
    fn verify_hash_tampered() {
        let h = message_hash(b"hello");
        assert!(!verify_hash(b"world", h));
    }

    #[test]
    fn commitment_round_trip() {
        let msg = b"secret message";
        let nonce = 12345u64;
        let commitment = create_commitment(msg, nonce);
        assert!(verify_commitment(msg, nonce, commitment));
    }

    #[test]
    fn commitment_wrong_nonce() {
        let msg = b"secret message";
        let commitment = create_commitment(msg, 12345);
        assert!(!verify_commitment(msg, 99999, commitment));
    }

    #[test]
    fn commitment_wrong_message() {
        let commitment = create_commitment(b"original", 12345);
        assert!(!verify_commitment(b"modified", 12345, commitment));
    }

    #[test]
    fn different_messages_different_hashes() {
        let h1 = message_hash(b"foo");
        let h2 = message_hash(b"bar");
        assert_ne!(h1, h2);
    }
}
