//! Key generation utilities.
//!
//! Provides simple hash functions and key derivation for the signature schemes.

/// A simple deterministic hash function (FNV-1a inspired).
///
/// **NOT cryptographically secure** — for educational use only.
pub fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

/// Hash a u64 value into another u64.
pub fn hash_u64(value: u64) -> u64 {
    simple_hash(&value.to_be_bytes())
}

/// Hash two u64 values together.
pub fn hash_pair(a: u64, b: u64) -> u64 {
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&a.to_be_bytes());
    data.extend_from_slice(&b.to_be_bytes());
    simple_hash(&data)
}

/// Hash a message (bytes) with a u64 nonce.
pub fn hash_message_nonce(message: &[u8], nonce: u64) -> u64 {
    let mut data = Vec::with_capacity(message.len() + 8);
    data.extend_from_slice(message);
    data.extend_from_slice(&nonce.to_be_bytes());
    simple_hash(&data)
}

/// Simple modular exponentiation (shared across modules).
pub fn mod_exp(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }
    let mut result: u128 = 1;
    let mut base: u128 = (base as u128) % (modulus as u128);
    let modulus = modulus as u128;
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }

    result as u64
}

/// Simple primality test.
pub fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n.is_multiple_of(2) || n.is_multiple_of(3) {
        return false;
    }
    let mut i = 5u64;
    while i * i <= n {
        if n.is_multiple_of(i) || n.is_multiple_of(i + 2) {
            return false;
        }
        i += 6;
    }
    true
}

/// Generate a deterministic random-looking u64 from a seed.
pub fn derive_u64(seed: u64, context: u64) -> u64 {
    hash_pair(seed, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_hash_deterministic() {
        let h1 = simple_hash(b"hello");
        let h2 = simple_hash(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn simple_hash_different_inputs() {
        let h1 = simple_hash(b"hello");
        let h2 = simple_hash(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_u64_deterministic() {
        assert_eq!(hash_u64(42), hash_u64(42));
    }

    #[test]
    fn hash_pair_order_matters() {
        let h1 = hash_pair(1, 2);
        let h2 = hash_pair(2, 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash_message_nonce_different() {
        let h1 = hash_message_nonce(b"test", 0);
        let h2 = hash_message_nonce(b"test", 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn mod_exp_simple() {
        assert_eq!(mod_exp(2, 10, 1000), 24);
    }

    #[test]
    fn mod_exp_fermat() {
        assert_eq!(mod_exp(3, 10, 11), 1);
    }

    #[test]
    fn is_prime_basic() {
        assert!(is_prime(2));
        assert!(is_prime(3));
        assert!(is_prime(5));
        assert!(is_prime(7));
        assert!(!is_prime(4));
        assert!(!is_prime(9));
    }

    #[test]
    fn derive_u64_different_contexts() {
        let a = derive_u64(42, 1);
        let b = derive_u64(42, 2);
        assert_ne!(a, b);
    }

    #[test]
    fn mod_exp_identity() {
        assert_eq!(mod_exp(5, 0, 7), 1);
    }

    #[test]
    fn mod_exp_base_zero() {
        assert_eq!(mod_exp(0, 5, 7), 0);
    }
}
