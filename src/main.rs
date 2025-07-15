// DEPKE PoC in Rust

use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::x25519::{PublicKey, StaticSecret};

const NONCE_LEN: usize = 12;

fn derive_shared_key(priv_key: &StaticSecret, pub_key: &PublicKey, msg_hash: &[u8]) -> Key {
    let shared_secret = priv_key.diffie_hellman(pub_key);
    let hk = Hkdf::<Sha256>::new(Some(msg_hash), shared_secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"depke key", &mut okm).unwrap();
    *Key::from_slice(&okm)
}

fn encrypt(
    priv_a: &StaticSecret,
    pub_b: &PublicKey,
    message: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Vec<u8> {
    let msg_hash = Sha256::digest(message);
    let key = derive_shared_key(priv_a, pub_b, &msg_hash);
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .encrypt(Nonce::from_slice(nonce), message)
        .expect("encryption failure")
}

fn decrypt(
    priv_b: &StaticSecret,
    pub_a: &PublicKey,
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LEN],
    msg_hash: &[u8],
) -> Vec<u8> {
    let key = derive_shared_key(priv_b, pub_a, msg_hash);
    let cipher = ChaCha20Poly1305::new(&key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .expect("decryption failure")
}

fn main() {
    // Key generation
    let priv_a = StaticSecret::new(&mut OsRng);
    let pub_a = PublicKey::from(&priv_a);
    let priv_b = StaticSecret::new(&mut OsRng);
    let pub_b = PublicKey::from(&priv_b);

    let message = b"double-edged encryption";
    let nonce = [0u8; NONCE_LEN]; // For demo only; use random in real applications

    // Encrypt with A's private key and B's public key
    let ciphertext = encrypt(&priv_a, &pub_b, message, &nonce);

    // Compute message hash for B to derive same key
    let msg_hash = Sha256::digest(message);

    // Decrypt with B's private key and A's public key
    let decrypted = decrypt(&priv_b, &pub_a, &ciphertext, &nonce, &msg_hash);

    assert_eq!(message.to_vec(), decrypted);
    println!(
        "Decryption successful: {}",
        String::from_utf8(decrypted).unwrap()
    );
}
