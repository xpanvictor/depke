// DEPKE PoC in Rust
// Author: xpanvictor

use chacha20poly1305::{
    aead::{Aead, OsRng},
    ChaCha20Poly1305, ChaChaPoly1305, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

fn hkdf_derive(shared_secret: &[u8], context: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(context), shared_secret);
    let mut okm = [0u8; 32];
    hkdf.expand(b"depke", &mut okm).expect("HKDF expand failed");
    okm
}

fn main() {
    let privA = EphemeralSecret::random();
    let pubA = PublicKey::from(&privA);

    let privB = EphemeralSecret::random();
    let pubB = PublicKey::from(&privB);

    // M
    let msg = b"Hello world";
    let some_hash = Sha256::digest(b"even_any");

    // encrypt
    let shared_a = privA.diffie_hellman(&pubB);
    let key_a = hkdf_derive(shared_a.as_bytes(), &some_hash);
    let cipher = ChaCha20Poly1305::new(&key_a.into());
    let nonce = [0u8; 12];
    let cipher_text = cipher
        .encrypt(Nonce::from_slice(&nonce), msg as &[u8])
        .unwrap();

    // decrypt
    let shared_b = privB.diffie_hellman(&pubA);
    let key_b = hkdf_derive(shared_b.as_bytes(), &some_hash);

    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), cipher_text.as_ref())
        .unwrap();

    let plain_text = String::from_utf8(plain).unwrap();

    // print
    println!("A - {:?}; B - {:?}", key_a, key_b);
    println!("{}", plain_text);

    assert_eq!(msg, plain_text.as_bytes(), "DEPKE failed!");
}
