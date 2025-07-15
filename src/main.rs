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
    let priv_a = EphemeralSecret::random();
    let pub_a = PublicKey::from(&priv_a);

    let priv_b = EphemeralSecret::random();
    let pub_b = PublicKey::from(&priv_b);

    // M
    let msg = b"Hello world";
    let some_hash = Sha256::digest(b"even_any");

    // encrypt
    let shared_a = priv_a.diffie_hellman(&pub_b);
    let key_a = hkdf_derive(shared_a.as_bytes(), &some_hash);
    let cipher_a = ChaCha20Poly1305::new(&key_a.into());
    let nonce_w = [0u8; 12];
    let nonce = Nonce::from_slice(&nonce_w);
    let cipher_text = cipher_a
        .encrypt(Nonce::from_slice(&nonce), msg as &[u8])
        .unwrap();

    // decrypt
    let shared_b = priv_b.diffie_hellman(&pub_a);
    let key_b = hkdf_derive(shared_b.as_bytes(), &some_hash);
    let cipher_b = ChaCha20Poly1305::new(&key_b.into());

    let plain = cipher_b.decrypt(nonce, cipher_text.as_ref()).unwrap();

    let plain_text = String::from_utf8(plain).unwrap();

    // try decrypt with A
    let plain_a = cipher_a.decrypt(nonce, cipher_text.as_ref()).unwrap();
    let plain_a_text = String::from_utf8(plain_a).unwrap();

    // print
    println!("A - {:?}; B - {:?}", key_a, key_b);
    println!("{}", plain_text);
    println!("Plain_a: {}", plain_a_text);

    assert_eq!(msg, plain_text.as_bytes(), "DEPKE failed!");
    assert_eq!(
        msg,
        plain_a_text.as_bytes(),
        "DEPKE (bidirectional) failed!"
    );
}
