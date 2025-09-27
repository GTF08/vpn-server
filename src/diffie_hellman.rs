use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};


pub fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}