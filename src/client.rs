use std::{net::SocketAddr};

use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305, Nonce};
use rand::rngs::OsRng;
use tokio::time::Instant;

use crate::messages::EncryptedMessage;



pub struct VPNClient {
    pub client_nonce: u128,
    pub server_nonce: u128,
    pub public_ip: SocketAddr,
    pub authorized: bool,
    pub cipher: ChaCha20Poly1305,
    pub lastseen: Instant
    // Other client-specific data
}


impl VPNClient {
    pub fn encrypt_packet(self: &Self, bytes: &[u8]) -> Result<EncryptedMessage, Box<dyn std::error::Error + Send + Sync>> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, bytes)
            .map_err(|e| format!("{e}")).unwrap();
        let encrypted_pkt = EncryptedMessage {
            ciphertext,
            nonce: nonce.to_vec(),
        };
        Ok(encrypted_pkt)
    }

    pub fn decrypt_packet(self: &Self, encrypted_msg: &EncryptedMessage) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let decrypted = self.cipher.decrypt(&Nonce::from_slice(&encrypted_msg.nonce), &encrypted_msg.ciphertext[..])
            .map_err(|e| format!("{e}")).unwrap();
        Ok(decrypted)
    }
}