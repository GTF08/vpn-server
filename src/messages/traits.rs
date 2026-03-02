use aead::{AeadCore, OsRng, AeadInPlace};
use bytes::BytesMut;
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::{messages::constants::ENCRYPTED_PACKET_HEADER_SIZE};

pub trait Encryptable {
    const PKT_TYPE: u8;

    fn encrypt_in_place(buffer: &mut BytesMut, cipher: &ChaCha20Poly1305) -> Result<(), aead::Error>
    {
        //let buffer = self.get_buffer_mut();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        let mut plaintext = buffer.split_off(ENCRYPTED_PACKET_HEADER_SIZE);
        //Buffer will be resized by itself!!!
        let encrypt_result = cipher.encrypt_in_place(
            &Nonce::from_slice(&nonce), 
            &[], 
            &mut plaintext
        );

        buffer.unsplit(plaintext);

        if encrypt_result.is_ok() {
            buffer[0] = Self::PKT_TYPE;
            buffer[1..13].copy_from_slice(&nonce);
        }

        encrypt_result
    }
}

pub trait Decryptable {
    fn decrypt_in_place(buffer: &mut BytesMut, cipher: &ChaCha20Poly1305) -> Result<(), aead::Error>
    {
        let mut ciphertext = buffer.split_off(ENCRYPTED_PACKET_HEADER_SIZE);

        let decrypt_result = cipher.decrypt_in_place(
            &Nonce::from_slice(&buffer[1..13]), 
            &[], 
            &mut ciphertext
        );
        
        buffer.unsplit(ciphertext);
        decrypt_result
    }
}