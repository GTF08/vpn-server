use aead::{AeadCore, OsRng, AeadInPlace};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

use crate::messages::constants::ENCRYPTED_PACKET_HEADER_SIZE;

pub trait Encryptable {
    type EncryptedType;
    const PKT_TYPE: u8;

    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut;
    
    fn encrypt(mut self, cipher: &ChaCha20Poly1305) -> Result<Self::EncryptedType, aead::Error>
        where Self: Into<Self::EncryptedType>

    {
        let buffer = self.get_buffer_mut();
        buffer[0] = Self::PKT_TYPE;

        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
        buffer[1..13].copy_from_slice(&nonce);
        
        let mut plaintext = buffer.split_off(ENCRYPTED_PACKET_HEADER_SIZE);
        //Buffer will be resized by itself!!!
        let encrypt_result = cipher.encrypt_in_place(
            &Nonce::from_slice(&nonce), 
            &[], 
            &mut plaintext
        );

        buffer.unsplit(plaintext);
        encrypt_result?;

        Ok(self.into())
    }
}

pub trait Decryptable {
    type DecryptedType;

    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut;

    fn decrypt(mut self, cipher: &ChaCha20Poly1305) -> Result<Self::DecryptedType, aead::Error>
        where Self: Into<Self::DecryptedType>
    {
        let buffer = self.get_buffer_mut();

        let mut ciphertext = buffer.split_off(ENCRYPTED_PACKET_HEADER_SIZE);

        let decrypt_result = cipher.decrypt_in_place(
            &Nonce::from_slice(&buffer[1..13]), 
            &[], 
            &mut ciphertext
        );
        
        buffer.unsplit(ciphertext);
        decrypt_result?;

        return Ok(self.into());
    }
}