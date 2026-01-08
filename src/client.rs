use std::{net::SocketAddr};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::time::Instant;


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
    // pub fn form_encrypted_buffer_for_socket(self: &Self, buffer_handle: &mut BufferHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     // let mut tun_pkt_nonce_slice = buffer_handle.data_mut().split_off(1);
    //     // let mut tun_pkt_plaintext_slice = tun_pkt_nonce_slice.split_off(12);

    //     let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        
    //     buffer_handle.data_mut()[0] = PKT_TYPE_ENCRYPTED_PKT;
    //     buffer_handle.data_mut()[1..13].copy_from_slice(&nonce);

    //     let mut plaintext = buffer_handle.data_mut().split_off(ENCRYPTED_PACKET_HEADER_SIZE);

    //     let encrypt_result = self.cipher.encrypt_in_place(&nonce, &[], &mut plaintext);
        
    //     buffer_handle.data_mut().unsplit(plaintext);

    //     match encrypt_result {
    //         Ok(()) => {
    //             return Ok(())
    //         },
    //         Err(e) => {
    //             error!("Failed to encrypt packet: {}", e);
    //             return Err(format!("Failed to encrypt packet: {}", e).into());
    //         }
    //     }
    // }

    // pub fn form_decrypted_buffer_for_tun(self: &Self, buffer_handle: &mut BufferHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     //let mut nonce = buffer_handle.data_mut().split_off(1);
    //     //let mut ciphertext = nonce.split_off(12);

    //     let mut ciphertext = buffer_handle.data_mut().split_off(ENCRYPTED_PACKET_HEADER_SIZE);

    //     let decrypt_result = self.cipher.decrypt_in_place(&Nonce::from_slice(&buffer_handle.data()[1..13]), &[], &mut ciphertext);
        
    //     buffer_handle.data_mut().unsplit(ciphertext);

    //     //VIRTIO HEADER
    //     buffer_handle.data_mut()[ENCRYPTED_PACKET_HEADER_SIZE - VIRTIO_NET_HDR_LEN .. ENCRYPTED_PACKET_HEADER_SIZE]
    //         .copy_from_slice(&[0u8; 10]);

    //     match decrypt_result {
    //         Ok(()) => {
    //             return Ok(())
    //         },
    //         Err(e) => {
    //             error!("Failed to decrypt packet: {}", e);
    //             return Err(format!("Failed to decrypt packet: {}", e).into());
    //         }
    //     }
    // }

    // pub fn encrypt_buffer(self: &Self, buffer_handle: &mut BufferHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     let mut plaintext = buffer_handle.data_mut().split_off(ENCRYPTED_PACKET_HEADER_SIZE);

    //     let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    //     buffer_handle.data_mut()[1..13].copy_from_slice(&nonce);

    //     let encrypt_result = self.cipher.encrypt_in_place(&nonce, &[], &mut plaintext);
        
    //     buffer_handle.data_mut().unsplit(plaintext);
        
    //     match encrypt_result {
    //         Ok(()) => {
    //             return Ok(())
    //         },
    //         Err(e) => {
    //             error!("Failed to decrypt packet: {}", e);
    //             return Err(format!("Failed to decrypt packet: {}", e).into());
    //         }
    //     }
    // }

    // pub fn decrypt_buffer(self: &Self, buffer_handle: &mut BufferHandle) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    //     let mut ciphertext = buffer_handle.data_mut().split_off(ENCRYPTED_PACKET_HEADER_SIZE);

    //     let decrypt_result = self.cipher.decrypt_in_place(&Nonce::from_slice(&buffer_handle.data()[1..13]), &[], &mut ciphertext);
        
    //     buffer_handle.data_mut().unsplit(ciphertext);

    //     match decrypt_result {
    //         Ok(()) => {
    //             return Ok(())
    //         },
    //         Err(e) => {
    //             error!("Failed to decrypt packet: {}", e);
    //             return Err(format!("Failed to decrypt packet: {}", e).into());
    //         }
    //     }
    // }
}