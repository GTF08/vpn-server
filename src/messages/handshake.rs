use bytes::BytesMut;
use x25519_dalek::PublicKey;

use crate::{messages::constants::{PKT_HANDSHAKE_NONCE_RANGE, PKT_HANDSHAKE_PUBKEY_RANGE, PKT_HANDSHAKE_SIZE, PKT_TYPE_HANDSHAKE}};

pub struct HandshakePacket;

impl HandshakePacket {
    pub fn new(
        mut buffer_handle: BytesMut,
        public: PublicKey, 
        client_nonce: u128
    ) -> BytesMut {

        buffer_handle.resize(PKT_HANDSHAKE_SIZE, 0);
        buffer_handle[0] = PKT_TYPE_HANDSHAKE;
        buffer_handle[PKT_HANDSHAKE_PUBKEY_RANGE].copy_from_slice(&public.to_bytes());
        buffer_handle[PKT_HANDSHAKE_NONCE_RANGE].copy_from_slice(&client_nonce.to_be_bytes());
        
        buffer_handle
    }

   
    pub fn get_key_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_HANDSHAKE_PUBKEY_RANGE]
    }

    pub fn get_client_nonce_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_HANDSHAKE_NONCE_RANGE]
    }

    pub const fn size(&self) -> usize {
        PKT_HANDSHAKE_SIZE
    }

    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_HANDSHAKE_SIZE
    }

    // pub fn clear_release(mut self) -> BufferHandle {
    //     self.0.data_mut().clear();
    //     self.0
    // }
}