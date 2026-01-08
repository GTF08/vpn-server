use x25519_dalek::PublicKey;

use crate::{bufferpool::BufferHandle, messages::constants::{PKT_HANDSHAKE_NONCE_RANGE, PKT_HANDSHAKE_PUBKEY_RANGE, PKT_HANDSHAKE_SIZE, PKT_TYPE_HANDSHAKE}};

pub struct HandshakePacket(BufferHandle);

impl HandshakePacket {
    pub fn new(
        mut buffer_handle: BufferHandle,
        public: PublicKey, 
        client_nonce: u128
    ) -> Self {

        buffer_handle.data_mut().resize(PKT_HANDSHAKE_SIZE, 0);
        buffer_handle.data_mut()[0] = PKT_TYPE_HANDSHAKE;
        buffer_handle.data_mut()[PKT_HANDSHAKE_PUBKEY_RANGE].copy_from_slice(&public.to_bytes());
        buffer_handle.data_mut()[PKT_HANDSHAKE_NONCE_RANGE].copy_from_slice(&client_nonce.to_be_bytes());
        Self(buffer_handle)
    }

    pub fn from_recieved(
        buffer_handle: BufferHandle
    ) -> Self {
        Self(buffer_handle)
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.0.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.0.data_mut()
    }

    pub fn is_valid_type(&self) -> bool {
        self.0.data()[0] == PKT_TYPE_HANDSHAKE
    }

    pub fn get_key_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_HANDSHAKE_PUBKEY_RANGE]
    }

    pub fn get_client_nonce_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_HANDSHAKE_NONCE_RANGE]
    }

    pub const fn size(&self) -> usize {
        PKT_HANDSHAKE_SIZE
    }

    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_HANDSHAKE_SIZE
    }

    pub fn clear_release(mut self) -> BufferHandle {
        self.0.data_mut().clear();
        self.0
    }
}