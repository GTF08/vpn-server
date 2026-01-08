use ed25519_dalek::Signature;
use x25519_dalek::PublicKey;

use crate::{bufferpool::BufferHandle, messages::constants::{PKT_HANDSHAKE_RESP_NONCE_RANGE, PKT_HANDSHAKE_RESP_PUBKEY_RANGE, PKT_HANDSHAKE_RESP_SIGNATURE_RANGE, PKT_HANDSHAKE_RESP_SIZE, PKT_TYPE_HANDSHAKE_RESP}};

pub struct HandshakeResponsePacket(BufferHandle);

impl HandshakeResponsePacket {
    pub fn new(
        mut buffer_handle: BufferHandle,
        pubkey: PublicKey,
        server_nonce: u128,
        signature: Signature
    ) -> Self {
        buffer_handle.data_mut().resize(PKT_HANDSHAKE_RESP_SIZE, 0);
        buffer_handle.data_mut()[0] = PKT_TYPE_HANDSHAKE_RESP;
        buffer_handle.data_mut()[PKT_HANDSHAKE_RESP_PUBKEY_RANGE].copy_from_slice(pubkey.as_bytes());
        buffer_handle.data_mut()[PKT_HANDSHAKE_RESP_NONCE_RANGE].copy_from_slice(&server_nonce.to_be_bytes());
        buffer_handle.data_mut()[PKT_HANDSHAKE_RESP_SIGNATURE_RANGE].copy_from_slice(&signature.to_bytes());
        

        Self(buffer_handle)
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.0.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.0.data_mut()
    }

    pub fn is_valid_type(&self) -> bool {
        self.0.data()[0] == PKT_TYPE_HANDSHAKE_RESP
    }

    pub fn get_key_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_HANDSHAKE_RESP_PUBKEY_RANGE]
    }

    pub fn get_server_nonce(&self) -> &[u8] {
        &self.0.data()[PKT_HANDSHAKE_RESP_NONCE_RANGE]
    }

    pub fn get_signature_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_HANDSHAKE_RESP_SIGNATURE_RANGE]
    }

    pub const fn size(&self) -> usize {
        PKT_HANDSHAKE_RESP_SIZE
    }

    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_HANDSHAKE_RESP_SIZE
    }

    pub fn clear_release(mut self) -> BufferHandle {
        self.0.data_mut().clear();
        self.0
    }
}