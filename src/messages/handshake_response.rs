use bytes::BytesMut;
use ed25519_dalek::Signature;
use x25519_dalek::PublicKey;

use crate::{bufferpool::BatchHandle, messages::constants::{PKT_HANDSHAKE_RESP_NONCE_RANGE, PKT_HANDSHAKE_RESP_PUBKEY_RANGE, PKT_HANDSHAKE_RESP_SIGNATURE_RANGE, PKT_HANDSHAKE_RESP_SIZE, PKT_TYPE_HANDSHAKE_RESP}};

pub struct HandshakeResponsePacket;

impl HandshakeResponsePacket {
    pub fn new(
        buffer_handle: &mut BytesMut,
        pubkey: PublicKey,
        server_nonce: u128,
        signature: Signature
    ) {
        buffer_handle.resize(PKT_HANDSHAKE_RESP_SIZE, 0);
        //unsafe {buffer_handle.set_len(PKT_HANDSHAKE_RESP_SIZE)};
        buffer_handle[0] = PKT_TYPE_HANDSHAKE_RESP;
        buffer_handle[PKT_HANDSHAKE_RESP_PUBKEY_RANGE].copy_from_slice(pubkey.as_bytes());
        buffer_handle[PKT_HANDSHAKE_RESP_NONCE_RANGE].copy_from_slice(&server_nonce.to_be_bytes());
        buffer_handle[PKT_HANDSHAKE_RESP_SIGNATURE_RANGE].copy_from_slice(&signature.to_bytes());
    }

    // pub fn data(&self) -> &bytes::BytesMut {
    //     self.0.data()
    // }

    // pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
    //     self.0.data_mut()
    // }

    // pub fn is_valid_type(&self) -> bool {
    //     self.0.data()[0] == PKT_TYPE_HANDSHAKE_RESP
    // }

    pub fn get_key_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_HANDSHAKE_RESP_PUBKEY_RANGE]
    }

    pub fn get_server_nonce(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_HANDSHAKE_RESP_NONCE_RANGE]
    }

    pub fn get_signature_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_HANDSHAKE_RESP_SIGNATURE_RANGE]
    }

    pub const fn size(&self) -> usize {
        PKT_HANDSHAKE_RESP_SIZE
    }

    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_HANDSHAKE_RESP_SIZE
    }

    // pub fn clear_release(mut self) -> PoolHandle {
    //     self.0.data_mut().clear();
    //     self.0
    // }
}