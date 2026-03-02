use bytes::BytesMut;

use crate::{messages::{constants::{ENCRYPTED_PACKET_HEADER_SIZE, PKT_TYPE_ENCRYPTED_PKT}, decrypted::DecryptedPacket, traits::Decryptable}};

pub struct EncryptedPacket;

impl EncryptedPacket {
    pub fn is_valid_buffer_size(buffer: &BytesMut) -> bool {
        buffer.len() > ENCRYPTED_PACKET_HEADER_SIZE
    }
}

impl Decryptable for EncryptedPacket {}