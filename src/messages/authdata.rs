use bytes::BytesMut;

use crate::{
    messages::{constants::{CHACHA_ENCRYPTION_OVERHEAD_SIZE, PKT_AUTH_CLIENT_NONCE_SIZE, PKT_AUTH_NO_USERNAME_SIZE, PKT_AUTH_PASSWORD_HASH_SIZE, PKT_AUTH_SERVER_NONCE_SIZE, PKT_AUTH_USERNAME_LEN_RANGE, PKT_AUTH_USERNAME_START, PKT_TYPE_AUTH}, 
    traits::{Decryptable, Encryptable}}
};



pub struct AuthPacket;

impl AuthPacket  {
    pub fn new(
        mut buffer: BytesMut,
        username: &[u8], 
        password_hash: &[u8], 
        client_nonce_bytes: &[u8], 
        server_nonce_bytes: &[u8]
    ) -> BytesMut {
        let username_len = username.len() as u8;
        
        buffer.resize(PKT_AUTH_CLIENT_NONCE_SIZE + username_len as usize, 0);

        buffer[0] = PKT_TYPE_AUTH;
        buffer[PKT_AUTH_USERNAME_LEN_RANGE] = username_len;
        
        let mut range = Self::username_range(username_len);
        buffer[range].copy_from_slice(username);
        
        range = Self::password_range(username_len);
        buffer[range].copy_from_slice(password_hash);
        
        range = Self::client_nonce_range(username_len);
        buffer[range].copy_from_slice(&client_nonce_bytes);
        
        range = Self::server_nonce_range(username_len);
        buffer[range].copy_from_slice(&server_nonce_bytes);

        buffer
    }

    // fn new_from_encryted(buffer_handle: BufferHandle) -> Self {
    //     Self {
    //         buffer_handle
    //     }
    // }

    // pub fn data(&self) -> &bytes::BytesMut {
    //     self.buffer_handle.data()
    // }

    // pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
    //     self.buffer_handle.data_mut()
    // }

    // pub fn is_valid_type(&self) -> bool {
    //     self.buffer_handle.data()[0] == PKT_TYPE_AUTH
    // }

    fn username_range(username_len: u8) -> std::ops::Range<usize> {
        PKT_AUTH_USERNAME_START..PKT_AUTH_USERNAME_START + username_len as usize
    }

    fn password_range(username_len: u8) -> std::ops::Range<usize> {
        let start = PKT_AUTH_USERNAME_START + username_len as usize;
        start..start + PKT_AUTH_PASSWORD_HASH_SIZE
    }

    fn client_nonce_range(username_len: u8) -> std::ops::Range<usize> {
        let start = PKT_AUTH_USERNAME_START + username_len as usize + PKT_AUTH_PASSWORD_HASH_SIZE;
        start..start + PKT_AUTH_CLIENT_NONCE_SIZE
    }
    
    fn server_nonce_range(username_len: u8) -> std::ops::Range<usize> {
        let start: usize = PKT_AUTH_USERNAME_START + username_len as usize + 
            PKT_AUTH_PASSWORD_HASH_SIZE + PKT_AUTH_CLIENT_NONCE_SIZE;
        start..start + PKT_AUTH_SERVER_NONCE_SIZE
    }

    pub fn get_username_bytes(buffer_handle: &BytesMut) -> &[u8] {
        let username_len = buffer_handle[PKT_AUTH_USERNAME_LEN_RANGE];
        &buffer_handle[Self::username_range(username_len)]
    }

    pub fn get_password_bytes(buffer_handle: &BytesMut) -> &[u8] {
        let username_len = buffer_handle[PKT_AUTH_USERNAME_LEN_RANGE];
        &buffer_handle[Self::password_range(username_len)]
    }

    pub fn get_client_nonce_bytes(buffer_handle: &BytesMut) -> &[u8] {
        let username_len = buffer_handle[PKT_AUTH_USERNAME_LEN_RANGE];
        &buffer_handle[Self::client_nonce_range(username_len)]
    }

    pub fn get_server_nonce_bytes(buffer_handle: &BytesMut) -> &[u8] {
        let username_len = buffer_handle[PKT_AUTH_USERNAME_LEN_RANGE];
        &buffer_handle[Self::server_nonce_range(username_len)]
    }

    // pub fn clear_release(mut self) -> BufferHandle {
    //     self.buffer_handle.data_mut().clear();
    //     self.buffer_handle
    // }

}


pub struct AuthPacketEncrypted;

impl AuthPacketEncrypted {

    // pub fn data(&self) -> &bytes::BytesMut {
    //     self.buffer_handle.data()
    // }

    // pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
    //     self.buffer_handle.data_mut()
    // }

    // pub fn clear_release(mut self) -> BufferHandle {
    //     self.buffer_handle.data_mut().clear();
    //     self.buffer_handle
    // }

    pub fn is_valid_buffer_size(buffer: &BytesMut) -> bool {
        buffer.len() > PKT_AUTH_NO_USERNAME_SIZE + CHACHA_ENCRYPTION_OVERHEAD_SIZE
    }
}

impl Encryptable for AuthPacket {
    const PKT_TYPE: u8 = PKT_TYPE_AUTH;
}

impl Decryptable for AuthPacketEncrypted {

}