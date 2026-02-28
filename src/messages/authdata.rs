use crate::{
    bufferpool::BufferHandle, 
    messages::{constants::{CHACHA_ENCRYPTION_OVERHEAD_SIZE, PKT_AUTH_CLIENT_NONCE_SIZE, PKT_AUTH_NO_USERNAME_SIZE, PKT_AUTH_PASSWORD_HASH_SIZE, PKT_AUTH_SERVER_NONCE_SIZE, PKT_AUTH_USERNAME_LEN_RANGE, PKT_AUTH_USERNAME_START, PKT_TYPE_AUTH}, 
    traits::{Decryptable, Encryptable}}
};



pub struct AuthPacket {
    buffer_handle: BufferHandle
}

impl AuthPacket  {
    pub fn new(
        mut buffer: BufferHandle,
        username: &[u8], 
        password_hash: &[u8], 
        client_nonce_bytes: &[u8], 
        server_nonce_bytes: &[u8]
    ) -> Self {
        let username_len = username.len() as u8;
        
        buffer.data_mut().resize(PKT_AUTH_CLIENT_NONCE_SIZE + username_len as usize, 0);

        buffer.data_mut()[0] = PKT_TYPE_AUTH;
        buffer.data_mut()[PKT_AUTH_USERNAME_LEN_RANGE] = username_len;
        log::debug!("username: {:?}", username);
        
        let mut range = Self::username_range(username_len);
        buffer.data_mut()[range].copy_from_slice(username);
        log::debug!("password: {:?}", password_hash);
        
        range = Self::password_range(username_len);
        buffer.data_mut()[range].copy_from_slice(password_hash);
        log::debug!("cnonce: {:?}", client_nonce_bytes);
        
        range = Self::client_nonce_range(username_len);
        buffer.data_mut()[range].copy_from_slice(&client_nonce_bytes);
        log::debug!("snonce: {:?}", server_nonce_bytes);
        
        range = Self::server_nonce_range(username_len);
        buffer.data_mut()[range].copy_from_slice(&server_nonce_bytes);

        
        Self { buffer_handle: buffer} 
    }

    fn new_from_encryted(buffer_handle: BufferHandle) -> Self {
        Self {
            buffer_handle
        }
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.buffer_handle.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }

    pub fn is_valid_type(&self) -> bool {
        self.buffer_handle.data()[0] == PKT_TYPE_AUTH
    }

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

    pub fn get_username_bytes(&self) -> &[u8] {
        let username_len = self.data()[PKT_AUTH_USERNAME_LEN_RANGE];
        &self.buffer_handle.data()[Self::username_range(username_len)]
    }

    pub fn get_password_bytes(&self) -> &[u8] {
        let username_len = self.data()[PKT_AUTH_USERNAME_LEN_RANGE];
        &self.buffer_handle.data()[Self::password_range(username_len)]
    }

    pub fn get_client_nonce_bytes(&self) -> &[u8] {
        let username_len = self.data()[PKT_AUTH_USERNAME_LEN_RANGE];
        &self.buffer_handle.data()[Self::client_nonce_range(username_len)]
    }

    pub fn get_server_nonce_bytes(&self) -> &[u8] {
        let username_len = self.data()[PKT_AUTH_USERNAME_LEN_RANGE];
        &self.buffer_handle.data()[Self::server_nonce_range(username_len)]
    }

    pub fn clear_release(mut self) -> BufferHandle {
        self.buffer_handle.data_mut().clear();
        self.buffer_handle
    }

}


pub struct AuthPacketEncrypted{
    buffer_handle: BufferHandle,
}

impl AuthPacketEncrypted {
    pub fn new(buffer_handle: BufferHandle) -> Self {
        Self{
            buffer_handle,
        }
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.buffer_handle.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }

    pub fn clear_release(mut self) -> BufferHandle {
        self.buffer_handle.data_mut().clear();
        self.buffer_handle
    }

    pub fn is_valid_buffer_size(buffer: &BufferHandle) -> bool {
        buffer.data().len() > PKT_AUTH_NO_USERNAME_SIZE + CHACHA_ENCRYPTION_OVERHEAD_SIZE
    }
}

impl Encryptable for AuthPacket {
    type EncryptedType = AuthPacketEncrypted;
    const PKT_TYPE: u8 = PKT_TYPE_AUTH;
    
    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }
}

impl Decryptable for AuthPacketEncrypted {
    type DecryptedType = AuthPacket;
    
    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut {
        self.buffer_handle.data_mut()
    }

}

impl Into<AuthPacketEncrypted> for AuthPacket {
    fn into(self) -> AuthPacketEncrypted {
        AuthPacketEncrypted::new(self.buffer_handle)
    }
}

impl From<AuthPacketEncrypted> for AuthPacket {
    fn from(value: AuthPacketEncrypted) -> Self {
        AuthPacket::new_from_encryted(value.buffer_handle)
    }
}