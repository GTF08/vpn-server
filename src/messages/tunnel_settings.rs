use crate::{bufferpool::BufferHandle, messages::{constants::{CHACHA_ENCRYPTION_OVERHEAD_SIZE, PKT_TUNNEL_SETTINGS_GATEWAY_RANGE, PKT_TUNNEL_SETTINGS_IP_RANGE, PKT_TUNNEL_SETTINGS_NETMASK_RANGE, PKT_TUNNEL_SETTINGS_SIZE, PKT_TYPE_TUNNEL_SETTINGS}, traits::{Decryptable, Encryptable}}};

pub struct TunnelSettingsPacket(BufferHandle);

impl TunnelSettingsPacket {
    pub fn new(
        mut buffer_handle: BufferHandle,
        tun_ip: u32,
        tun_netmask: u32,
        tun_gateway: u32
    ) -> Self {
        buffer_handle.data_mut().resize(PKT_TUNNEL_SETTINGS_SIZE, 0);
        buffer_handle.data_mut()[0] = PKT_TYPE_TUNNEL_SETTINGS;
        buffer_handle.data_mut()[PKT_TUNNEL_SETTINGS_IP_RANGE].copy_from_slice(&tun_ip.to_be_bytes());
        buffer_handle.data_mut()[PKT_TUNNEL_SETTINGS_NETMASK_RANGE].copy_from_slice(&tun_netmask.to_be_bytes());
        buffer_handle.data_mut()[PKT_TUNNEL_SETTINGS_GATEWAY_RANGE].copy_from_slice(&tun_gateway.to_be_bytes());

        Self(buffer_handle)
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.0.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.0.data_mut()
    }

    pub fn is_valid_type(&self) -> bool {
        self.0.data()[0] == PKT_TYPE_TUNNEL_SETTINGS
    }

    pub fn get_ip_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_TUNNEL_SETTINGS_IP_RANGE]
    }

    pub fn get_netmask_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_TUNNEL_SETTINGS_NETMASK_RANGE]
    }

    pub fn get_gateway_bytes(&self) -> &[u8] {
        &self.0.data()[PKT_TUNNEL_SETTINGS_GATEWAY_RANGE]
    }

    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_TUNNEL_SETTINGS_SIZE
    }
}

const PKT_TUNNEL_SETTINGS_ENCRYPTED_SIZE: usize = PKT_TUNNEL_SETTINGS_SIZE + CHACHA_ENCRYPTION_OVERHEAD_SIZE;
pub struct TunnelSettingsPacketEncrypted(BufferHandle);

impl TunnelSettingsPacketEncrypted {
    pub fn new(buffer_handle: BufferHandle) -> Self {
        Self(buffer_handle)
    }

    pub fn data(&self) -> &bytes::BytesMut {
        self.0.data()
    }

    pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
        self.0.data_mut()
    }

    pub fn is_valid_type(&self) -> bool {
        self.0.data()[0] == PKT_TYPE_TUNNEL_SETTINGS
    }

    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_TUNNEL_SETTINGS_ENCRYPTED_SIZE
    }
}


impl Encryptable for TunnelSettingsPacket {
    type EncryptedType = TunnelSettingsPacketEncrypted;
    const PKT_TYPE: u8 = PKT_TYPE_TUNNEL_SETTINGS;


    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut {
        self.0.data_mut()
    }
}

impl Decryptable for TunnelSettingsPacketEncrypted {
    type DecryptedType = TunnelSettingsPacket;
    
    fn get_buffer_mut(&mut self) -> &mut bytes::BytesMut {
        self.0.data_mut()
    }

}

impl Into<TunnelSettingsPacket> for TunnelSettingsPacketEncrypted {
    fn into(self) -> TunnelSettingsPacket {
        TunnelSettingsPacket(self.0)
    }
}

impl From<TunnelSettingsPacket> for TunnelSettingsPacketEncrypted {
    fn from(value: TunnelSettingsPacket) -> Self {
        Self::new(value.0)
    }
}