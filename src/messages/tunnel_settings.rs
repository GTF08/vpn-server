use bytes::BytesMut;

use crate::{bufferpool::BatchHandle, messages::{constants::{CHACHA_ENCRYPTION_OVERHEAD_SIZE, PKT_TUNNEL_SETTINGS_GATEWAY_RANGE, PKT_TUNNEL_SETTINGS_IP_RANGE, PKT_TUNNEL_SETTINGS_NETMASK_RANGE, PKT_TUNNEL_SETTINGS_SIZE, PKT_TYPE_TUNNEL_SETTINGS}, traits::{Decryptable, Encryptable}}};

pub struct TunnelSettingsPacket;

impl TunnelSettingsPacket {
    pub fn new(
        buffer_handle: &mut BytesMut,
        tun_ip: u32,
        tun_netmask: u32,
        tun_gateway: u32
    ) {
        //unsafe {buffer_handle.set_len(PKT_TUNNEL_SETTINGS_SIZE)};
        buffer_handle.resize(PKT_TUNNEL_SETTINGS_SIZE, 0);
        buffer_handle[0] = PKT_TYPE_TUNNEL_SETTINGS;
        buffer_handle[PKT_TUNNEL_SETTINGS_IP_RANGE].copy_from_slice(&tun_ip.to_be_bytes());
        buffer_handle[PKT_TUNNEL_SETTINGS_NETMASK_RANGE].copy_from_slice(&tun_netmask.to_be_bytes());
        buffer_handle[PKT_TUNNEL_SETTINGS_GATEWAY_RANGE].copy_from_slice(&tun_gateway.to_be_bytes());
    }

    // pub fn data(&self) -> &bytes::BytesMut {
    //     self.0.data()
    // }

    // pub fn data_mut(&mut self) -> &mut bytes::BytesMut {
    //     self.0.data_mut()
    // }

    // pub fn is_valid_type(&self) -> bool {
    //     self.0.data()[0] == PKT_TYPE_TUNNEL_SETTINGS
    // }

    pub fn get_ip_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_TUNNEL_SETTINGS_IP_RANGE]
    }

    pub fn get_netmask_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_TUNNEL_SETTINGS_NETMASK_RANGE]
    }

    pub fn get_gateway_bytes(buffer_handle: &BytesMut) -> &[u8] {
        &buffer_handle[PKT_TUNNEL_SETTINGS_GATEWAY_RANGE]
    }

    // pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
    //     buffer_size == PKT_TUNNEL_SETTINGS_SIZE
    // }
}

const PKT_TUNNEL_SETTINGS_ENCRYPTED_SIZE: usize = PKT_TUNNEL_SETTINGS_SIZE + CHACHA_ENCRYPTION_OVERHEAD_SIZE;
pub struct TunnelSettingsPacketEncrypted;

impl TunnelSettingsPacketEncrypted {
    pub fn is_valid_buffer_size(buffer_size: usize) -> bool {
        buffer_size == PKT_TUNNEL_SETTINGS_ENCRYPTED_SIZE
    }
}

impl Encryptable for TunnelSettingsPacket {
    const PKT_TYPE: u8 = PKT_TYPE_TUNNEL_SETTINGS;
}

impl Decryptable for TunnelSettingsPacketEncrypted {}