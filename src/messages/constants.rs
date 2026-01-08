//
pub const ENCRYPTED_PACKET_HEADER_SIZE: usize = 13;
pub(super) const CHACHA_ENCRYPTION_OVERHEAD_SIZE: usize = 16;

//
pub const PKT_TYPE_HANDSHAKE: u8 = 0x01;

pub(super) const PKT_HANDSHAKE_PUBKEY_RANGE: std::ops::Range<usize> = 1..33;
pub(super) const PKT_HANDSHAKE_NONCE_RANGE: std::ops::Range<usize> = 33..49;
pub(super) const PKT_HANDSHAKE_SIZE: usize = 49;


//
pub const PKT_TYPE_HANDSHAKE_RESP: u8 = 0x02;
pub(super) const PKT_HANDSHAKE_RESP_PUBKEY_RANGE: std::ops::Range<usize> = 1..33;
pub(super) const PKT_HANDSHAKE_RESP_NONCE_RANGE: std::ops::Range<usize> = 33..49;
pub(super) const PKT_HANDSHAKE_RESP_SIGNATURE_RANGE: std::ops::Range<usize> = 49..49 + 64;
pub(super) const PKT_HANDSHAKE_RESP_SIZE: usize = 49 + 64;

//

pub const PKT_TYPE_AUTH: u8 = 0x03;
pub(super) const PKT_AUTH_USERNAME_LEN_RANGE: usize = ENCRYPTED_PACKET_HEADER_SIZE + 1;
pub(super) const PKT_AUTH_USERNAME_START: usize = ENCRYPTED_PACKET_HEADER_SIZE + 2;
pub(super) const PKT_AUTH_PASSWORD_HASH_SIZE: usize = 64;
pub(super) const PKT_AUTH_CLIENT_NONCE_SIZE: usize = 16;
pub(super) const PKT_AUTH_SERVER_NONCE_SIZE: usize = 16;
pub(super) const PKT_AUTH_NO_USERNAME_SIZE: usize = 
    ENCRYPTED_PACKET_HEADER_SIZE +
    1 + 
    //username?
    PKT_AUTH_PASSWORD_HASH_SIZE +
    PKT_AUTH_CLIENT_NONCE_SIZE +
    PKT_AUTH_SERVER_NONCE_SIZE +
    CHACHA_ENCRYPTION_OVERHEAD_SIZE;

//
pub const PKT_TYPE_TUNNEL_SETTINGS: u8 = 0x04;
pub(super) const PKT_TUNNEL_SETTINGS_NONCE_RANGE: std::ops::Range<usize> = 1..13;
pub(super) const PKT_TUNNEL_SETTINGS_CIPHERTEXT_RANGE: std::ops::RangeFrom<usize> = 13..;
pub(super) const PKT_TUNNEL_SETTINGS_IP_RANGE: std::ops::Range<usize> = 13..17;
pub(super) const PKT_TUNNEL_SETTINGS_NETMASK_RANGE: std::ops::Range<usize> = 17..21;
pub(super) const PKT_TUNNEL_SETTINGS_GATEWAY_RANGE: std::ops::Range<usize> = 21..25;
pub(super) const PKT_TUNNEL_SETTINGS_SIZE: usize = 25;

//

pub const PKT_TYPE_ENCRYPTED_PKT: u8 = 0x05;