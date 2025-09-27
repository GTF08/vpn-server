
use bincode::{Decode, Encode};
use chacha20poly1305::{aead::Aead, AeadCore, ChaCha20Poly1305};
use rand::rngs::OsRng;

#[derive(Encode, Decode, Debug)]
pub enum PacketType {
    Handshake(DHKeyPacket),
    HandshakeResponse(DHKeyResponsePacket),
    AuthPacket(EncryptedMessage),
    TunnelSettings(EncryptedMessage),
    EncryptedPkt(EncryptedMessage)
}


#[derive(Encode, Decode, Debug)]
pub struct DHKeyPacket {
    pub pub_key: Vec<u8>,
    pub nonce: u128
}

#[derive(Encode, Decode, Debug)]
pub struct DHKeyResponsePacket {
    pub pub_key: Vec<u8>,
    pub nonce: u128,
    pub signature: Vec<u8>
}

#[derive(Encode, Decode, Debug)]
pub struct AuthData {
    pub username: String,
    pub password: String,
    pub client_nonce: u128,
    pub server_nonce: u128
}

#[derive(Encode, Decode, Debug)]
pub struct TunnelSettingsPkt {
    pub ip_string: String,
    pub netmask_string: String,
    pub gateway_string: String,
}


#[derive(Encode, Decode, Debug)]
pub struct EncryptedMessage {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>
}



pub trait CryptoSupported
where Self: Sized + Encode + Decode<()> {
    fn encrypt(self, cipher: &ChaCha20Poly1305) -> Result<EncryptedMessage, String> {
        let bytes = 
            bincode::encode_to_vec(self, bincode::config::standard())
            .map_err(|e| format!("{e}"))?;
        let nonce = ChaCha20Poly1305::generate_nonce(OsRng);
        let ciphertext = cipher.encrypt(&nonce, bytes.as_slice())
            .map_err(|e| format!("{e}"))?;
        Ok(EncryptedMessage { ciphertext: ciphertext, nonce: nonce.to_vec() })
    }

    fn decrypt(encrypted: &EncryptedMessage, cipher: &ChaCha20Poly1305) -> Result<Self, String> {
        let nonce = encrypted.nonce.as_slice().into();
        let bytes = cipher.decrypt(nonce, encrypted.ciphertext.as_slice())
            .map_err(|e| format!("{e}"))?;
        let decoded = bincode::decode_from_slice(&bytes, bincode::config::standard())
            .map_err(|e| format!("{e}"))?;
        return Ok(decoded.0)
    }
}

impl CryptoSupported for AuthData {}
impl CryptoSupported for TunnelSettingsPkt {}