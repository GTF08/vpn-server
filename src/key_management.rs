use ed25519_dalek::{SignatureError, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::fs::File;
use std::io::{Write, Read};

/// Generate and save a new Ed25519 keypair to files
pub fn generate_and_save_keys(
    private_key_path: &str,
    public_key_path: &str,
) -> Result<(), Box<dyn std::error::Error + Sync + Send>> {
    // Generate a new keypair
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    // Save private key
    let mut priv_file = File::create(private_key_path)?;
    priv_file.write_all(&signing_key.to_bytes())?;
    
    // Save public key
    let mut pub_file = File::create(public_key_path)?;
    pub_file.write_all(&verifying_key.to_bytes())?;
    
    println!("Keys generated and saved successfully:");
    
    Ok(())
}

pub fn load_signing_key(path: &str) -> Result<SigningKey, Box<dyn std::error::Error + Sync + Send>> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 32]; // Ed25519 private keys are 32 bytes
    file.read_exact(&mut bytes)?;
    
    let signing_key = SigningKey::from_bytes(&bytes);
    
    Ok(signing_key)
}


pub fn load_verifying_key(path: &str) -> Result<VerifyingKey, Box<dyn std::error::Error + Sync + Send>> {
    let mut file = File::open(path)?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)?;
    
    let verifying_key = VerifyingKey::from_bytes(&bytes)
        .map_err(|e: SignatureError| format!("Invalid public key: {}", e))?;
    
    Ok(verifying_key)
}