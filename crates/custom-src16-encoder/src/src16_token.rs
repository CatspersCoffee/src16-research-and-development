use sha3::{Digest, Keccak256};

#[derive(Debug, Clone)]
pub enum Token {
    Uint([u8; 32]),         // For 256-bit numbers
    FixedBytes(Vec<u8>),    // For fixed-size byte arrays
    Address([u8; 32]),      // For Fuel 32-byte addresses
    String(String),         // For strings that need to be hashed
}

pub fn encode(tokens: &[Token]) -> Vec<u8> {
    let mut result = Vec::new();
    
    for token in tokens {
        match token {
            Token::Uint(val) => {
                result.extend_from_slice(val);
            },
            Token::FixedBytes(bytes) => {
                let mut padded = [0u8; 32];
                if bytes.len() <= 32 {
                    padded[..bytes.len()].copy_from_slice(bytes);
                }
                result.extend_from_slice(&padded);
            },
            Token::Address(addr) => {
                // Fuel addresses are already 32 bytes, so no padding needed
                result.extend_from_slice(addr);
            },
            Token::String(s) => {
                let hash = keccak256(s.as_bytes());
                result.extend_from_slice(&hash);
            }
        }
    }
    
    result
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

// convert a big-endian number to Token::Uint
pub fn number_to_token(num: u64) -> Token {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&num.to_be_bytes());
    Token::Uint(bytes)
}

// convert bytes to Token::FixedBytes
pub fn bytes_to_token(bytes: Vec<u8>) -> Token {
    Token::FixedBytes(bytes)
}

// create Token::Address for 32-Byte Fuel address
pub fn address_to_token(addr: [u8; 32]) -> Token {
    Token::Address(addr)
}