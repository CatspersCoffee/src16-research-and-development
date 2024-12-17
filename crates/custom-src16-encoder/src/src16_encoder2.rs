use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use sha3::{Digest, Keccak256};
use fuels::types::Bytes32;

use crate::src16_v4::custom04_src16::SRC16Domain;


#[derive(Debug, Clone, PartialEq)]
pub enum ParamType {
    Address,    // For 32-byte Fuel addresses
    Bytes32,    // For fixed 32-byte values
    Uint(usize),    // Single uint type that handles all sizes (8, 16, 32, 64, 256)
    String,     // For string values
    Bool,
}

#[derive(Debug, Clone)]
pub enum Token {
    Address([u8; 32]),     // Holds actual address
    FixedBytes([u8; 32]),  // Holds actual bytes32
    Uint([u8; 32]),        // Holds actual uint value
    String(String),        // Holds actual string
    Bool(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypedData {
    pub domain: SRC16Domain,
    pub types: BTreeMap<String, Vec<TypeField>>,
    #[serde(rename = "primaryType")]
    pub primary_type: String,
    pub message: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeField {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
}

impl Token {
    pub fn type_check(&self, param_type: &ParamType) -> bool {
        match (self, param_type) {
            (Token::Address(_), ParamType::Address) => true,
            (Token::FixedBytes(_), ParamType::Bytes32) => true,
            (Token::Uint(_), ParamType::Uint(_)) => true,
            (Token::String(_), ParamType::String) => true,
            (Token::Bool(_), ParamType::Bool) => true,
            _ => false,
        }
    }

    // Helper function to display token values
    pub fn display(&self) -> String {
        match self {
            Token::FixedBytes(bytes) => {
                format!("FixedBytes({:?}): 0x{}", ParamType::Bytes32, hex::encode(bytes))
            },
            Token::Address(addr) => {
                format!("Address({:?}): 0x{}", ParamType::Address, hex::encode(addr))
            },
            Token::String(s) => {
                format!("String({:?}): {}", ParamType::String, s)
            },
            Token::Uint(num) => {
                format!("Uint({:?}): 0x{}", ParamType::Uint(256), hex::encode(num))
            },
            Token::Bool(b) => {
                format!("Bool({:?}): {}", ParamType::Bool, b)
            }
        }
    }
}

pub fn encode(tokens: &[Token]) -> Vec<u8> {
    let mut result = Vec::new();
    
    for token in tokens {
        match token {
            Token::Address(addr) => {
                result.extend_from_slice(addr);
            },
            Token::FixedBytes(bytes) => {
                result.extend_from_slice(bytes);
            },
            Token::Uint(val) => {
                result.extend_from_slice(val);
            },
            Token::String(s) => {
                result.extend_from_slice(&keccak256(s.as_bytes()));
            },
            Token::Bool(b) => {
                let mut padded = [0u8; 32];
                padded[31] = *b as u8;
                result.extend_from_slice(&padded);
            },
        }
    }
    
    result
}

pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(input);
    hasher.finalize().into()
}

pub fn number_to_token(num: u64) -> Token {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&num.to_be_bytes());
    Token::Uint(bytes)
}


impl TypedData {

    pub fn encode_type(&self, primary_type: &str) -> Result<String, Box<dyn std::error::Error>> {
        let mut deps = self.find_dependencies(primary_type);
        deps.sort();
        deps.insert(0, primary_type.to_string());

        let mut result = String::new();
        for dep in deps {
            if let Some(fields) = self.types.get(&dep) {
                result.push_str(&dep);
                result.push('(');
                result.push_str(
                    &fields
                        .iter()
                        .map(|f| {
                            let param_type = Self::get_param_type(&f.type_name)
                                .map_err(|e| format!("Invalid type {}: {}", f.type_name, e))
                                .unwrap_or(ParamType::String); // Fallback to string if type is unknown
                            format!("{} {}", param_type, f.name)
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                );
                result.push(')');
            }
        }
        Ok(result)
    }

    fn find_dependencies(&self, primary_type: &str) -> Vec<String> {
        let mut deps = Vec::new();
        if let Some(fields) = self.types.get(primary_type) {
            for field in fields {
                let field_type = field.type_name.split('[').next().unwrap();
                if self.types.contains_key(field_type) && field_type != primary_type {
                    deps.push(field_type.to_string());
                    deps.extend(self.find_dependencies(field_type));
                }
            }
        }
        deps
    }

    // Convert type string to ParamType
    fn get_param_type(type_str: &str) -> Result<ParamType, Box<dyn std::error::Error>> {
        match type_str {
            "address" => Ok(ParamType::Address),
            "bytes32" => Ok(ParamType::Bytes32),
            "bool" => Ok(ParamType::Bool),
            s if s.starts_with("uint") => {
                let size = s[4..].parse().unwrap_or(256);
                Ok(ParamType::Uint(size))
            },
            "string" => Ok(ParamType::String),
            _ => Err("Unsupported type".into())
        }
    }

    pub fn encode_uint(value: u64, bits: usize) -> Token {
        let mut bytes = [0u8; 32];
        match bits {
            8 => bytes[31] = value as u8,
            16 => bytes[30..32].copy_from_slice(&(value as u16).to_be_bytes()),
            32 => bytes[28..32].copy_from_slice(&(value as u32).to_be_bytes()),
            64 => bytes[24..32].copy_from_slice(&value.to_be_bytes()),
            _ => bytes[0..32].copy_from_slice(&[0u8; 32])  // uint256 case
        }
        Token::Uint(bytes)
    }

    pub fn encode_value(&self, type_str: &str, value: &serde_json::Value) 
        -> Result<Token, Box<dyn std::error::Error>> 
    {
        let param_type = Self::get_param_type(type_str)?;

        match param_type {
            ParamType::Address | ParamType::Bytes32 => {
                let hex_str = value.as_str()
                    .ok_or("Expected string")?
                    .trim_start_matches("0x");
                let bytes = hex::decode(hex_str)?;
                if bytes.len() != 32 {
                    return Err("Must be 32 bytes".into());
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);

                match param_type {
                    ParamType::Address => Ok(Token::Address(arr)),
                    ParamType::Bytes32 => Ok(Token::FixedBytes(arr)),
                    _ => unreachable!(),
                }
            },
            ParamType::Uint(_) => {
                let num: u64 = value.as_str()
                    .ok_or("Expected string")?
                    .parse()?;
                let mut bytes = [0u8; 32];
                bytes[24..32].copy_from_slice(&num.to_be_bytes());
                Ok(Token::Uint(bytes))
            },
            ParamType::String => {
                Ok(Token::String(value.as_str()
                    .ok_or("Expected string")?
                    .to_string()))
            },
            ParamType::Bool => {
                let bool_val = value.as_bool()
                    .ok_or("Expected boolean")?;
                Ok(Token::Bool(bool_val))
            },
        }
    }

    pub fn encode_data(&self, primary_type: &str, data: &serde_json::Value) 
        -> Result<Vec<Token>, Box<dyn std::error::Error>> 
    {
        let mut tokens = Vec::new();

        // Add type hash
        let type_string = self.encode_type(primary_type)?;
        let type_hash = self.hash_type(&type_string);
        tokens.push(Token::FixedBytes(type_hash));
        
        // Encode fields
        if let Some(fields) = self.types.get(primary_type) {
            for field in fields {
                if let Some(value) = data.get(&field.name) {
                    tokens.push(self.encode_value(&field.type_name, value)?);
                }
            }
        }

        Ok(tokens)
    }

    fn hash_type(&self, encoded_type: &str) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(encoded_type.as_bytes());
        hasher.finalize().into()
    }

}

impl std::fmt::Display for ParamType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParamType::Address => write!(f, "address"),
            ParamType::Bytes32 => write!(f, "bytes32"),
            ParamType::Uint(size) => write!(f, "uint{}", size),
            ParamType::String => write!(f, "string"),
            ParamType::Bool => write!(f, "bool"),
        }
    }
}