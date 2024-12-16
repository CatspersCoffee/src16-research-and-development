use serde::{Deserialize, Deserializer, Serialize, Serializer};
use fuels::types::Bits256;

pub fn serialize<S>(bits: &Bits256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex = format!("0x{}", hex::encode(bits.0));
    hex.serialize(serializer)
}

pub fn deserialize<'de, D>(deserializer: D) -> Result<Bits256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = String::deserialize(deserializer)?;
    let s = s.trim_start_matches("0x");
    
    let bytes = hex::decode(s)
        .map_err(serde::de::Error::custom)?;
        
    if bytes.len() != 32 {
        return Err(serde::de::Error::custom(
            "Bits256 must be exactly 32 bytes"
        ));
    }
    
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Bits256(arr))
}