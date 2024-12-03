library;

use std::{
    bytes::Bytes,
    string::String,
    hash::*,
};
use std::bytes_conversions::{b256::*, u256::*, u64::*};
use std::primitive_conversions::{u16::*, u32::*, u64::*};



abi SRC16 {

    /// Returns the domain separator struct containing the initialized parameters
    fn domain_separator() -> SRC16Domain;

    /// Returns the Keccak256 hash of the encoded domain separator
    fn domain_separator_hash() -> b256;

    /// Return the Keccak256 hash of the encoded typed structured data.
    ///
    /// # Additional Information
    ///
    /// * `type` : [<custom_struct>] - A custom data structure used by the SRC16 validator.
    ///
    /// This is a per-contract implementation. This function should be implemented
    /// for the `type`. The DefaultEncoder can be used to encoded known data types.
    ///
    /// # Returns
    ///
    /// * [b256] - The Keccak256 hash of the encoded structured data
    ///
    fn data_struct_hash() -> b256;

    /// Returns the combined typed data hash according to SRC16 specification.
    ///
    /// # Additional Information
    ///
    /// This function produces a domain-bound hash by combining:
    /// 1. The prefix bytes (\x19\x01)
    /// 2. The domain separator hash
    /// 3. The structured data hash
    ///
    /// # Arguments
    ///
    /// * `data_hash`: [b256] - The Keccak256 hash of the encoded structured data
    ///
    /// # Returns
    ///
    /// * [Option<b256>] - The combined typed data hash, or None if encoding fails
    ///
    fn encode(data_hash: b256) -> Option<b256>;

}

/// Contains the core parameters that uniquely identify a domain for typed
/// data signing.
pub struct SRC16Domain {
    /// The name of the signing domain
    name: String,
    /// The current major version of the signing domain
    version: String,
    /// The active chain ID where the signing is intended to be used.
    chain_id: u64,
    /// The address of the contract that will verify the signature
    verifying_contract: b256,
}

/// The type hash constant for the domain separator
///
/// # Additional Information
///
/// This is the Keccak256 hash of "SRC16Domain(string name,string version,uint64 chainId,address verifyingContract)"
pub const SRC16_DOMAIN_TYPE_HASH: b256 = 0xae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd;


impl SRC16Domain {

    /// Creates a new SRC16Domain instance with the provided parameters
    ///
    /// # Arguments
    ///
    /// * `domain_name`: [String] - The name of the signing domain
    /// * `version`: [String] - The version of the signing domain
    /// * `chain_id`: [u64] - The chain ID where the contract is deployed
    /// * `verifying_contract`: [b256] - The address of the contract that will verify the signature
    ///
    /// # Returns
    ///
    /// * [SRC16Domain] - A new instance of SRC16Domain with the provided parameters
    ///
    pub fn new(
        domain_name: String,
        version: String,
        chain_id: u64,
        verifying_contract: b256,
    ) -> SRC16Domain {
        SRC16Domain {
            name: domain_name,
            version: version,
            chain_id: chain_id,
            verifying_contract: verifying_contract,
        }
    }

    /// Computes the Keccak256 hash of the encoded domain parameters
    ///
    /// # Additional Information
    ///
    /// The encoding follows thse scheme:
    /// 1. add SRC16_DOMAIN_TYPE_HASH
    /// 2. add Keccak256 hash of name string
    /// 3. add Keccak256 hash of version string
    /// 4. add Chain ID as 32-byte big-endian
    /// 5. add Verifying contract address as 32-bytes
    ///
    /// # Returns
    ///
    /// * [b256] - The Keccak256 hash of the encoded domain parameters
    ///
    pub fn domain_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        encoded.append(
            SRC16_DOMAIN_TYPE_HASH.to_be_bytes()
        );
        encoded.append(
            keccak256(Bytes::from(self.name)).to_be_bytes()
        );
        encoded.append(
            keccak256(Bytes::from(self.version)).to_be_bytes()
        );
        encoded.append(
            (asm(r1: (0, 0, 0, self.chain_id)) { r1: b256 }).to_be_bytes()
        );
        encoded.append(
            self.verifying_contract.to_be_bytes()
        );
        keccak256(encoded)
    }

}


/// Trait that provides common encoding methods for different data types
///
/// # Additional Information
///
/// This trait standardizes the encoding of common data types used in structured data.
///
pub trait TypedDataEncoder {

    /// Encodes a string value into a 32-byte hash
    ///
    /// # Arguments
    ///
    /// * `value`: [String] - The string to encode
    ///
    /// # Returns
    ///
    /// * [b256] - The encoded string value
    fn encode_string(value: String) -> b256;

    /// Encodes a 32-byte value
    ///
    /// # Arguments
    ///
    /// * `value`: [b256] - The value to encode
    ///
    /// # Returns
    ///
    /// * [b256] - The encoded value
    fn encode_bytes32(value: b256) -> b256;

    /// Encodes a u64 value into a 32-byte value
    ///
    /// # Arguments
    ///
    /// * `value`: [u64] - The number to encode
    ///
    /// # Returns
    ///
    /// * [b256] - The encoded value
    fn encode_u64(value: u64) -> b256;
}

/// Default implementation of the TypedDataEncoder trait
///
/// # Additional Information
///
/// This implementation provides standard encoding methods that follow
/// the SRC16 specification's requirements for type encoding.
pub struct DefaultEncoder {}

impl TypedDataEncoder for DefaultEncoder {

    #[allow(dead_code)]
    fn encode_string(value: String) -> b256 {
        // string.as_bytes()
        keccak256(Bytes::from(value))
    }

    #[allow(dead_code)]
    fn encode_bytes32(value: b256) -> b256 {
        value
    }

    #[allow(dead_code)]
    fn encode_u64(value: u64) -> b256 {
        asm(r1: (0, 0, 0, value)) { r1: u256 }
    }
}

/// Trait for types that can be hashed in a structured way
///
/// # Additional Information
///
/// Types implementing this trait can be used with SRC16 for structured data signing.
/// Implementors should ensure their hash computation follows the SRC16 specification.
pub trait TypedDataHash {

    /// Returns the hash of the structured data
    ///
    /// # Returns
    ///
    /// * [b256] - The Keccak256 hash of the encoded structured data
    fn struct_hash(self) -> b256;
}


/// A struct to hold the signing domain and types data hash.
pub struct SRC16Payload{
    pub domain: SRC16Domain,
    pub data_hash: b256,
}

impl SRC16Payload {

    /// Computes the encoded hash according to SRC16 specification
    ///
    /// # Additional Information
    ///
    /// The encoding follows this scheme:
    /// 1. Add prefix bytes \x19\x01
    /// 2. Add domain separator hash
    /// 3. Add data struct hash
    /// 4. Compute final Keccak256 hash
    ///
    /// # Returns
    ///
    /// * [Option<b256>] - The encoded hash, or None if encoding fails
    ///
    pub fn encode_hash(self) -> Option<b256> {

        let domain_separator_bytes = self.domain.domain_hash().to_be_bytes();
        let data_hash_bytes = self.data_hash.to_be_bytes();
        let mut digest_input = Bytes::with_capacity(66);
        // add prefix
        digest_input.push(0x19);
        digest_input.push(0x01);
        // add domain_separator then tped data hash
        digest_input.append(domain_separator_bytes);
        digest_input.append(data_hash_bytes);
        let final_hash = keccak256(digest_input);

        Some(final_hash)
    }
}

