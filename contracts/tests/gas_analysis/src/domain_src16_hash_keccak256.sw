library;

use std::{
    bytes::Bytes,
    string::String,
    hash::*,
};
use std::bytes_conversions::{b256::*, u256::*, u64::*};
use std::core::codec::{AbiEncode, encode};
use helpers::hex::*;

/*
--------------------------------------------------
|                                                 |
| Keccak256 version of SRC16Domain Implementation |
|                                                 |
--------------------------------------------------
*/

pub struct SRC16Domain {
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: ContractId,
}

/// This is the Keccak256 hash of "SRC16Domain(string name,string version,uint256 chainId,contractId verifyingContract)"
pub const SRC16_DOMAIN_TYPE_HASH: b256 = 0x10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f;

// Implement AbiEncode for SRC16Domain
impl AbiEncode for SRC16Domain {
    fn abi_encode(self, buffer: Buffer) -> Buffer {
        let buffer = SRC16_DOMAIN_TYPE_HASH_KECCAK256.abi_encode(buffer);
        let buffer = keccak256(Bytes::from(self.name)).abi_encode(buffer);
        let buffer = keccak256(Bytes::from(self.version)).abi_encode(buffer);
        let buffer = (asm(r1: (0, 0, 0, self.chain_id)) { r1: b256 }).abi_encode(buffer);
        let buffer = self.verifying_contract.abi_encode(buffer);
        buffer
    }
}

impl SRC16Domain {

    pub fn new(
        domain_name: String,
        version: String,
        chain_id: u64,
        verifying_contract: ContractId,
    ) -> SRC16Domain {
        SRC16Domain {
            name: domain_name,
            version: version,
            chain_id: chain_id,
            verifying_contract: verifying_contract,
        }
    }

    pub fn keccack256_domain_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        encoded.append(
            SRC16_DOMAIN_TYPE_HASH_KECCAK256.to_be_bytes()
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

    pub fn domain_hash(self) -> b256 {
        // Use the encode() helper from core::codec
        // Convert raw_slice to Bytes before hashing
        let encoded = encode(self);
        let bytes = Bytes::from(encoded);
        keccak256(bytes)
    }

}



/// Trait for domain types that can be hashed
pub trait DomainHash {
    fn domain_hash(self) -> b256;
}

impl DomainHash for SRC16Domain {
    fn domain_hash(self) -> b256 {
        self.domain_hash()
    }
}



pub struct SRC16DomainHashTest<D> {
    pub domain: D,
}

impl<D> SRC16DomainHashTest<D> {

    pub fn domain_encode_hash(self) -> Option<b256>
        where D: DomainHash
    {
        let domain_separator = self.domain.domain_hash();

        Some(domain_separator)
    }

}

// Create the domain for testing
fn get_src16_domain() -> SRC16Domain {

    let contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;

    let domain = SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        ContractId::from(contractid),
    );
    domain
}


// forc test src16_abiencode_domain_hash_keccak256 --logs
// test the gas usage of hashing the domain type with Keccak256
#[test]
fn src16_abiencode_domain_hash_keccak256(){

    let domain_test = SRC16DomainHashTest {
        domain: get_src16_domain(),
    };

    // Get the abi encoded domain hash
    match domain_test.domain_encode_hash() {
        Some(hash) => {

            log(b256_to_hex(hash));
        },
        None => revert(0),
    }

    // test src16_abiencode_domain_hash_keccak256 ... ok (35.816364ms, 34475 gas)

}

// forc test src16_gas_analysis_domain_hash_keccak256 --logs
// test the gas usage of hashing the domain type with Keccak256
#[test]
fn src16_gas_analysis_domain_hash_keccak256(){

    let domain_type_hash = get_src16_domain().keccack256_domain_hash();

    log(b256_to_hex(domain_type_hash));

    // test src16_gas_analysis_domain_hash_keccak256 ... ok (32.321632ms, 35793 gas)

}
