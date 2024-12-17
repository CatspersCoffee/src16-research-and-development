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
-----------------------------------------------
|                                              |
| SHA256 version of SRC16Domain Implementation |
|                                              |
-----------------------------------------------
*/

pub struct SRC16Domain {
    name: String,
    version: String,
    chain_id: u64,
    verifying_contract: ContractId,
}

/// This is the SHA256 hash of "SRC16Domain(string name,string version,uint256 chainId,address verifyingContract)"
pub const SRC16_DOMAIN_TYPE_HASH_SHA256: b256 = 0xae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd;


// Implement AbiEncode for SRC16Domain
impl AbiEncode for SRC16Domain {
    fn abi_encode(self, buffer: Buffer) -> Buffer {
        let buffer = SRC16_DOMAIN_TYPE_HASH_SHA256.abi_encode(buffer);
        let buffer = sha256(Bytes::from(self.name)).abi_encode(buffer);
        let buffer = sha256(Bytes::from(self.version)).abi_encode(buffer);
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

    pub fn sha256_domain_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        encoded.append(
            SRC16_DOMAIN_TYPE_HASH_SHA256.to_be_bytes()
        );
        encoded.append(
            sha256(Bytes::from(self.name)).to_be_bytes()
        );
        encoded.append(
            sha256(Bytes::from(self.version)).to_be_bytes()
        );
        encoded.append(
            (asm(r1: (0, 0, 0, self.chain_id)) { r1: b256 }).to_be_bytes()
        );
        encoded.append(
            self.verifying_contract.to_be_bytes()
        );
        sha256(encoded)
    }

    pub fn domain_hash(self) -> b256 {
        // Use the encode() helper from core::codec
        // Convert raw_slice to Bytes before hashing
        let encoded = encode(self);
        let bytes = Bytes::from(encoded);
        sha256(bytes)
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




// forc test src16_abiencode_domain_hash_sha256 --logs
// test the gas usage of hashing the domain type with SHA256
#[test]
fn src16_abiencode_domain_hash_sha256(){

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

    // test src16_abiencode_domain_hash_sha256 ... ok (33.065711ms, 34024 gas)
    // Decoded log value: 2d8d5a40bc8506473721b97b9eb5fa0909d5d504bc4c80b1556d5a005684832e, log rb: 11132648958528852192
}

// forc test src16_gas_analysis_domain_hash_sha256 --logs
// test the gas usage of hashing the domain type with SHA256
#[test]
fn src16_gas_analysis_domain_hash_sha256(){

    let domain_type_hash = get_src16_domain().sha256_domain_hash();

    log(b256_to_hex(domain_type_hash));

    // Type hash (sha256 of)
    // Domain Name
    // Version
    // chainId
    // Verifying ContracId
    //
    // ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd
    // 7fbd3da2eec7df4aa07603bb0562d31ceea1ab6478809ab76bf062cafffdf2ae
    // 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b
    // 00000000000000000000000000000000000000000000000000000000000026a1
    // 0000000000000000000000000000000000000000000000000000000000000001

    // ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd7fbd3da2eec7df4aa07603bb0562d31ceea1ab6478809ab76bf062cafffdf2ae6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b00000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001

    // test src16_gas_analysis_domain_hash_sha256 ... ok (33.715049ms, 35549 gas)
    // Decoded log value: 2d8d5a40bc8506473721b97b9eb5fa0909d5d504bc4c80b1556d5a005684832e, log rb: 11132648958528852192
}

// forc test get_sha_chainid_value --logs
//
#[test]
fn get_sha_chainid_value(){

    let chain_id = 9889u64;
    let chainid_bytes = (asm(r1: (0, 0, 0, chain_id)) { r1: b256 }).to_be_bytes();
    let chainid_encoded = sha256(chainid_bytes);

    log(b256_to_hex((asm(r1: (0, 0, 0, chain_id)) { r1: b256 })));
    log(b256_to_hex(chainid_encoded));
}

// Create the domain for testing
fn get_src16_domain() -> SRC16Domain {

    let contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let dummy_contractid = ContractId::from(contractid);

    SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        dummy_contractid
    )
}