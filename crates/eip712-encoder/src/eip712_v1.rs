#![allow(unused_imports)]
use std::str::FromStr;
use hex;

use ethers::prelude::*;
use ethers::core::abi::{AbiDecode, Token, ParamType};
use ethers::core::types::{Address, U256, Bytes, H256, U64};
use ethers_core::types::transaction::eip712::EIP712Domain;

pub mod eip712_encoder_generic {

    use super::*;
    use crate::compact;

    use ethers_contract_derive::EthAbiType;
    // use ethers_core::types::*;
    // use ethers_core::abi::{AbiType, ParamType};


    use ethers::abi::{AbiEncode, AbiType, ParamType, Token, Tokenizable};
    use ethers_core::types::{
        transaction::eip712::{
            EIP712Domain, Eip712, EIP712_DOMAIN_TYPE_HASH,
            EIP712_DOMAIN_TYPE_HASH_WITH_SALT,
        },
        Address as EthAddress, H160, U256,
    };

    #[derive(Eip712, Clone, Debug, EthAbiType)]
    #[eip712(
        name = "MyDomain",
        version = "1",
        chain_id = 9889,
        verifying_contract = "0x0000000000000000000000000000000000000001"
    )]
    pub struct Mail {
        pub from: H256,
        pub to: H256,
        pub contents: String,
    }

    // cargo test --package eip712-encoder --lib -- eip712_v1::eip712_encoder_generic::test_eip712_final_encoding_for_mail --exact --show-output
    //
    //NOTE - Produces the same result as: forc test eip712_demo_encode_hash --logs
    //       in file: src16-research-and-development/contracts/tests/src/tests.sw
    //
    // Domain Separator : 0x02c940d36d1b3bfa130e17826da9f4d1615f52f87a0f17a86bf72cc9236e36c0
    // Type Hash        : 0xcfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
    // Struct Hash      : 0x23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775
    // Encoded EIP-712  : 0xd79278fa19b574f4b6e3fcbde0cd55576cdbfed7ad5b098fc2b60b5fe9aa75ff
    //
    #[test]
    fn test_eip712_final_encoding_for_mail() {

        // Create the mail struct:
        //
        let from_address = [0xAB; 32];
        let dummy_from_address = H256::from_slice(from_address.as_ref());
        let to_address = [0xCD; 32];
        let dummy_to_address = H256::from_slice(to_address.as_ref());
        let dummy_contents = "A message from Alice to Bob.".to_string();

        let mail_data = Mail {
            from: dummy_from_address,
            to: dummy_to_address,
            contents: dummy_contents,
        };

        // Verify the components of the EIP-712 structure
        let domain_separator = mail_data.domain().unwrap().separator();
        let type_hash = Mail::type_hash().unwrap();
        let struct_hash = mail_data.struct_hash().unwrap();

        let encoded = mail_data.encode_eip712().unwrap();

        println!("Domain Separator : 0x{}", hex::encode(domain_separator));
        println!("Type Hash        : 0x{}", hex::encode(type_hash));
        println!("Struct Hash      : 0x{}", hex::encode(struct_hash));
        println!("Encoded EIP-712  : 0x{}", hex::encode(encoded));
        println!(" ");
    }



}


pub mod eip712_encoder_v1 {

    use super::*;
    use crate::compact;

    use ethers_contract_derive::EthAbiType;
    // use ethers_core::types::*;
    // use ethers_core::abi::{AbiType, ParamType};


    use ethers::abi::{AbiEncode, AbiType, ParamType, Token, Tokenizable};
    use ethers_core::types::{
        transaction::eip712::{
            EIP712Domain, Eip712, EIP712_DOMAIN_TYPE_HASH,
            EIP712_DOMAIN_TYPE_HASH_WITH_SALT,
        },
        Address as EthAddress, H160, U256,
    };

    /// Pre-computed value of the following expression:
    /// Reference:
    /// from the ethers-contract/tests/solidity-contracts/DeriveEip712Test.sol
    ///
    /// const EIP712_DOMAIN_TYPEHASH: [u8; 32] = keccak256(
    ///     b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    /// );
    ///

    //---------------------------------------------------------------------------
    //
    //  Typed Structured Data
    //
    //---------------------------------------------------------------------------

    #[derive(Eip712, Clone, Debug, EthAbiType)]
    #[eip712(
        name = "MyDomain",
        version = "1",
        chain_id = 9889,
        verifying_contract = "0xc563dea1a8c6b7dace5a1412a26b8a71637b08a7"
    )]
    pub struct Mail {
        pub from: H256,
        pub to: H256,
        pub contents: String,
    }

    // cargo test --package eip712-encoder --lib -- eip712_v1::eip712_encoder_v1::test_eip712_final_encoding_for_mail --exact --show-output
    #[test]
    fn test_eip712_final_encoding_for_mail() {

        // Create the mail struct:
        //
        let from_address = [0xAB; 32];
        let dummy_from_address = H256::from_slice(from_address.as_ref());
        let to_address = [0xCD; 32];
        let dummy_to_address = H256::from_slice(to_address.as_ref());
        let dummy_contents = "A message from Alice to Bob.".to_string();

        let mail_data = Mail {
            from: dummy_from_address,
            to: dummy_to_address,
            contents: dummy_contents,
        };

        // Verify the components of the EIP-712 structure
        let domain_separator = mail_data.domain().unwrap().separator();
        let type_hash = Mail::type_hash().unwrap();
        let struct_hash = mail_data.struct_hash().unwrap();

        let encoded = mail_data.encode_eip712().unwrap();

        println!("Domain Separator : 0x{}", hex::encode(domain_separator));
        println!("Type Hash        : 0x{}", hex::encode(type_hash));
        println!("Struct Hash      : 0x{}", hex::encode(struct_hash));
        println!("Encoded EIP-712  : 0x{}", hex::encode(encoded));
        println!(" ");
    }

    pub fn eip712_get_static_varifying_contact_encode() -> [u8; 32] {

        // Create the mail struct:
        //
        let from_address = [0xAB; 32];
        let dummy_from_address = H256::from_slice(from_address.as_ref());
        let to_address = [0xCD; 32];
        let dummy_to_address = H256::from_slice(to_address.as_ref());
        let dummy_contents = "A message from Alice to Bob.".to_string();

        let mail_data = Mail {
            from: dummy_from_address,
            to: dummy_to_address,
            contents: dummy_contents,
        };

        // Verify the components of the EIP-712 structure
        let _domain_separator = mail_data.domain().unwrap().separator();
        let _type_hash = Mail::type_hash().unwrap();
        let _struct_hash = mail_data.struct_hash().unwrap();

        let encoded = mail_data.encode_eip712().unwrap();

        encoded
    }

}
