use std::str::FromStr;
use hex;
use ethers::core::abi::{AbiDecode, Token, ParamType};
use ethers::core::types::{Address, U256, Bytes, H256, U64};
use ethers::utils::rlp;

use ethers::prelude::*;


use ethers_core::types::transaction::eip712::EIP712Domain;





pub mod custom01_src16 {
    use crate::crypto_helpers;

    use super::*;
    use ethers::utils::keccak256;
    use std::collections::BTreeMap;
    use ethers::abi::{Token, encode};
    use ethers::types::transaction::eip712::encode_eip712_type;

    // use crate::crypto::*;

    /// Pre-computed value of the following expression:
    ///
    /// `keccak256("SRC16Domain(string name,string version,uint256 chainId,address verifyingContract)")`
    ///
    /// ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd
    ///
    /// Reference:
    /// from the ethers-contract/tests/solidity-contracts/DeriveEip712Test.sol
    ///
    /// const EIP712_DOMAIN_TYPEHASH: [u8; 32] = keccak256(
    ///     b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    /// );
    ///
    pub const SRC16_DOMAIN_TYPE_HASH: [u8; 32] = [
        174, 145, 137, 212, 150, 148, 79, 124, 100, 57, 97, 207, 27, 121, 117,
        195, 15, 234, 70, 66, 99, 237, 25, 231, 104, 129, 221, 181, 98, 91, 185, 189
    ];


    //---------------------------------------------------------------------------
    //
    //  Domain Type
    //
    //---------------------------------------------------------------------------

    // This struct represents the SRC16Domain "the domain type"
    struct SRC16Domain {
        name: String,
        version: String,
        chain_id: u64,
        verifying_contract: Address,
    }

    // cargo test --package src16-research-and-development --bin src16-research-and-development -- src16_v1::custom01_src16::domain_type_hash --exact --show-output
    #[test]
    pub fn domain_type_hash(){
        let domain_type_hash = hex::decode("ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd").unwrap();
        let domain_type_hash_bytes: [u8; 32] = domain_type_hash.as_slice().try_into().unwrap();

        assert_eq!(domain_type_hash_bytes, SRC16_DOMAIN_TYPE_HASH);
    }


    //---------------------------------------------------------------------------
    //
    //  Domain Separator "Domain type with parameters"
    //
    //---------------------------------------------------------------------------


    impl SRC16Domain {

        /*
        Domain Separator Hash Calculation:

        1. Start with empty result
        result = []

        2. Add SRC16_DOMAIN_TYPE_HASH
        result += SRC16_DOMAIN_TYPE_HASH

        3. Add hash of name
        result += keccak256(bytes(name))

        4. Add hash of version
        result += keccak256(bytes(version))

        5. Add chainId (as 32-byte big-endian)
        result += uint256(chainId).to_be_bytes()

        6. Add verifyingContract (as 20-byte address)
        result += address(verifyingContract)

        7. Compute final hash
        domain_separator = keccak256(result)
        */

        fn domain_separator_hash(&self) -> [u8; 32] {

            let mut tokens = Vec::new();

            // 1. Add SRC16_DOMAIN_TYPE_HASH
            let token1 = Token::Uint(U256::from(SRC16_DOMAIN_TYPE_HASH));
            println!("SRC16_DOMAIN_TYPE_HASH      : {}", hex::encode(SRC16_DOMAIN_TYPE_HASH));
            println!("SRC16_DOMAIN_TYPE_HASH Token: {:?}", token1);
            tokens.push(token1);

            // 2. Add hash of name
            let token2 = Token::Uint(U256::from(keccak256(self.name.as_bytes())));
            println!(" ");
            println!("Name Hash Token    : {:?}", token2);
            println!("Name Hash          : {}", hex::encode(keccak256(self.name.as_bytes())));
            println!(" ");
            tokens.push(token2);

            // 3. Add hash of version
            let token3 = Token::Uint(U256::from(keccak256(self.version.as_bytes())));
            println!(" ");
            println!("Version Hash Token: {:?}", token3);
            println!("Version Hash      : {}", hex::encode(keccak256(self.version.as_bytes())));
            println!(" ");
            tokens.push(token3);

            // 4. Add chainId
            let token4 = Token::Uint(U256::from(self.chain_id));
            // println!("Chain ID Token: {:?}", token4);
            // Convert U256 to bytes
            let u256_chainid = U256::from(self.chain_id);
            let mut u256_chainid_bytes = [0u8; 32];
            u256_chainid.to_big_endian(&mut u256_chainid_bytes);
            println!(" ");
            println!("Chain ID (hex)    : {}", hex::encode(u256_chainid_bytes));
            tokens.push(token4);

            // 5. Add verifyingContract
            let token5 = Token::Address(self.verifying_contract);
            // println!("Verifying Contract Token: {:?}", token5);
            let mut vcbytes = [0u8; 32];
            vcbytes[12..32].copy_from_slice(&self.verifying_contract.0);
            println!(" ");
            println!("Verifying Contract : {}", hex::encode(vcbytes));
            tokens.push(token5);

            // Encode all tokens
            let encoded = encode(&tokens);
            println!(" ");
            println!("Encoded Tokens     : {}", hex::encode(&encoded));

            // Compute final hash
            let final_hash = keccak256(encoded);
            println!(" ");
            println!("Final Hash         : {}", hex::encode(&final_hash));
            println!(" ");

            final_hash
        }

        /*
        https://emn178.github.io/online-tools/keccak_256.html?input=ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001&input_type=hex&output_type=hex

        ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd --> SRC16_DOMAIN_TYPE_HASH
        49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract

        cdf6328e5f89cab9b3f1cae206af45e1ce8c9dde811e3c42717f44d9f8347ffb --> final hash
        */

    }

    // cargo test --package src16-research-and-development --bin src16-research-and-development -- src16_v1::custom01_src16::test_domain_separator_hash --exact --show-output
    #[test]
    fn test_domain_separator_hash() {
        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        };
        let domain_separator_hash = domain.domain_separator_hash();
        println!("Domain Separator Hash : 0x{}", hex::encode(domain_separator_hash));

        let expected_domain_separator_hash = hex::decode("cdf6328e5f89cab9b3f1cae206af45e1ce8c9dde811e3c42717f44d9f8347ffb").unwrap();
        assert_eq!(expected_domain_separator_hash, domain_separator_hash.as_slice());
    }



    //---------------------------------------------------------------------------
    //
    //  Typed Structured Data
    //
    //---------------------------------------------------------------------------

    // This struct represent the Typed Structured Data
    #[derive(Clone, Debug)]
    struct Mail {
        from: H256,
        to: H256,
        contents: String,
    }


    impl Mail {

        /// https://emn178.github.io/online-tools/keccak_256.html?input=Mail(bytes32%20from%2Cbytes32%20to%2Cstring%20contents)&input_type=utf-8&output_type=hex
        /// cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
        fn type_hash() -> [u8; 32] {
            let type_string = "Mail(bytes32 from,bytes32 to,string contents)";
            keccak256(type_string)
        }

        fn manual_encode_string(value: &str) -> [u8; 32] {
            // Convert string to UTF-8 bytes and take keccak256 hash
            keccak256(value.as_bytes())
        }

        fn manual_encode_h256(value: &H256) -> [u8; 32] {
            value.0
        }

        fn manual_encode_u256(value: &U256) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            value.to_big_endian(&mut bytes);
            bytes
        }

        fn manual_encode_src16_array<T>(array: &[T], encoder: fn(&T) -> [u8; 32]) -> [u8; 32] {
            let mut encoded = Vec::with_capacity(array.len() * 32);
            for item in array {
                encoded.extend_from_slice(&encoder(item));
            }
            keccak256(encoded)
        }

        // manually calcualte struct hash
        fn struct_hash(&self) -> [u8; 32] {
            let mut encoded = Vec::new();

            // Encode: type hash
            // 1.
            encoded.extend_from_slice(&Self::type_hash());

            let type_hash_encoded = Self::type_hash();
            println!("type_hash_encoded     : {}", hex::encode(type_hash_encoded));


            // Encode: return from --> H256
            // 2.
            let from_encoded_hash = Self::manual_encode_h256(&self.from);
            println!("from_encoded_hash     : {}", hex::encode(from_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.from));


            // Encode: return to --> H256
            // 3.
            let to_encoded_hash = Self::manual_encode_h256(&self.to);
            println!("to_encoded_hash       : {}", hex::encode(to_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.to));


            // Encode: Command --> String:
            // 4.
            let contents_encoded_hash = Self::manual_encode_string(&self.contents);
            println!("contents_encoded_hash : {}", hex::encode(contents_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_string(&self.contents));


            // encoded bytes
            println!("encoded: {}", hex::encode(&encoded));
            println!(" ");

            let encoded_hash = keccak256(encoded);
            println!("encoded struct hash   : {}", hex::encode(&encoded_hash));
            println!(" ");

            encoded_hash
        }


    }


    // cargo test --package src16-research-and-development --bin src16-research-and-development -- src16_v1::custom01_src16::test_struct_hash_for_mail --exact --show-output
    /*
    type_hash_encoded     : cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
    from_encoded_hash     : abababababababababababababababababababababababababababababababab
    to_encoded_hash       : cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
    contents_encoded_hash : 4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
    encoded: cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056ababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8

    encoded struct hash   : 23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775

    https://emn178.github.io/online-tools/keccak_256.html?input=cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056ababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8&input_type=hex&output_type=hex
    */
    #[test]
    fn test_struct_hash_for_mail() {
        //
        // Create the mail struct:

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


        let mail_data_struct_hash = mail_data.struct_hash();
        println!("Mail data hash: 0x{}", hex::encode(mail_data_struct_hash));
        let expected_struct_hash = hex::decode("23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775").unwrap();

        assert_eq!(mail_data_struct_hash, expected_struct_hash.as_slice());
    }




    //
    trait SRC16 {
        fn encode_src16(&self) -> Result<[u8; 32], String>;
    }

    impl SRC16 for (SRC16Domain, Mail) {
        fn encode_src16(&self) -> Result<[u8; 32], String> {
            let (domain, tx_data) = self;
            let domain_separator = domain.domain_separator_hash();
            let struct_hash = tx_data.struct_hash();

            // Concatenate the components as per EIP-712 specification
            // -->  \x19\x01 + domain_separator + struct_hash
            let mut digest_input = Vec::with_capacity(66); // 2 + 32 + 32
            digest_input.extend_from_slice(&[0x19, 0x01]);
            digest_input.extend_from_slice(&domain_separator);
            digest_input.extend_from_slice(&struct_hash);
            let hash = keccak256(digest_input);

            Ok(hash)
        }
    }

    // cargo test --package src16-research-and-development --bin src16-research-and-development -- src16_v1::custom01_src16::test_final_encoding_for_mail --exact --show-output
    #[test]
    fn test_final_encoding_for_mail() {

        // Setup signer domain:
        //
        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        };


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

        // let mail_data_struct_hash = mail_data.struct_hash();
        // println!("Mail data hash: 0x{}", hex::encode(mail_data_struct_hash));

        let payload = (domain, mail_data);

        let encoded_hash = payload.encode_src16().map_err(|e| e.to_string()).unwrap();

        println!("encoded_hash: {}", hex::encode(encoded_hash));
        println!(" ");


        // let expected_struct_hash = hex::decode("23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775").unwrap();
        // assert_eq!(mail_data_struct_hash, expected_struct_hash.as_slice());

    }



}
