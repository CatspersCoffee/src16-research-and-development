#![allow(unused_imports)]
#![allow(dead_code)]
use std::str::FromStr;
use hex;
use fuels::types::{Bytes32, U256, B512, Bits256, ContractId, Address};


pub mod custom04_src16 {

    use super::*;
    use sha3::{Digest, Keccak256};

    use crate::src16_encoder2::{
        self, encode, keccak256, Token, TypedData, ParamType
    };

    use serde_json::json;
    use serde::{Deserialize, Serialize};
    use serde::{Deserializer};

    use crate::hex_serde;

    // use serde::{de::Deserializer, de::Error as SerdeError};




    /// Pre-computed value of the following expression:
    ///
    /// `keccak256("SRC16Domain(string name,string version,uint256 chainId,contractId verifyingContract)")`
    ///
    /// 0x10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f
    ///
    /// Reference:
    /// from the ethers-contract/tests/solidity-contracts/DeriveEip712Test.sol
    ///
    /// const EIP712_DOMAIN_TYPEHASH: [u8; 32] = keccak256(
    ///     b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    /// );
    ///
    pub const SRC16_DOMAIN_TYPE_HASH: [u8; 32] = [
        16, 241, 50, 209, 173, 201, 145, 5, 187, 154, 208, 217, 137, 86, 169, 63,
        53, 189, 165, 199, 119, 19, 172, 19, 173, 196, 137, 96, 156, 57, 51, 111
    ];


    //---------------------------------------------------------------------------
    //
    //  Domain Type
    //
    //---------------------------------------------------------------------------

    // This struct represents the SRC16Domain "the domain type"

    // #[derive(Debug, Clone)]
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SRC16Domain {
        pub name: String,
        pub version: String,
        #[serde(
            rename = "chainId",
            deserialize_with = "deserialize_stringified_numeric",
        )]
        pub chain_id: u64,
        #[serde(rename = "verifyingContract")]
        pub verifying_contract: ContractId,
    }

    fn deserialize_stringified_numeric<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }

    /*
    /// Helper function to deserialize string numbers into u64
    fn deserialize_stringified_numeric_opt<'de, D>(
        deserializer: D
    ) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de> + serde::de::Error,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum StringifiedNumeric {
            String(String),
            Number(u64),
        }

        match Option::<StringifiedNumeric>::deserialize(deserializer)? {
            Some(StringifiedNumeric::String(s)) => {
                s.parse().map(Some).map_err(D::custom)
            }
            Some(StringifiedNumeric::Number(n)) => Ok(Some(n)),
            None => Ok(None),
        }
    }
    */

    // cargo test --package custom-src16-encoder --lib -- src16_v4::custom04_src16::domain_type_hash --exact --show-output
    #[test]
    pub fn domain_type_hash(){
        let expected_domain_type_hash = hex::decode("10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f").unwrap();
        let expected_domain_type_hash_bytes: [u8; 32] = expected_domain_type_hash.as_slice().try_into().unwrap();

        println!("expected_domain_type_hash_bytes: {}", hex::encode(expected_domain_type_hash_bytes));

        let domain_type_utf8 = "SRC16Domain(string name,string version,uint256 chainId,contractId verifyingContract)";

        let mut hasher = Keccak256::new();
        hasher.update(domain_type_utf8.as_bytes());
        let hash = hasher.finalize();

        let domain_type_hash: [u8; 32] = hash.into();
        println!("domain_type_hash: {}", hex::encode(domain_type_hash));

        assert_eq!(expected_domain_type_hash_bytes, domain_type_hash);
        assert_eq!(expected_domain_type_hash_bytes, SRC16_DOMAIN_TYPE_HASH);
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

        6. Add verifyingContract (as 32-byte ContractId on Fuel)
        result += address(verifyingContract)

        7. Compute final hash
        domain_separator = keccak256(result)
        */

        fn domain_separator_hash(&self) -> [u8; 32] {

            let mut tokens = Vec::new();

            // 1. Add SRC16_DOMAIN_TYPE_HASH
            // DEBUG:
            let token1 = Token::Uint(SRC16_DOMAIN_TYPE_HASH);
            println!("SRC16_DOMAIN_TYPE_HASH       : {}", hex::encode(SRC16_DOMAIN_TYPE_HASH));
            println!("SRC16_DOMAIN_TYPE_HASH Token : {:?}", token1);

            tokens.push(Token::Uint(SRC16_DOMAIN_TYPE_HASH));


            // 2. Add hash of name
            // DEBUG:
            let nh = keccak256(self.name.as_bytes());
            let token2 = Token::String(self.name.clone());
            println!(" ");
            println!("Name Hash                    : {}", hex::encode(nh));
            println!("Name Hash Token              : {:?}", token2);

            tokens.push(Token::String(self.name.clone()));


            // 3. Add hash of version
            let vh = keccak256(self.version.as_bytes());
            let token3 = Token::String(self.version.clone());
            println!(" ");
            println!("Version Hash                 : {}", hex::encode(vh));
            println!("Version Hash Token           : {:?}", token3);

            tokens.push(Token::String(self.version.clone()));


            // 4. Add chainId
            let mut c_bytes = [0u8; 32];
            c_bytes[24..32].copy_from_slice(&self.chain_id.to_be_bytes());
            let token4 = src16_encoder2::number_to_token(self.chain_id);
            println!(" ");
            println!("Chain ID (hex)               : {}", hex::encode(c_bytes));
            println!("Chain ID Token               : {:?}", token4);

            tokens.push(src16_encoder2::number_to_token(self.chain_id));


            // 5. Add verifyingContract
            /*
            let token5 = Token::FixedBytes(self.verifying_contract.0.to_vec());
            let mut vcbytes = [0u8; 32];
            vcbytes.copy_from_slice(&self.verifying_contract.0);
            println!(" ");
            println!("Verifying Contract           : {}", hex::encode(vcbytes));
            println!("Verifying Contract Token     : {:?}", token5);

            tokens.push(Token::FixedBytes(self.verifying_contract.0.to_vec()));
            */

            // let token5 = Token::FixedBytes(self.verifying_contract.to_vec());
            // let mut vcbytes = [0u8; 32];
            // vcbytes.copy_from_slice(&self.verifying_contract.as_slice());
            // println!(" ");
            // println!("Verifying Contract           : {}", hex::encode(vcbytes));
            // println!("Verifying Contract Token     : {:?}", token5);

            // tokens.push(Token::FixedBytes(self.verifying_contract.to_vec()));


            let contract_bytes: [u8; 32] = self.verifying_contract.into();
            let token5 = Token::FixedBytes(contract_bytes);
            println!(" ");
            println!("Verifying Contract           : {}", hex::encode(&contract_bytes));
            println!("Verifying Contract Token     : {:?}", token5);

            tokens.push(token5);



            // Encode all tokens
            let encoded = src16_encoder2::encode(&tokens);
            println!(" ");
            println!("Encoded Tokens     : {}", hex::encode(&encoded));

            // Compute final hash
            let final_hash = src16_encoder2::keccak256(encoded.as_slice());
            println!(" ");
            println!("Final Hash         : {}", hex::encode(&final_hash));
            println!(" ");

            final_hash
        }

        /*
        https://emn178.github.io/online-tools/keccak_256.html?input=10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001&input_type=hex&output_type=hex

        10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f --> SRC16_DOMAIN_TYPE_HASH
        49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract

        a4a3e8ae873833c636439e06bda4dce44a171cc137900fc3af7aa26c6085b403 --> final hash
        */

    }

    // cargo test --package custom-src16-encoder --lib -- src16_v4::custom04_src16::test_domain_separator_hash_fuel_address --exact --show-output
    //
    // SRC16_DOMAIN_TYPE_HASH   : 10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f
    // Name Hash                : 49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20
    // Version Hash             : c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6
    // Chain ID (hex)           : 00000000000000000000000000000000000000000000000000000000000026a1
    // Verifying Contract       : 0000000000000000000000000000000000000000000000000000000000000001
    // Encoded Tokens           : 10f132d1adc99105bb9ad0d98956a93f35bda5c77713ac13adc489609c39336f49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001
    // Final Hash               : a4a3e8ae873833c636439e06bda4dce44a171cc137900fc3af7aa26c6085b403
    //
    #[test]
    fn test_domain_separator_hash_fuel_address() {

        let mut fuel_verifying_contract: [u8; 32] = [0x00; 32];
        fuel_verifying_contract[31] = 0x01;
        let verifying_contract_id = ContractId::from(fuel_verifying_contract);

        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: verifying_contract_id,
        };
        let domain_separator_hash = domain.domain_separator_hash();
        println!("Domain Separator Hash : 0x{}", hex::encode(domain_separator_hash));

        let expected_domain_separator_hash = hex::decode("a4a3e8ae873833c636439e06bda4dce44a171cc137900fc3af7aa26c6085b403").unwrap();
        assert_eq!(expected_domain_separator_hash, domain_separator_hash.as_slice());
    }


    //---------------------------------------------------------------------------
    //
    //  Typed Structured Data
    //
    //---------------------------------------------------------------------------

    // This struct represent the Typed Structured Data
    #[derive(Clone, Debug)]
    pub struct Mail {
        pub from: Address,
        pub to: Address,
        pub contents: String,
    }


    impl Mail {

        /// https://emn178.github.io/online-tools/keccak_256.html?input=Mail(address%20from%2Caddress%20to%2Cstring%20contents)&input_type=utf-8&output_type=hex
        /// 536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67f
        fn type_hash() -> [u8; 32] {
            let type_string = "Mail(address from,address to,string contents)";
            src16_encoder2::keccak256(type_string.as_bytes())
        }

        fn manual_encode_string(value: &str) -> [u8; 32] {
            // Convert string to UTF-8 bytes and take keccak256 hash
            keccak256(value.as_bytes())
        }

        fn manual_encode_h256(value: &Bits256) -> [u8; 32] {
            value.0
        }

        fn manual_encode_address(value: &Address) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(value.as_slice());
            bytes
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
            src16_encoder2::keccak256(encoded.as_slice())
        }

        // manually calcualte struct hash
        fn struct_hash(&self) -> [u8; 32] {
            let mut encoded = Vec::new();

            // Encode: type hash
            // 1.
            encoded.extend_from_slice(&Self::type_hash());

            // let type_hash_encoded = Self::type_hash();
            // println!("type_hash_encoded     : {}", hex::encode(type_hash_encoded));


            // Encode: return from --> H256
            // 2.
            // let from_encoded_hash = Self::manual_encode_address(&self.from);
            // println!("from_encoded_hash     : {}", hex::encode(from_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_address(&self.from));


            // Encode: return to --> H256
            // 3.
            // let to_encoded_hash = Self::manual_encode_address(&self.to);
            // println!("to_encoded_hash       : {}", hex::encode(to_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_address(&self.to));


            // Encode: Command --> String:
            // 4.
            // let contents_encoded_hash = Self::manual_encode_string(&self.contents);
            // println!("contents_encoded_hash : {}", hex::encode(contents_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_string(&self.contents));


            // encoded bytes
            // println!("encoded: {}", hex::encode(&encoded));
            // println!(" ");

            let encoded_hash = src16_encoder2::keccak256(encoded.as_slice());
            // println!("encoded struct hash   : {}", hex::encode(&encoded_hash));
            // println!(" ");

            encoded_hash
        }


    }


    // cargo test --package custom-src16-encoder --lib -- src16_v4::custom04_src16::test_struct_hash_for_mail --exact --show-output
    /*
    type_hash_encoded     : 536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67f
    from_encoded_hash     : abababababababababababababababababababababababababababababababab
    to_encoded_hash       : cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
    contents_encoded_hash : 4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
    encoded: 536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67fababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8

    encoded struct hash   : 62d7ef9b8083d5789cc5631f3398ab2ed4e01644f4222716b8a487f351be2c37

    https://emn178.github.io/online-tools/keccak_256.html?input=536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67fababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8&input_type=hex&output_type=hex
    */
    #[test]
    fn test_struct_hash_for_mail() {

        // Create the mail struct:
        //
        let from_address: [u8; 32] = [0xAB; 32];
        let dummy_from_address = Address::from(from_address);

        let to_address: [u8; 32] = [0xCD; 32];
        let dummy_to_address = Address::from(to_address);
        let dummy_contents = "A message from Alice to Bob.".to_string();

        let mail_data = Mail {
            from: dummy_from_address,
            to: dummy_to_address,
            contents: dummy_contents,
        };

        let mail_data_struct_hash = mail_data.struct_hash();
        println!("Mail data hash: 0x{}", hex::encode(mail_data_struct_hash));
        let expected_struct_hash = hex::decode("62d7ef9b8083d5789cc5631f3398ab2ed4e01644f4222716b8a487f351be2c37").unwrap();

        assert_eq!(mail_data_struct_hash, expected_struct_hash.as_slice());
    }


    pub trait SRC16 {
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
            let hash = src16_encoder2::keccak256(digest_input.as_slice());

            Ok(hash)
        }
    }

    // cargo test --package custom-src16-encoder --lib -- src16_v4::custom04_src16::test_final_encoding_for_mail --exact --show-output
    #[test]
    fn test_final_encoding_for_mail() {

        // Setup signer domain:
        //
        let mut fuel_verifying_contract: [u8; 32] = [0x00; 32];
        fuel_verifying_contract[31] = 0x01;
        let verifying_contract_id = ContractId::from(fuel_verifying_contract);

        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: verifying_contract_id,
        };

        // Create the mail struct:
        //
        let from_address: [u8; 32] = [0xAB; 32];
        let dummy_from_address = Address::from(from_address);

        let to_address: [u8; 32] = [0xCD; 32];
        let dummy_to_address = Address::from(to_address);
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
        let expected_final_encoded_hash = hex::decode("df830c4a36744c712c3057faf8142a8b56946d3319b7c7688310407d3fab0e96").unwrap();

        assert_eq!(encoded_hash, expected_final_encoded_hash.as_slice());
    }


    //---------------------------------------------------------------------------
    //
    //  Mail Encoding using TypeData Encoder
    //
    //---------------------------------------------------------------------------



    // cargo test --package custom-src16-encoder --lib -- src16_v4::custom04_src16::test_mail_encoding --exact --show-output
    #[test]
    fn test_mail_encoding() {
        let from_address: [u8; 32] = [0xAB; 32];
        let to_address: [u8; 32] = [0xCD; 32];
        let contents = "A message from Alice to Bob.";

        // The JSON structure stays the same since it's the external interface
        let typed_data_json = json!({
            "types": {
                "SRC16Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"}
                ],
                "Mail": [
                    {"name": "from", "type": "bytes32"},
                    {"name": "to", "type": "bytes32"},
                    {"name": "contents", "type": "string"}
                ]
            },
            "primaryType": "Mail",
            "domain": {
                "name": "MyDomain",
                "version": "1",
                "chainId": "9889",
                "verifyingContract": format!("0x{}", hex::encode([0u8; 31].into_iter().chain([1u8].into_iter()).collect::<Vec<_>>()))
            },
            "message": {
                "from": format!("0x{}", hex::encode(from_address)),
                "to": format!("0x{}", hex::encode(to_address)),
                "contents": contents
            }
        });

        // Parse JSON into TypedData
        let typed_data: TypedData = match serde_json::from_value(typed_data_json) {
            Ok(data) => data,
            Err(e) => {
                panic!("Failed to parse JSON: {}", e);
            }
        };

        // Now using the new encoding with ParamTypes
        let encoded = match typed_data.encode_data(
            "Mail",
            &serde_json::Value::Object(serde_json::Map::from_iter(typed_data.message.clone()))
        ) {
            Ok(tokens) => {
                println!("\nEncoded tokens:");
                for token in &tokens {
                    match token {
                        Token::FixedBytes(bytes) => {
                            let param_type = ParamType::Bytes32;
                            println!("FixedBytes({:?}): 0x{}", param_type, hex::encode(bytes))
                        },
                        Token::Address(addr) => {
                            let param_type = ParamType::Address;
                            println!("Address({:?}): 0x{}", param_type, hex::encode(addr))
                        },
                        Token::String(s) => {
                            let param_type = ParamType::String;
                            println!("String({:?}): {}", param_type, s)
                        },
                        Token::Uint(num) => {
                            let param_type = ParamType::Uint(256);
                            println!("Uint({:?}): 0x{}", param_type, hex::encode(num))
                        },
                        Token::Bool(value) => {
                            let param_type = ParamType::Bool;
                            println!("Bool({:?}): {}", param_type, value)
                        }
                    }
                }
                tokens
            },
            Err(e) => {
                panic!("Failed to encode data: {}", e);
            }
        };

        // Create final hash
        let final_hash = keccak256(&encode(&encoded));
        println!("final_hash: 0x{}", hex::encode(final_hash));

        // Verify the hash matches expected value
        let expected_struct_hash = hex::decode(
            "23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775"
        ).expect("Failed to decode expected hash");

        assert_eq!(final_hash.as_slice(), expected_struct_hash.as_slice());
    }


}
