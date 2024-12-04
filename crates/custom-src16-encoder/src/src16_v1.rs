#![allow(unused_imports)]
#![allow(dead_code)]
use std::str::FromStr;
use hex;
use ethers::core::types::{Address, U256, Bytes, H256, U64};

pub mod custom01_src16 {

    use crate::compact;

    use super::*;
    use ethers::utils::keccak256;
    use ethers::abi::{Token, encode};
    // use ethers::types::transaction::eip712::encode_eip712_type;

    // use crate::crypto::*;

    /// Pre-computed value of the following expression:
    ///
    /// `keccak256("SRC16Domain(string name,string version,uint256 chainId,address verifyingContract)")`
    ///
    /// 0x3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e
    ///
    /// Reference:
    /// from the ethers-contract/tests/solidity-contracts/DeriveEip712Test.sol
    ///
    /// const EIP712_DOMAIN_TYPEHASH: [u8; 32] = keccak256(
    ///     b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    /// );
    ///
    pub const SRC16_DOMAIN_TYPE_HASH: [u8; 32] = [61, 153, 82, 13, 104, 145, 140, 57, 209, 21, 192, 177,
     123, 168, 69, 76, 23, 35, 23, 94, 207, 75, 56, 210, 85, 40, 254, 10, 17, 125, 183, 142];


    //---------------------------------------------------------------------------
    //
    //  Domain Type
    //
    //---------------------------------------------------------------------------

    // This struct represents the SRC16Domain "the domain type"
    /*
    pub struct SRC16Domain {
        pub name: String,
        pub version: String,
        pub chain_id: u64,
        pub verifying_contract: Adress,
    }
    */
    //NOTE - See Note 1. changed to 32-Byte verifying_contract Address (Fuel Address type)
    pub struct SRC16Domain {
        pub name: String,
        pub version: String,
        pub chain_id: u64,
        pub verifying_contract: H256,
    }

    // cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::domain_type_hash --exact --show-output
    #[test]
    pub fn domain_type_hash(){
        let expected_domain_type_hash = hex::decode("3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e").unwrap();
        let expected_domain_type_hash_bytes: [u8; 32] = expected_domain_type_hash.as_slice().try_into().unwrap();

        println!("expected_domain_type_hash_bytes: {:?}", expected_domain_type_hash_bytes);

        let domain_type_utf8 = "SRC16Domain(string name,string version,uint256 chainId,address verifyingContract)";
        let domain_type_hash = keccak256(domain_type_utf8);

        println!("domain_type_hash: {}", hex::encode(domain_type_hash));


        assert_eq!(expected_domain_type_hash_bytes, domain_type_hash);
        assert_eq!(expected_domain_type_hash_bytes, SRC16_DOMAIN_TYPE_HASH);
    }


    //---------------------------------------------------------------------------
    //
    //  Domain Separator "Domain type with parameters"
    //
    //---------------------------------------------------------------------------


    //---------------------------------------------------------------------------
    //
    //NOTE - Note 1:
    //NOTE - For Ethereum using EIP712 encoding/Tokenization this would need to
    // remain as a 20-Byte Address. On Fuel we are using the full 32-Bytes.
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

        6. Add verifyingContract (as 20-byte address on Ethereum) / (as 32-byte address on Fuel) See Note 1
        result += address(verifyingContract)

        7. Compute final hash
        domain_separator = keccak256(result)
        */

        fn domain_separator_hash(&self) -> [u8; 32] {

            let mut tokens = Vec::new();

            // 1. Add SRC16_DOMAIN_TYPE_HASH
            let token1 = Token::Uint(U256::from(SRC16_DOMAIN_TYPE_HASH));
            // println!("SRC16_DOMAIN_TYPE_HASH      : {}", hex::encode(SRC16_DOMAIN_TYPE_HASH));
            // println!("SRC16_DOMAIN_TYPE_HASH Token: {:?}", token1);
            tokens.push(token1);

            // 2. Add hash of name
            let token2 = Token::Uint(U256::from(keccak256(self.name.as_bytes())));
            // println!(" ");
            // println!("Name Hash Token    : {:?}", token2);
            // println!("Name Hash          : {}", hex::encode(keccak256(self.name.as_bytes())));
            // println!(" ");
            tokens.push(token2);

            // 3. Add hash of version
            let token3 = Token::Uint(U256::from(keccak256(self.version.as_bytes())));
            // println!(" ");
            // println!("Version Hash Token: {:?}", token3);
            // println!("Version Hash      : {}", hex::encode(keccak256(self.version.as_bytes())));
            // println!(" ");
            tokens.push(token3);

            // 4. Add chainId
            let token4 = Token::Uint(U256::from(self.chain_id));
            // println!("Chain ID Token: {:?}", token4);
            // Convert U256 to bytes
            let u256_chainid = U256::from(self.chain_id);
            let mut u256_chainid_bytes = [0u8; 32];
            u256_chainid.to_big_endian(&mut u256_chainid_bytes);
            // println!(" ");
            // println!("Chain ID (hex)    : {}", hex::encode(u256_chainid_bytes));
            tokens.push(token4);

            // 5. Add verifyingContract
            //NOTE - See Note 1
            /*
            let token5 = Token::Address(self.verifying_contract);
            // println!("Verifying Contract Token: {:?}", token5);
            let mut vcbytes = [0u8; 32];
            vcbytes[12..32].copy_from_slice(&self.verifying_contract.0);
            println!(" ");
            println!("Verifying Contract : {}", hex::encode(vcbytes));
            tokens.push(token5);
            */
            // let f = self.verifying_contract.0;
            let token5 = Token::FixedBytes(self.verifying_contract.0.to_vec());
            // println!("Verifying Contract Token: {:?}", token5);
            let mut vcbytes = [0u8; 32];
            vcbytes.copy_from_slice(&self.verifying_contract.0);
            // println!(" ");
            // println!("Verifying Contract : {}", hex::encode(vcbytes));
            tokens.push(token5);


            // Encode all tokens
            let encoded = encode(&tokens);
            // println!(" ");
            // println!("Encoded Tokens     : {}", hex::encode(&encoded));

            // Compute final hash
            let final_hash = keccak256(encoded);
            // println!(" ");
            // println!("Final Hash         : {}", hex::encode(&final_hash));
            // println!(" ");

            final_hash
        }

        /*
        https://emn178.github.io/online-tools/keccak_256.html?input=3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001&input_type=hex&output_type=hex

        3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e --> SRC16_DOMAIN_TYPE_HASH
        49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract

        b7398b1020c9fc9ecea32c3bdd18b471b814ed9a1a142addb0ef5bde2fab7c07 --> final hash
        */

    }

    /*
    // cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_domain_separator_hash_ethereum_address --exact --show-output
    #[test]
    fn test_domain_separator_hash_ethereum_address() {
        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        };
        let domain_separator_hash = domain.domain_separator_hash();
        println!("Domain Separator Hash : 0x{}", hex::encode(domain_separator_hash));

        let expected_domain_separator_hash = hex::decode("b7398b1020c9fc9ecea32c3bdd18b471b814ed9a1a142addb0ef5bde2fab7c07").unwrap();
        assert_eq!(expected_domain_separator_hash, domain_separator_hash.as_slice());
    }
    */

    // cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_domain_separator_hash_fuel_address --exact --show-output
    //
    // SRC16_DOMAIN_TYPE_HASH   : 3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e
    // Name Hash                : 49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20
    // Version Hash             : c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6
    // Chain ID (hex)           : 00000000000000000000000000000000000000000000000000000000000026a1
    // Verifying Contract       : 0000000000000000000000000000000000000000000000000000000000000001
    // Encoded Tokens           : 3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001
    // Final Hash               : b7398b1020c9fc9ecea32c3bdd18b471b814ed9a1a142addb0ef5bde2fab7c07
    //
    #[test]
    fn test_domain_separator_hash_fuel_address() {

        //NOTE - See Note 1
        let mut fuel_verifying_contract = [0x00; 32];
        fuel_verifying_contract[31] = 0x01;
        let verifying_contract_32byte = H256::from_slice(fuel_verifying_contract.as_slice());

        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: verifying_contract_32byte,
        };
        let domain_separator_hash = domain.domain_separator_hash();
        println!("Domain Separator Hash : 0x{}", hex::encode(domain_separator_hash));

        let expected_domain_separator_hash = hex::decode("b7398b1020c9fc9ecea32c3bdd18b471b814ed9a1a142addb0ef5bde2fab7c07").unwrap();
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
        pub from: H256,
        pub to: H256,
        pub contents: String,
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

            // let type_hash_encoded = Self::type_hash();
            // println!("type_hash_encoded     : {}", hex::encode(type_hash_encoded));


            // Encode: return from --> H256
            // 2.
            // let from_encoded_hash = Self::manual_encode_h256(&self.from);
            // println!("from_encoded_hash     : {}", hex::encode(from_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.from));


            // Encode: return to --> H256
            // 3.
            // let to_encoded_hash = Self::manual_encode_h256(&self.to);
            // println!("to_encoded_hash       : {}", hex::encode(to_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.to));


            // Encode: Command --> String:
            // 4.
            // let contents_encoded_hash = Self::manual_encode_string(&self.contents);
            // println!("contents_encoded_hash : {}", hex::encode(contents_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_string(&self.contents));


            // encoded bytes
            // println!("encoded: {}", hex::encode(&encoded));
            // println!(" ");

            let encoded_hash = keccak256(encoded);
            // println!("encoded struct hash   : {}", hex::encode(&encoded_hash));
            // println!(" ");

            encoded_hash
        }


    }


    // cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_struct_hash_for_mail --exact --show-output
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

        let mail_data_struct_hash = mail_data.struct_hash();
        println!("Mail data hash: 0x{}", hex::encode(mail_data_struct_hash));
        let expected_struct_hash = hex::decode("23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775").unwrap();

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
            let hash = keccak256(digest_input);

            Ok(hash)
        }
    }

    // cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_final_encoding_for_mail --exact --show-output
    #[test]
    fn test_final_encoding_for_mail() {

        // Setup signer domain:
        //
        // let domain = SRC16Domain {
        //     name: "MyDomain".to_string(),
        //     version: "1".to_string(),
        //     chain_id: 9889,
        //     verifying_contract: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        // };

        //NOTE - See Note 1
        let mut fuel_verifying_contract = [0x00; 32];
        fuel_verifying_contract[31] = 0x01;
        let verifying_contract_32byte = H256::from_slice(fuel_verifying_contract.as_slice());

        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: verifying_contract_32byte,
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
        let expected_final_encoded_hash = hex::decode("97b74437f3c96315f4156ced725a7ccc085dcfef9cde7e7a810806a93ee98032").unwrap();

        assert_eq!(encoded_hash, expected_final_encoded_hash.as_slice());
    }



}
