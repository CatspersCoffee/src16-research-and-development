use std::str::FromStr;
use hex;
use ethers::core::abi::{AbiDecode, Token, ParamType};
use ethers::core::types::{Address, U256, Bytes, H256, U64};
use ethers::utils::rlp;

use ethers::prelude::*;


use ethers_core::types::transaction::eip712::EIP712Domain;



// #[cfg(test)]

pub mod tests_eip712_module07 {

    use super::*;


    // use abi::Tokenizable;
    // use ethers::abi::{AbiEncode, AbiType, ParamType, Token};

    use ethers::abi::{AbiEncode, AbiType, ParamType, Token, Tokenizable};

    // use abi::{Tokenizable, AbiEncode, AbiType, ParamType, Token};

    use ethers_core::types::{
        transaction::eip712::{
            EIP712Domain, Eip712, EIP712_DOMAIN_TYPE_HASH,
            EIP712_DOMAIN_TYPE_HASH_WITH_SALT,
        },
        Address as EthAddress, H160, U256,
    };


    #[derive(Eip712, Clone, Debug, EthAbiType)]
    #[eip712(
        name = "ZapGasSponsor",
        version = "1",
        chain_id = 9889,
        verifying_contract = "0x0000000000000000000000000000000000000001"
    )]
    struct GasSponsor {
        command: String,
        returnaddress: H256,
        inputgasutxoid: H256,
        expectedgasoutputamount: U256,
        expectedoutputasset: H256,
        expectedoutputamount: U256,
        tolerance: U256,
    }



    // // cargo test --package evm-related --lib -- eip712_module07_v2::tests_eip712_module07::test_eip712_by_ethers_m07_command_sponsor --exact --show-output
    // #[tokio::test]

    pub async fn test_eip712_by_ethers_m07_command_sponsor()  {
        /*
        /// struct params for a sponsor with expected swap
        /// set command to "sponsor" and specify the utxoid available, the expected
        /// gas return amount, the expected assetid tip, amount and tolerance.

        Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
        Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
        Struct Hash      : 0xa65e39f42cb8baa1cbfb61bf9eefa5e2270dea0e517ee3219383f78bd508af08
        Encoded EIP-712  : 0xa28538cffc96e9113fb8766fcf1c9fbca316504e8b5bd0e17c5335fbf7d563fd
        */

        // Create the sponsor tx struct
        let dummy_command = "sponsor".to_string();

        let return_address = [0xAB; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());

        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());

        let dummy_gas_amount_out = U256::from(1_000_000_000u64);

        let asset_out = [02u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());

        let dummy_amount_out = U256::from(2_000_000_000u64);

        let dummy_tollerance = U256::from(250u64);


        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };

        // Create a wallet from a private key
        let private_key = "0xa45f8875ccb5e0a756e5e65f509b372356bdee7699cc6236a417ad8f8d2a3839"; // public: 0x333339d42a89028ee29a9e9f4822e651bac7ba14
        let wallet_from_key = LocalWallet::from_str(private_key).unwrap();

        // For this example, we'll use the wallet created from the private key
        let wallet = wallet_from_key.with_chain_id(1u64);

        // Sign the transaction
        let sig = wallet.sign_typed_data(&tx).await.expect("failed to sign typed data");

        println!("Signature: {:?}", sig);

        // Extract r, s, v from the signature
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        sig.r.to_big_endian(&mut r);
        sig.s.to_big_endian(&mut s);
        let v = sig.v as u8;

        // Verify the components of the EIP-712 structure
        let domain_separator = tx.domain().unwrap().separator();
        let type_hash = GasSponsor::type_hash().unwrap();
        let struct_hash = tx.struct_hash().unwrap();

        let encoded = tx.encode_eip712().unwrap();

        // Print out the results for verification
        println!("Wallet Address   : {}", hex::encode(wallet.address()));
        println!(" ");
        println!("Domain Separator : 0x{}", hex::encode(domain_separator));
        println!("Type Hash        : 0x{}", hex::encode(type_hash));
        println!("Struct Hash      : 0x{}", hex::encode(struct_hash));
        println!("Encoded EIP-712  : 0x{}", hex::encode(encoded));
        println!(" ");
        println!("Signature (r)    : 0x{}", hex::encode(r));
        println!("Signature (s)    : 0x{}", hex::encode(s));
        println!("Signature (v)    : {}", v);

        // Verify the signature
        let signer = sig.recover(encoded).expect("failed to recover signer");
        println!("Signer: {}", hex::encode(signer));

        assert_eq!(signer, wallet.address(), "Recovered signer does not match the wallet address");
    }

    // cargo test --package evm-related --lib -- eip712_module07_v2::tests_eip712_module07::test_eip712_by_ethers_m07_command_gasspass --exact --show-output
    #[tokio::test]
    async fn test_eip712_by_ethers_m07_command_gasspass()  {
        /*
        /// Struct params for a sponsor with no swap expected, but does require some gas difference
        /// only the command is set to "gasspass" and expect gas output amount, everything else should be zero'd

        Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
        Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
        Struct Hash      : 0x75b8150553bc268aa10fd86011656ca87aa239b103539f8af8d480a51a2818fa
        Encoded EIP-712  : 0xcccd067a02c854748838898c68a5c14b3b3a72e31a88e6d76dbb26158d740a91
        */

        // Create the sponsor tx struct
        let dummy_command = "gasspass".to_string();

        let return_address = [0xAB; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());

        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());

        let dummy_gas_amount_out = U256::from(1_000_000_000u64);

        let asset_out = [00u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());

        let dummy_amount_out = U256::from(0u64);

        let dummy_tollerance = U256::from(0u64);


        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };

        // Create a wallet from a private key
        let private_key = "0xa45f8875ccb5e0a756e5e65f509b372356bdee7699cc6236a417ad8f8d2a3839"; // public: 0x333339d42a89028ee29a9e9f4822e651bac7ba14
        let wallet_from_key = LocalWallet::from_str(private_key).unwrap();

        // For this example, we'll use the wallet created from the private key
        let wallet = wallet_from_key.with_chain_id(1u64);

        // Sign the transaction
        let sig = wallet.sign_typed_data(&tx).await.expect("failed to sign typed data");

        println!("Signature: {:?}", sig);

        // Extract r, s, v from the signature
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        sig.r.to_big_endian(&mut r);
        sig.s.to_big_endian(&mut s);
        let v = sig.v as u8;

        // Verify the components of the EIP-712 structure
        let domain_separator = tx.domain().unwrap().separator();
        let type_hash = GasSponsor::type_hash().unwrap();
        let struct_hash = tx.struct_hash().unwrap();

        let encoded = tx.encode_eip712().unwrap();

        // Print out the results for verification
        println!("Wallet Address   : {}", hex::encode(wallet.address()));
        println!(" ");
        println!("Domain Separator : 0x{}", hex::encode(domain_separator));
        println!("Type Hash        : 0x{}", hex::encode(type_hash));
        println!("Struct Hash      : 0x{}", hex::encode(struct_hash));
        println!("Encoded EIP-712  : 0x{}", hex::encode(encoded));
        println!(" ");
        println!("Signature (r)    : 0x{}", hex::encode(r));
        println!("Signature (s)    : 0x{}", hex::encode(s));
        println!("Signature (v)    : {}", v);

        // Verify the signature
        let signer = sig.recover(encoded).expect("failed to recover signer");
        println!("Signer: {}", hex::encode(signer));

        assert_eq!(signer, wallet.address(), "Recovered signer does not match the wallet address");
    }

    // cargo test --package evm-related --lib -- eip712_module07_v2::tests_eip712_module07::test_eip712_by_ethers_m07_command_cancel --exact --show-output
    #[tokio::test]
    async fn test_eip712_by_ethers_m07_command_cancel()  {
        /*
        /// struct params for a cancellation.
        /// for use when the sponsor want to cancel the sponsorship utxo.
        /// only the command is set to "cancel", everything else should be zero'd

        Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
        Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
        Struct Hash      : 0x8100dd06753bfe78c3ce5344aea822f17d9549112cebe22a5d2b7e63545ce4ac
        Encoded EIP-712  : 0xa5308f4d457db8327fc2aa14d12ef7d2d3ea1f170f50a70273e2bddf412a3e82
        */

        // Create the sponsor tx struct
        let dummy_command = "cancel".to_string();

        let return_address = [0x00; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());

        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());

        let dummy_gas_amount_out = U256::from(0u64);

        let asset_out = [00u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());

        let dummy_amount_out = U256::from(0u64);

        let dummy_tollerance = U256::from(0u64);


        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };

        // Create a wallet from a private key
        let private_key = "0xa45f8875ccb5e0a756e5e65f509b372356bdee7699cc6236a417ad8f8d2a3839"; // public: 0x333339d42a89028ee29a9e9f4822e651bac7ba14
        let wallet_from_key = LocalWallet::from_str(private_key).unwrap();

        // For this example, we'll use the wallet created from the private key
        let wallet = wallet_from_key.with_chain_id(1u64);

        // Sign the transaction
        let sig = wallet.sign_typed_data(&tx).await.expect("failed to sign typed data");

        println!("Signature: {:?}", sig);

        // Extract r, s, v from the signature
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        sig.r.to_big_endian(&mut r);
        sig.s.to_big_endian(&mut s);
        let v = sig.v as u8;

        // Verify the components of the EIP-712 structure
        let domain_separator = tx.domain().unwrap().separator();
        let type_hash = GasSponsor::type_hash().unwrap();
        let struct_hash = tx.struct_hash().unwrap();

        let encoded = tx.encode_eip712().unwrap();

        // Print out the results for verification
        println!("Wallet Address   : {}", hex::encode(wallet.address()));
        println!(" ");
        println!("Domain Separator : 0x{}", hex::encode(domain_separator));
        println!("Type Hash        : 0x{}", hex::encode(type_hash));
        println!("Struct Hash      : 0x{}", hex::encode(struct_hash));
        println!("Encoded EIP-712  : 0x{}", hex::encode(encoded));
        println!(" ");
        println!("Signature (r)    : 0x{}", hex::encode(r));
        println!("Signature (s)    : 0x{}", hex::encode(s));
        println!("Signature (v)    : {}", v);

        // Verify the signature
        let signer = sig.recover(encoded).expect("failed to recover signer");
        println!("Signer: {}", hex::encode(signer));

        assert_eq!(signer, wallet.address(), "Recovered signer does not match the wallet address");
    }


}


/*

    //
    //
    // EIP-712 Typed Data
    //   |
    //   |------------------- EIP-712 prefix ----------------->|
    //   |                                                     |
    //   |----> Domain Separator                               |
    //   |        |                                            |
    //   |        |----> Domain Hash ------------------------->|
    //   |                                                     |
    //   |                                                     |
    //   |        |----> Type Hash ---->|                      |
    //   |        |                     |                      |
    //   |------->|                     +----> Struct Hash --->|
    //            |                     |                      |
    //            |---- Struct Data --->|                      |
    //                                                         |
    //                                                         |
    //          Encode EIP-712 <-------------------------------+
    //                |
    //                |
    //                v
    //          Sign keccak256(Encode EIP-712).
    //



*/

// cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07 --show-output
pub mod custom_712_module07 {
    use crate::crypto_helpers;

    use super::*;
    use ethers::utils::keccak256;
    use std::collections::BTreeMap;
    use ethers::abi::{Token, encode};
    use ethers::types::transaction::eip712::encode_eip712_type;

    // use crate::crypto::*;

    /// Pre-computed value of the following expression:
    ///
    /// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address
    /// verifyingContract)")`
    pub const EIP712_DOMAIN_TYPE_HASH: [u8; 32] = [
        139, 115, 195, 198, 155, 184, 254, 61, 81, 46, 204, 76, 247, 89, 204, 121, 35, 159, 123, 23,
        155, 15, 250, 202, 169, 167, 93, 82, 43, 57, 64, 15,
    ];
    // from the ethers-contract/tests/solidity-contracts/DeriveEip712Test.sol
    // const EIP712_DOMAIN_TYPEHASH: [u8; 32] = keccak256(
    //     b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    // );

    //--------------------------------------------------
    // 1. Define the domain separator
    // This struct represents the EIP712Domain
    struct DebugEIP712Domain {
        name: String,
        version: String,
        chain_id: u64,
        verifying_contract: Address,
    }

    impl DebugEIP712Domain {

        /*
        // Domain Separator Hash Calculation
        //
        // 1. Start with empty result
        // result = []
        //
        // 2. Add EIP712_DOMAIN_TYPE_HASH
        // result += EIP712_DOMAIN_TYPE_HASH
        //
        // 3. Add hash of name
        // result += keccak256(bytes(name))
        //
        // 4. Add hash of version
        // result += keccak256(bytes(version))
        //
        // 5. Add chainId (as 32-byte big-endian)
        // result += uint256(chainId).to_be_bytes()
        //
        // 6. Add verifyingContract (as 20-byte address)
        // result += address(verifyingContract)
        //
        // 7. Compute final hash
        // domain_separator = keccak256(result)
        */
        fn domain_separator_hash_4(&self) -> [u8; 32] {

            let mut tokens = Vec::new();

            // 1. Add EIP712_DOMAIN_TYPE_HASH
            let token1 = Token::Uint(U256::from(EIP712_DOMAIN_TYPE_HASH));
            println!("EIP712_DOMAIN_TYPE_HASH      : {}", hex::encode(EIP712_DOMAIN_TYPE_HASH));
            println!("EIP712_DOMAIN_TYPE_HASH Token: {:?}", token1);
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
        https://emn178.github.io/online-tools/keccak_256.html?input=8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f66834a862a0f3e61bc1ede225d0f26b3b93dc33a0962ed512034712a71ad63b5c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001&input_type=hex&output_type=hex

        8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f --> EIP712_DOMAIN_TYPE_HASH
        66834a862a0f3e61bc1ede225d0f26b3b93dc33a0962ed512034712a71ad63b5 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract

        2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08 --> final hash
        */

    }

    //--------------------------------------------------
    // 2. Define the struct for which we're creating a signature

    #[derive(Clone, Debug)]
    struct GasSponsor {
        command: String,
        returnaddress: H256,
        inputgasutxoid: H256,
        expectedgasoutputamount: U256,
        expectedoutputasset: H256,
        expectedoutputamount: U256,
        tolerance: U256,
    }

    impl GasSponsor {

        fn type_hash() -> [u8; 32] {
            let type_string = "GasSponsor(string command,bytes32 returnaddress,bytes32 inputgasutxoid,uint256 expectedgasoutputamount,bytes32 expectedoutputasset,uint256 expectedoutputamount,uint256 tolerance)";
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

        fn manual_encode_eip712_array<T>(array: &[T], encoder: fn(&T) -> [u8; 32]) -> [u8; 32] {
            let mut encoded = Vec::with_capacity(array.len() * 32);
            for item in array {
                encoded.extend_from_slice(&encoder(item));
            }

            // println!("---------------------------------------manual_encode_eip712_array:");
            // println!("encoded: {}", hex::encode(&encoded));
            // println!("---------------------------------------manual_encode_eip712_array");

            keccak256(encoded)
        }


        // manually calcualte struct hash
        fn struct_hash(&self) -> [u8; 32] {
            let mut encoded = Vec::new();

            // Encode: type hash
            // 1.
            encoded.extend_from_slice(&Self::type_hash());

            let type_hash_encoded = Self::type_hash();
            println!("type_hash_encoded                         : {}", hex::encode(type_hash_encoded));

            // Encode: Command --> String:
            // 2.
            //
            //
            let command_encoded_hash = Self::manual_encode_string(&self.command);
            println!("command_encoded_hash                      : {}", hex::encode(command_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_string(&self.command));


            // Encode: return address --> H256
            // 3.
            //
            //
            let return_address_encoded_hash = Self::manual_encode_h256(&self.returnaddress);
            println!("return_address_encoded_hash               : {}", hex::encode(return_address_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.returnaddress));


            // Encode: input gas utxoid --> H256
            // 4.
            //
            //
            let input_gas_utxoid_encoded_hash = Self::manual_encode_h256(&self.inputgasutxoid);
            println!("input_gas_utxoid_encoded_hash             : {}", hex::encode(input_gas_utxoid_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.inputgasutxoid));



            // Encode: Expected Gas Output Amount --> U256
            // 5.
            //
            //
            let expected_gas_output_amount_encoded_hash = Self::manual_encode_u256(&self.expectedgasoutputamount);
            println!("expected_gas_output_amount_encoded_hash   : {}", hex::encode(expected_gas_output_amount_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_u256(&self.expectedgasoutputamount));


            // Encode: Expected Output Asset --> H256
            // 6.
            //
            //
            let expected_output_asset_encoded_hash = Self::manual_encode_h256(&self.expectedoutputasset);
            println!("expected_output_asset_encoded_hash        : {}", hex::encode(expected_output_asset_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_h256(&self.expectedoutputasset));



            // Encode: Expected Output Amount --> U256
            // 7.
            //
            //
            let expected_output_amount_encoded_hash = Self::manual_encode_u256(&self.expectedoutputamount);
            println!("input_output_amount_encoded_hash          : {}", hex::encode(expected_output_amount_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_u256(&self.expectedoutputamount));


            // Encode tolerance (is a u64 extended value to 256-bits), big-endian encoded.
            // 8. Tolerance (32 bytes), No special encoding applied to a singular value.
            //
            let tolerance_encoded_hash = Self::manual_encode_u256(&self.tolerance);
            println!("tolerance_encoded_hash                    : {}", hex::encode(tolerance_encoded_hash));

            encoded.extend_from_slice(&Self::manual_encode_u256(&self.tolerance));



            println!("encoded    : {}", hex::encode(&encoded));
            println!(" ");

            let encoded_hash = keccak256(encoded);

            println!("encoded struct hash                       : {}", hex::encode(&encoded_hash));
            println!(" ");

            encoded_hash
        }

    }



    //--------------------------------------------------
    // 7. sign types data

    use ethers::signers::{LocalWallet, Signer};

    struct SimpleSigner {
        wallet: LocalWallet
    }

    impl SimpleSigner {

        async fn sign_typed_data_2<T: DebugEip712>(&self, payload: &T) -> Result<Signature, WalletError> {
            let encoded_hash = payload.encode_eip712().map_err(|e| e.to_string()).unwrap();

            println!("encoded_hash: {}", hex::encode(encoded_hash));
            println!(" ");

            let hash = H256::from(encoded_hash);
            let s = self.wallet.sign_hash(hash);
            s


        }
    }

    // Simplified Eip712 trait
    trait DebugEip712 {
        fn encode_eip712(&self) -> Result<[u8; 32], String>;
    }

    impl DebugEip712 for (DebugEIP712Domain, GasSponsor) {
        fn encode_eip712(&self) -> Result<[u8; 32], String> {
            let (domain, tx) = self;
            let domain_separator = domain.domain_separator_hash_4();
            let struct_hash = tx.struct_hash();

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


    /*
    Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
    Type Hash        : 0xbbf829f5506241b26d58fff32c209df1b76ef88e07c3eeafc707d5e199c2fb4b
    Struct Hash      : 0x8b996a142db60dc78f14267c32a9f92bd93bc164d5921e0a5880dae864bd5d03
    Encoded EIP-712  : 0x8997dec7cd4683dc2d6490d7d0833416d41d36634f00b5f2ef0b12799c6b4c54
    */

    // cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07::test_domain_separator_hash --exact --show-output
    #[test]
    fn test_domain_separator_hash() {
        let domain = DebugEIP712Domain {
            name: "ZapGasSponsor".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        };
        let domain_separator_hash_4 = domain.domain_separator_hash_4();
        println!("Domain Separator Hash 4: 0x{}", hex::encode(domain_separator_hash_4));
        let domain_separator_hash = hex::decode("2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08").unwrap();
        assert_eq!(domain_separator_hash_4, domain_separator_hash.as_slice());
    }

    // cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07::test_calculate_type_hash --exact --show-output
    #[test]
    fn test_calculate_type_hash() {

        let typehash2 = GasSponsor::type_hash();
        println!("Type hash: 0x{}", hex::encode(typehash2));

        // https://emn178.github.io/online-tools/keccak_256.html?input=GasSponsor(string%20command%2Cbytes32%20inputgasutxoid%2Cuint256%20expectedgasoutputamount%2Cbytes32%20expectedoutputasset%2Cuint256%20expectedoutputamount%2Cuint256%20tolerance)&input_type=utf-8&output_type=hex

        let expected_type_hash = hex::decode("bbf829f5506241b26d58fff32c209df1b76ef88e07c3eeafc707d5e199c2fb4b").unwrap();
        assert_eq!(typehash2, expected_type_hash.as_slice());
    }


    // cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07::test_struct_hash_command_sponsor --exact --show-output
    #[test]
    fn test_struct_hash_command_sponsor() {
        // struct params for a sponsor with expected swap
        // set command to "sponsor" and specify the utxoid available, the expected
        // gas return amount, the expected assetid tip, amount and tolerance.
        // Create the "sponsor" tx struct:

        let dummy_command = "sponsor".to_string();

        let return_address = [0xAB; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());
        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());
        let dummy_gas_amount_out = U256::from(1_000_000_000u64);
        let asset_out = [02u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());
        let dummy_amount_out = U256::from(2_000_000_000u64);
        let dummy_tollerance = U256::from(250u64);

        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };


        let struct_hash = tx.struct_hash();
        println!("Struct hash: 0x{}", hex::encode(struct_hash));
        let expected_struct_hash = hex::decode("a65e39f42cb8baa1cbfb61bf9eefa5e2270dea0e517ee3219383f78bd508af08").unwrap();
        assert_eq!(struct_hash, expected_struct_hash.as_slice());

    }

    // cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07::test_struct_hash_command_gasspass --exact --show-output
    #[test]
    fn test_struct_hash_command_gasspass() {
        // Struct params for a sponsor with no swap expected.
        // only the command is set to "gasspass", everything else should be zero'd
        // Create the "gasspass" tx struct:

        let dummy_command = "gasspass".to_string();

        let return_address = [0xAB; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());
        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());
        let dummy_gas_amount_out = U256::from(1_000_000_000u64);
        let asset_out = [00u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());
        let dummy_amount_out = U256::from(0u64);
        let dummy_tollerance = U256::from(0u64);


        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };


        let struct_hash = tx.struct_hash();
        println!("Struct hash: 0x{}", hex::encode(struct_hash));
        let expected_struct_hash = hex::decode("75b8150553bc268aa10fd86011656ca87aa239b103539f8af8d480a51a2818fa").unwrap();
        assert_eq!(struct_hash, expected_struct_hash.as_slice());

    }

    // cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07::test_struct_hash_command_cancel --exact --show-output
    #[test]
    fn test_struct_hash_command_cancel() {
        // struct params for a cancellation.
        // for use when the sponsor want to cancel sponsor utxo.
        // only the command is set to "cancel", everything else should be zero'd

        let dummy_command = "cancel".to_string();

        let return_address = [0x00; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());
        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());
        let dummy_gas_amount_out = U256::from(0u64);
        let asset_out = [00u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());
        let dummy_amount_out = U256::from(0u64);
        let dummy_tollerance = U256::from(0u64);


        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };

        let struct_hash = tx.struct_hash();
        println!("Struct hash: 0x{}", hex::encode(struct_hash));
        let expected_struct_hash = hex::decode("8100dd06753bfe78c3ce5344aea822f17d9549112cebe22a5d2b7e63545ce4ac").unwrap();
        assert_eq!(struct_hash, expected_struct_hash.as_slice());

    }



    // cargo test --package evm-related --lib -- eip712_module07_v2::custom_712_module07::test_encoded_and_sign_recover --exact --show-output
    #[tokio::test]
    async fn test_encoded_and_sign_recover() {
        // Setup
        let domain = DebugEIP712Domain {
            name: "ZapGasSponsor".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: Address::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        };

        let dummy_command = "sponsor".to_string();

        let return_address = [0xAB; 32];
        let dummy_return_address = H256::from_slice(return_address.as_ref());
        let utxoid_in = [01u8; 32];
        let dummy_gas_utxoid_in = H256::from_slice(utxoid_in.as_ref());
        let dummy_gas_amount_out = U256::from(1_000_000_000u64);
        let asset_out = [02u8; 32];
        let dummy_asset_out = H256::from_slice(asset_out.as_ref());
        let dummy_amount_out = U256::from(2_000_000_000u64);
        let dummy_tollerance = U256::from(250u64);


        let tx = GasSponsor {
            command: dummy_command,
            returnaddress: dummy_return_address,
            inputgasutxoid: dummy_gas_utxoid_in,
            expectedgasoutputamount: dummy_gas_amount_out,
            expectedoutputasset: dummy_asset_out,
            expectedoutputamount: dummy_amount_out,
            tolerance: dummy_tollerance,
        };

        // Convert expected gas output amount to 32 bytes
        let mut bytes1 = [0u8; 32];
        tx.expectedgasoutputamount.to_big_endian(&mut bytes1);
        println!("gas expected amount out U256 value                  : {}", tx.expectedgasoutputamount);
        println!("gas expected amount out 32-byte representation (hex): {}", hex::encode(bytes1));
        println!(" ");

        // Convert expected gas output amount to 32 bytes
        let mut bytes2 = [0u8; 32];
        tx.expectedoutputamount.to_big_endian(&mut bytes2);
        println!("amount output asset U256 value                      : {}", tx.expectedoutputamount);
        println!("amount output asset 32-byte representation (hex)    : {}", hex::encode(bytes2));
        let mut bytes3 = [0u8; 32];
        tx.tolerance.to_big_endian(&mut bytes2);
        println!("tolerance U256 value: {}", tx.tolerance);
        println!("tolerance 32-byte representation (hex): 0x{}", hex::encode(bytes3));


        let payload = (domain, tx);

        // Create a wallet from a private key
        // let private_key = "0x1234567890123456789012345678901234567890123456789012345678901234";  // public: 0x2e988a386a799f506693793c6a5af6b54dfaabfb
        let private_key = "0xa45f8875ccb5e0a756e5e65f509b372356bdee7699cc6236a417ad8f8d2a3839"; // public: 0x333339d42a89028ee29a9e9f4822e651bac7ba14
        let wallet_from_key = LocalWallet::from_str(private_key).unwrap();
        println!("Wallet Address: {}", hex::encode(wallet_from_key.address()));

        let signer = SimpleSigner{
            wallet: wallet_from_key,
        };
        let signature = signer.sign_typed_data_2(&payload).await.unwrap();
        let compact_sig = crypto_helpers::compact(&signature);

        println!("Signature  : {:?}", signature);
        println!("Compact Sig: {}", hex::encode(compact_sig));

        // Verify the signature
        let encoded_hash = payload.encode_eip712().unwrap();

        println!("encoded eip712hash    : {}", hex::encode(encoded_hash));

        /*
        /// set command to "sponsor" and specify the utxoid available, the expected

        Domain Separator : 0x2b764082318dc24789dfc7093f781ddb8648f8be834a51d6f4eb2293f6303f08
        Type Hash        : 0x12b061b07fda7c0cac0e0d57861c96710c33e8b914993843a5fec61b4047e3d8
        Struct Hash      : 0xa65e39f42cb8baa1cbfb61bf9eefa5e2270dea0e517ee3219383f78bd508af08
        Encoded EIP-712  : 0xa28538cffc96e9113fb8766fcf1c9fbca316504e8b5bd0e17c5335fbf7d563fd
        */

        let expected_eip712encoded_hash = hex::decode("a28538cffc96e9113fb8766fcf1c9fbca316504e8b5bd0e17c5335fbf7d563fd").unwrap();
        assert_eq!(encoded_hash, expected_eip712encoded_hash.as_slice());

        let recovered_signer = signature.recover(encoded_hash).expect("failed to recover signer");
        println!("Signer: {}", hex::encode(recovered_signer));

    }





    fn convert_hex_str_to_h256(hex_str: &str) -> [u8; 32] {
        let expected_struct_hash = hex::decode(hex_str).unwrap();
        let h256_slice = expected_struct_hash.as_slice();
        let mut h: [u8; 32] = [0x00; 32];
        h.copy_from_slice(h256_slice);


        h
    }

    const ASSET_IN_ID: &str = "648318bcc430e79e7e9f0d2087a00353912505ac8beb18661b8a1e6907f800a9";

    const UTXO_1: &str = "585a36b425eb9afcfadce25944486ac80a6ed5090aa1e76ca4176b3a8f230956";
    const UTXO_2: &str = "ff22400efac198dfa4a4a29d816a089d1f18c166663077a06ed7317b6c044551";

    const ASSET_OUT_ID: &str = "7701ab82f40441a90b39eaebdade54a4464f9c070678766bd2eda3f89e44a7c6";



}

