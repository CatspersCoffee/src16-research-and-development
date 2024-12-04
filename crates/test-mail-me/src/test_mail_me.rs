use fuels::prelude::*;
//         Address, ContractId,
//     },
//     types::{
//         Bits256, EvmAddress, Bytes32, B512,
//     },
//     accounts::wallet::WalletUnlocked,
// };

use crate::setup_env::setup_test_environment::*;
use crate::interfaces::mail_me_interface::call_send_mail_get_hash;


// cargo test --package test-mail-me --lib -- test_mail_me::test_mailme_encode --exact --show-output
#[tokio::test]
pub async fn test_mailme_encode() {

    let (_provider, mailme_cid, wallet) = setup_assets_sdk_provider().await.unwrap();

    println!("MailMe contractid: {}", mailme_cid);

    let mut mailme_contractid_array: [u8; 32] = [0x00; 32];
    mailme_contractid_array.copy_from_slice(mailme_cid.as_slice());

    /*
    // this is the same struct setup as in /contracts/tests/src/tests.sw

    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: from_addr,
        to: to_addr,
        contents: String::from_ascii_str("A message from Alice to Bob."),
    };

    */

    let from_alice_addr = convert_hex_string_to_address("ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB".to_string());
    let to_bob_addr = convert_hex_string_to_address("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD".to_string());

    let message = "A message from Alice to Bob.".to_string();

    let encoded_hash_cc = call_send_mail_get_hash(
        mailme_cid,
        &wallet,
        from_alice_addr,
        to_bob_addr,
        message,
    ).await;
    println!("------------------------------------------------------------------- (contract call result):\n");

    println!("encoded hash from contract call : {}", hex::encode(encoded_hash_cc));

    println!("\nShould match below ⬇️");
    println!("\n-------------------------------------------------------------------------------------------");

    let encoded_hash_independent = src16_independent_encoder::get_encoded_hash_using_custom_encoder(mailme_contractid_array);

    println!("------------------------------------------------------------------ (custom encoder result):\n");
    println!("Should match above ⬆️ \n");
    println!("encoded hash custom encoder     : {}", hex::encode(encoded_hash_independent));
    println!("\n-------------------------------------------------------------------------------------------");

    assert_eq!(encoded_hash_cc, encoded_hash_independent);
}



pub mod src16_independent_encoder {

    // use std::str::FromStr;
    use ethers::core::types::{
        // Address as EthAddress,
        H256 as EthH256,
    };
    use custom_src16_encoder::src16_v1::custom01_src16::*;


    /// Independently setup a SRC16Domain, Mail struct with populated data, and obtain
    /// the typed data hash.
    pub fn get_encoded_hash_using_custom_encoder(
        mailme_contractid: [u8; 32],
    ) -> [u8; 32] {

        // Setup signer domain:
        //
        // let domain = SRC16Domain {
        //     name: "MyDomain".to_string(),
        //     version: "1".to_string(),
        //     chain_id: 9889,
        //     verifying_contract: EthAddress::from_str("0x0000000000000000000000000000000000000001").unwrap(),
        // };

        //NOTE - See Note 1 in crates/custom-src16-encoder/src/src16_v1.rs
        //
        let verifying_contract_32byte = EthH256::from_slice(mailme_contractid.as_slice());

        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: verifying_contract_32byte,
        };

        // Create the mail struct:
        //
        let from_address = [0xAB; 32];
        let dummy_from_address = EthH256::from_slice(from_address.as_ref());
        let to_address = [0xCD; 32];
        let dummy_to_address = EthH256::from_slice(to_address.as_ref());
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

        encoded_hash
    }


}






fn convert_hex_string_to_address(hex_string: String) -> Address {
    let some_addr_bytes = hex::decode(hex_string).unwrap();
    let some_array: [u8; 32] = some_addr_bytes.try_into()
        .expect("slice has incorrect length");
    let some_addr = Address::from_bytes_ref(&some_array);

    some_addr.to_owned()
}


