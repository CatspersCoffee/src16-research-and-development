
use crate::setup_env::setup_test_environment_fuelmailme;
use crate::interfaces::*;
use crate::helpers::*;

// cargo test --package test-mail-me --lib -- test_mail_me::test_mailme_encode_w_src16domain --exact --show-output
#[tokio::test]
pub async fn test_mailme_encode_w_src16domain() {

    let (_provider, mailme_cid, wallet) = setup_test_environment_fuelmailme::setup_assets_sdk_provider().await.unwrap();

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

    let encoded_hash_cc = mail_me_fuel_interface::call_send_mail_get_hash(
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
/*
    let encoded_hash_independent = src16domain_independent_encoder::get_encoded_hash_using_custom_encoder(mailme_contractid_array);

    println!("------------------------------------------------------------------ (custom encoder result):\n");
    println!("Should match above ⬆️ \n");
    println!("encoded hash custom encoder     : {}", hex::encode(encoded_hash_independent));
    println!("\n-------------------------------------------------------------------------------------------");

    assert_eq!(encoded_hash_cc, encoded_hash_independent);
*/
}


/*
pub mod src16domain_independent_encoder {

    use fuels::types::Bits256;
    use custom_src16_encoder::src16_v2::custom02_src16::*;

    /// Independently setup a SRC16Domain, Mail struct with populated data, and obtain
    /// the typed data hash.
    pub fn get_encoded_hash_using_custom_encoder(
        mailme_contractid: [u8; 32],
    ) -> [u8; 32] {

        // Setup signer domain:
        //
        let verifying_contract_32byte = Bits256(mailme_contractid);

        let domain = SRC16Domain {
            name: "MyDomain".to_string(),
            version: "1".to_string(),
            chain_id: 9889,
            verifying_contract: verifying_contract_32byte,
        };

        // Create the mail struct:
        //
        let from_address: [u8; 32] = [0xAB; 32];
        let dummy_from_address = Bits256(from_address);
        let to_address: [u8; 32] = [0xCD; 32];
        let dummy_to_address = Bits256(to_address);
        let dummy_contents = "A message from Alice to Bob.".to_string();

        let mail_data = Mail {
            from: dummy_from_address,
            to: dummy_to_address,
            contents: dummy_contents,
        };

        let payload = (domain, mail_data);
        let encoded_hash = payload.encode_src16().map_err(|e| e.to_string()).unwrap();

        encoded_hash
    }


}

*/