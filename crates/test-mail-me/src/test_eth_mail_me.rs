use crate::setup_env::setup_test_environment_ethereummailme;
use crate::interfaces::*;
use crate::helpers::*;

use eip712_encoder::eip712_v1::eip712_encoder_v1;

// cargo test --package test-mail-me --lib -- test_eth_mail_me::test_mailme_encode_w_eip712domain --exact --show-output
#[tokio::test]
pub async fn test_mailme_encode_w_eip712domain() {

    let (_provider, mailme_cid, wallet) = setup_test_environment_ethereummailme::setup_assets_sdk_provider().await.unwrap();

    // println!("MailMe contractid                : {}", mailme_cid);

    let mut mailme_contractid_array: [u8; 32] = [0x00; 32];
    mailme_contractid_array.copy_from_slice(mailme_cid.as_slice());

    let rightmost_20_bytes = &mailme_contractid_array[12..32];
    println!("MailMe contractid (last 20 bytes): {}\n", hex::encode(rightmost_20_bytes));
    println!("MailMe contractid (last 20 bytes): {}", hex::encode(rightmost_20_bytes));
    println!("                                   ^");
    println!("                                   |");
    println!("                                   |");
    println!("    this value is hard coded  ------");
    println!("    into the EIP712Domain separator\n");
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

    let encoded_hash_independent = eip712_encoder_v1::eip712_get_static_varifying_contact_encode();

    println!("------------------------------------------------------------------ (eip712 encoder result):\n");
    println!("Should match above ⬆️ \n");
    println!("encoded hash eip712 encoder     : {}", hex::encode(encoded_hash_independent));
    println!("\n-------------------------------------------------------------------------------------------");

    assert_eq!(encoded_hash_cc, encoded_hash_independent);

}





