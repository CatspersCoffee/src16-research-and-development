library;

use std::{
    bytes::Bytes,
    hash::*,
    string::String,
};
use helpers::hex::*;

use standards::src16::{
    SRC16Base,
    SRC16Domain,
    EIP712Domain,
    DomainHash,
    TypedDataHash,
    DataEncoder,
    EncoderType,
    SRC16Payload
};




// --- Test hashing of Domain Separator:

// forc test src16_boiler_src16_domain_hash --logs
// test the calculation of domain hash that exists in the standard
#[test]
fn src16_boiler_src16_domain_hash(){

    let contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;

    let domain_type_hash = SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        ContractId::from(contractid),
    ).domain_hash();
    log(b256_to_hex(domain_type_hash));

    let expected_domain_hash: b256 = 0xa4a3e8ae873833c636439e06bda4dce44a171cc137900fc3af7aa26c6085b403;
    assert(domain_type_hash == expected_domain_hash );
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


// --- Test encoding and hashing of some typed data:

/// A demo struct representing a mail message
pub struct Mail {
    /// The sender's address
    pub from: Address,
    /// The recipient's address
    pub to: Address,
    /// The message contents
    pub contents: String,
}

/// The Keccak256 hash of "Mail(address from,address to,string contents)"
/// 536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67f
///
/// https://emn178.github.io/online-tools/keccak_256.html?input=Mail(bytes32%20from%2Cbytes32%20to%2Cstring%20contents)&input_type=utf-8&output_type=hex
///
const MAIL_TYPE_HASH: b256 = 0x536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67f;


impl TypedDataHash for Mail {

    fn type_hash() -> b256 {
        MAIL_TYPE_HASH
    }

    fn struct_hash(self) -> b256 {

        let mut encoded = Bytes::new();
        // Use the TypedDataEncoder to encode each field
        encoded.append(
            MAIL_TYPE_HASH.to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_address(self.from).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_address(self.to).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.contents).to_be_bytes()
        );

        keccak256(encoded)
    }
}

// forc test src16_demo_typed_data_hash --logs
//
// type_hash_encoded     : 536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67f
// from_encoded_hash     : abababababababababababababababababababababababababababababababab
// to_encoded_hash       : cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
// contents_encoded_hash : 4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
// encoded: 536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67fababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
//
// encoded struct hash   : 62d7ef9b8083d5789cc5631f3398ab2ed4e01644f4222716b8a487f351be2c37
//
// https://emn178.github.io/online-tools/keccak_256.html?input=https://emn178.github.io/online-tools/keccak_256.html?input=536e54c54e6699204b424f41f6dea846ee38ac369afec3e7c141d2c92c65e67fababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8&input_type=hex&output_type=hex&input_type=hex&output_type=hex
//
#[test]
fn src16_demo_typed_data_hash(){

    let mail_data = get_fuel_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();
    let expected_mail_encoded_hash = 0x62d7ef9b8083d5789cc5631f3398ab2ed4e01644f4222716b8a487f351be2c37;

    log(b256_to_hex(mail_encoded_hash));
    assert(mail_encoded_hash == expected_mail_encoded_hash );
}


// test setup params for a populated Mail struct.
// For Fuel using Address as the "address" type.
fn get_fuel_mail_test_params() -> Mail {

    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: Address::from(from_addr),
        to: Address::from(to_addr),
        contents: String::from_ascii_str("A message from Alice to Bob."),
    };

    mail_data
}

// --- Test Final encoded hash:

// forc test src16_demo_encode_hash --logs
//
#[test]
fn src16_demo_encode_hash(){

    // Setup signer domain:
    //
    let contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let domain = SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        ContractId::from(contractid),
    );

    // Create the mail struct:
    //
    let mail_data = get_fuel_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();

    let expected_final_hash = 0xdf830c4a36744c712c3057faf8142a8b56946d3319b7c7688310407d3fab0e96;

    let payload = SRC16Payload {
        domain: domain,
        data_hash: mail_encoded_hash,
    };

    match payload.encode_hash() {
        Some(hash) => {
            log(b256_to_hex(hash));
            assert(hash == expected_final_hash );
        },
        None => {
            revert(445u64);
        }
    }
}
