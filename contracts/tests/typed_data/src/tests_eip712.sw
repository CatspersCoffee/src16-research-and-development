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



// --- Test logic for extracting rightmost 20 bytes from ContractID:

fn get_last_20_bytes(input: b256) -> b256 {
    // Convert b256 to Bytes.
    let input_bytes: Bytes = input.into();
    // Create a new Bytes with 32 byte capacity that will hold the result
    let mut result_bytes = Bytes::with_capacity(32);
    // Fill first 12 bytes with zeros
    let mut i = 0;
    while i < 12 {
        result_bytes.push(0);
        i += 1;
    }
    // Take the last 20 bytes from original
    let (_, last_20) = input_bytes.split_at(12);
    // Append the last 20 bytes to the zeroed bytes
    result_bytes.append(last_20);
    result_bytes.into()
}

// forc test src16_test_contract_id_conversion --logs
//
#[test]
fn src16_test_contract_id_conversion() {
    //                                      32-20 -->| |<-- 19-0
    //                                               | |
    let contract_id: b256 = 0xaBaAa9a8a7a6a5a4a3a2a1a0c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
                        //  0x000000000000000000000000c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
    let cid = ContractId::from(contract_id);
    let result = get_last_20_bytes(cid.bits());
    log(b256_to_hex(result));

    // Verify the first 12 bytes are zero and last 20 bytes match input
    let expected = 0x000000000000000000000000c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
    assert(result == expected);
}


// --- Test hashing of Domain Separator:

// forc test src16_boiler_eip712_domain_hash --logs
// test the calculation of domain hash that exists in the standard
#[test]
fn src16_boiler_eip712_domain_hash(){

    let contractid: b256 = 0xaBaAa9a8a7a6a5a4a3a2a1a0c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
    let dummy_contractid = ContractId::from(contractid);

    let domain_type_hash = EIP712Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }),
        dummy_contractid
    ).domain_hash();
    log(b256_to_hex(domain_type_hash));

    let expected_domain_hash: b256 = 0xcb9a66789a8ba14900b75c28e57bf7c54d6c97b0a2aa18503bc216cf481ab976;
    assert(domain_type_hash == expected_domain_hash );
    /*
        https://emn178.github.io/online-tools/keccak_256.html?input=3d99520d68918c39d115c0b17ba8454c1723175ecf4b38d25528fe0a117db78e49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001&input_type=hex&output_type=hex

        8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f --> EIP712_DOMAIN_TYPE_HASH
        49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        000000000000000000000000c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0 --> Verifying Contract

        cb9a66789a8ba14900b75c28e57bf7c54d6c97b0a2aa18503bc216cf481ab976 --> final hash
    */
}


// --- Test encoding and hashing of some typed data:

/// A demo struct representing a mail message
pub struct Mail {
    /// The sender's address
    pub from: b256,
    /// The recipient's address
    pub to: b256,
    /// The message contents
    pub contents: String,
}

/// The Keccak256 hash of "Mail(bytes32 from,bytes32 to,string contents)"
/// cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
///
/// https://emn178.github.io/online-tools/keccak_256.html?input=Mail(bytes32%20from%2Cbytes32%20to%2Cstring%20contents)&input_type=utf-8&output_type=hex
///
const MAIL_TYPE_HASH: b256 = 0xcfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056;


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
            DataEncoder::encode_b256(self.from).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_b256(self.to).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.contents).to_be_bytes()
        );

        keccak256(encoded)
    }
}

// forc test eip712_demo_typed_data_hash --logs
//
// type_hash_encoded     : cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
// from_encoded_hash     : abababababababababababababababababababababababababababababababab
// to_encoded_hash       : cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
// contents_encoded_hash : 4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
// encoded: cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056ababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
//
// encoded struct hash   : 23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775
//
// https://emn178.github.io/online-tools/keccak_256.html?input=https://emn178.github.io/online-tools/keccak_256.html?input=cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056ababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8&input_type=hex&output_type=hex&input_type=hex&output_type=hex
//
#[test]
fn eip712_demo_typed_data_hash(){

    let mail_data = get_ether_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();
    let expected_mail_encoded_hash = 0x23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775;

    log(b256_to_hex(mail_encoded_hash));
    assert(mail_encoded_hash == expected_mail_encoded_hash );
}

// test setup params for a populated Mail struct.
// For Ethereum, using bytes32 (b256) as the "address" type.
fn get_ether_mail_test_params() -> Mail {

    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: from_addr,
        to: to_addr,
        contents: String::from_ascii_str("A message from Alice to Bob."),
    };

    mail_data
}


// --- Test Final EIP712 encoded hash:

// forc test eip712_demo_encode_hash --logs
//
#[test]
fn eip712_demo_encode_hash(){

    // Setup signer domain:
    //
    // let dummy_1_contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let dummy_2_contractid: b256 = 0xaBaAa9a8a7a6a5a4a3a2a1a0c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
    let dummy_contractid = ContractId::from(dummy_2_contractid);

    let domain = EIP712Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }),
        dummy_contractid
    );

    // Create the mail struct:
    //
    let mail_data = get_ether_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();

    // let expected_1_final_hash = 0xd79278fa19b574f4b6e3fcbde0cd55576cdbfed7ad5b098fc2b60b5fe9aa75ff;
    let expected_2_final_hash = 0x6183587447d2aa038cf08cc1eac45c166a8f329b401a459c0ce9fc2252356c9c;

    let payload = SRC16Payload {
        domain: domain,
        data_hash: mail_encoded_hash,
    };

    match payload.encode_hash() {
        Some(hash) => {
            // log(b256_to_hex(hash));
            assert(hash == expected_2_final_hash );
        },
        None => {
            revert(445u64);
        }
    }
}
