library;

use std::{
    bytes::Bytes,
    hash::*,
    string::String,
};
use ::hex::*;

use standards::src16::{
    SRC16Base,
    SRC16Domain,
    EIP712Domain,
    DomainHash,
    TypedDataHash,
    DataEncoder,
    SRC16Payload
};



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

// forc test src16_test_002_contract_id_conversion --logs
//
#[test]
fn src16_test_002_contract_id_conversion() {

    //                                      32-20 -->| |<-- 19-0
    //                                               | |
    let contract_id: b256 = 0xaBaAa9a8a7a6a5a4a3a2a1a0c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
                        //  0x000000000000000000000000c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
    let result = get_last_20_bytes(contract_id);
    log(b256_to_hex(result));

    // Verify the first 12 bytes are zero and last 20 bytes match input
    let expected = 0x000000000000000000000000c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;
    assert(result == expected);
}







// --- Test hashing of Domain Separator:

// forc test src16_boiler_src16_domain_hash --logs
// test the calculation of domain hash that exists in the standard
#[test]
fn src16_boiler_src16_domain_hash(){

    let dummy_contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;

    let domain_type_hash = SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        dummy_contractid
    ).domain_hash();
    // log(b256_to_hex(domain_type_hash));

    let expected_domain_hash: b256 = 0xb7398b1020c9fc9ecea32c3bdd18b471b814ed9a1a142addb0ef5bde2fab7c07;
    assert(domain_type_hash == expected_domain_hash );
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

// forc test src16_boiler_eip712_domain_hash --logs
// test the calculation of domain hash that exists in the standard
#[test]
fn src16_boiler_eip712_domain_hash(){

    let dummy_contractid: b256 = 0xaBaAa9a8a7a6a5a4a3a2a1a0c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0;

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

        // 8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a1000000000000000000000000c3c2c1c0bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0


// --- Test encoding of data:

// forc test src16_encode_data --logs
//
#[test]
fn src16_encode_data(){


    // test String --> b256 encoding:
    let a0 = String::from_ascii_str("ThisIsAStringToEncode");
    let expected_a0: b256 = 0xeb1507b54449cc939071613359d36b27b0451c1f95d78f85206f9d5ae09c9d41;
    let a0_encoded = DataEncoder::encode_string(a0);
    // log(b256_to_hex(a0_encoded));
    assert_eq(a0_encoded, expected_a0);

    // test u8 --> b256 encoding:
    let expected_a1 = 0x00000000000000000000000000000000000000000000000000000000000000fe;
    let a1_encoded = DataEncoder::encode_u8(0xfe);
    // log(b256_to_hex(a1_encoded));
    assert_eq(a1_encoded, expected_a1);

    // test u16 --> b256 encoding:
    let expected_a2 = 0x000000000000000000000000000000000000000000000000000000000000fedc;
    let a2_encoded = DataEncoder::encode_u16(0xfedc);
    // log(b256_to_hex(a2_encoded));
    assert_eq(a2_encoded, expected_a2);

    // test u32 --> b256 encoding:
    let expected_a3 = 0x00000000000000000000000000000000000000000000000000000000fedcba98;
    let a3_encoded = DataEncoder::encode_u32(0xfedcba98);
    // log(b256_to_hex(a3_encoded));
    assert_eq(a3_encoded, expected_a3);

    // test u64 --> b256 encoding:
    let expected_a4 = 0x000000000000000000000000000000000000000000000000fedcba9876543210;
    let a4_encoded = DataEncoder::encode_u64(0xfedcba9876543210);
    // log(b256_to_hex(a4_encoded));
    assert_eq(a4_encoded, expected_a4);

    // test bytes32 --> b256 encoding:
    let expected_a5: b256 = 0x0000000000000004000000000000000300000000000000020000000000000001;
    let a5_encoded = DataEncoder::encode_bytes32(
        asm(r1: (
            0x0000000000000004,
            0x0000000000000003,
            0x0000000000000002,
            0x0000000000000001
        )) { r1: b256 }
    );
    // log(b256_to_hex(a5_encoded));
    assert_eq(a5_encoded, expected_a5);

    // test u8 array encoding
    let mut u8_array = Vec::new();
    u8_array.push(0x11);
    u8_array.push(0x22);
    u8_array.push(0x33);
    let u8_array_encoded = DataEncoder::dynamic_u8_array(u8_array);
    let expected_u8_array = 0x7f654b5c8bf6519cddb680bf8bf2f6fc0b22e04163af6d4ac782a35c35847278;
    // log(b256_to_hex(u8_array_encoded));
    assert_eq(u8_array_encoded, expected_u8_array);

    // test u16 array encoding
    let mut u16_array = Vec::new();
    u16_array.push(0x1111);
    u16_array.push(0x2222);
    u16_array.push(0x3333);
    let u16_array_encoded = DataEncoder::dynamic_u16_array(u16_array);
    let expected_u16_array = 0xe8e5c44ce696b88a9e483474eeb6cba3c90977f0eaa142ee13367332fe5c4609;
    // log(b256_to_hex(u16_array_encoded));
    assert_eq(u16_array_encoded, expected_u16_array);

    // test u32 array encoding
    let mut u32_array = Vec::new();
    u32_array.push(0x11111111);
    u32_array.push(0x22222222);
    u32_array.push(0x33333333);
    let u32_array_encoded = DataEncoder::dynamic_u32_array(u32_array);
    let expected_u32_array = 0xf7728e843b9578d6c9af74e17d8a1a329001b36778ca4be39e1a53e035506e51;
    // log(b256_to_hex(u32_array_encoded));
    assert_eq(u32_array_encoded, expected_u32_array);

    // test u64 array encoding
    let mut u64_array = Vec::new();
    u64_array.push(0x1111111111111111);
    u64_array.push(0x2222222222222222);
    u64_array.push(0x3333333333333333);
    let u64_array_encoded = DataEncoder::dynamic_u64_array(u64_array);
    let expected_u64_array = 0x22be7762140084dcfec082523ca6f216ebc1bc1c7e498eb97c066e304883d931;
    // log(b256_to_hex(u64_array_encoded));
    assert_eq(u64_array_encoded, expected_u64_array);

    // test dynamic array encoding:
    let mut b256_array = Vec::new();
    b256_array.push(0x1111111111111111111111111111111111111111111111111111111111111111);
    b256_array.push(0x2222222222222222222222222222222222222222222222222222222222222222);
    b256_array.push(0x3333333333333333333333333333333333333333333333333333333333333333);
    let array_encoded = DataEncoder::dynamic_bytes32_array(b256_array);
    let expected_array = 0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573;
    // log(b256_to_hex(array_encoded));
    assert_eq(array_encoded, expected_array);

    // test bool --> b256 encoding:
    // boolean true case
    let expected_a11 = asm(r1: (
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000001
        )) { r1: b256 };
    let a11_encoded = DataEncoder::encode_bool(true);
    // log(b256_to_hex(a5_encoded));
    assert_eq(a11_encoded, expected_a11);
    // boolean false case
    let expected_a12 = asm(r1: (
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000,
            0x0000000000000000
        )) { r1: b256 };
    let a12_encoded = DataEncoder::encode_bool(false);
    // log(b256_to_hex(a5_encoded));
    assert_eq(a12_encoded, expected_a12);

    // Test address --> b256 encoding
    let expected_a13 = asm(r1: (
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
        0x4444444444444444 )) { r1: b256 };
    let a13_address = Address::from(expected_a13);
    let a13_encoded = DataEncoder::encode_address(a13_address);
    // log(b256_to_hex(a13_encoded));
    assert_eq(a13_encoded, expected_a13);

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
    fn struct_hash(self) -> b256 {

        let mut encoded = Bytes::new();
        /*
        log(String::from_ascii_str("Mail type hash (b256):"));
        log(b256_to_hex(MAIL_TYPE_HASH));

        log(String::from_ascii_str("encode_bytes32 self.from (b256):"));
        let g1 = TypedDataEncoder::encode_bytes32(self.from);
        log(b256_to_hex(g1));

        log(String::from_ascii_str("encode_bytes32 self.to (b256):"));
        let g2 = TypedDataEncoder::encode_bytes32(self.to);
        log(b256_to_hex(g2));

        log(String::from_ascii_str("encode_string self.contents (string):"));
        let g3 = TypedDataEncoder::encode_string(self.contents);
        log(b256_to_hex(g3));

        log(String::from_ascii_str("final hash:"));
        let g4 = keccak256(encoded);
        log(b256_to_hex(g4));
        */
        // Use the TypedDataEncoder to encode each field
        encoded.append(
            MAIL_TYPE_HASH.to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_bytes32(self.from).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_bytes32(self.to).to_be_bytes()
        );
        encoded.append(
            DataEncoder::encode_string(self.contents).to_be_bytes()
        );

        keccak256(encoded)
    }
}

// forc test src16_demo_typed_data_hash --logs
//
// type_hash_encoded     : cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
// from_encoded_hash     : abababababababababababababababababababababababababababababababab
// to_encoded_hash       : cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
// contents_encoded_hash : 4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
// encoded: cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056ababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8
//
// encoded struct hash   : 23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775
//
// https://emn178.github.io/online-tools/keccak_256.html?input=cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056ababababababababababababababababababababababababababababababababcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd4b67b2460d3b59a13388999b0d9cdabf6678d03f749051fed0c303f77e2f2de8&input_type=hex&output_type=hex
//
#[test]
fn src16_demo_typed_data_hash(){

    let mail_data = get_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();
    let expected_mail_encoded_hash = 0x23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775;

    log(b256_to_hex(mail_encoded_hash));
    assert(mail_encoded_hash == expected_mail_encoded_hash );
}


// test setup params for a populated Mail struct.
fn get_mail_test_params() -> Mail {

    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: from_addr,
        to: to_addr,
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
    let dummy_contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let domain = SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        dummy_contractid
    );

    // Create the mail struct:
    //
    let mail_data = get_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();

    let expected_final_hash = 0x97b74437f3c96315f4156ced725a7ccc085dcfef9cde7e7a810806a93ee98032;

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

// forc test eip712_demo_encode_hash --logs
//
#[test]
fn eip712_demo_encode_hash(){

    // Setup signer domain:
    //
    let dummy_contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;
    let domain = EIP712Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        (asm(r1: (0, 0, 0, 9889u64)) { r1: u256 }),
        dummy_contractid
    );

    // Create the mail struct:
    //
    let mail_data = get_mail_test_params();
    let mail_encoded_hash = mail_data.struct_hash();

    let expected_final_hash = 0xd79278fa19b574f4b6e3fcbde0cd55576cdbfed7ad5b098fc2b60b5fe9aa75ff;

    let payload = SRC16Payload {
        domain: domain,
        data_hash: mail_encoded_hash,
    };

    match payload.encode_hash() {
        Some(hash) => {
            log(b256_to_hex(hash));
            // assert(hash == expected_final_hash );
        },
        None => {
            revert(445u64);
        }
    }
}
