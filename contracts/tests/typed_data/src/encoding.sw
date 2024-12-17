library;

use std::{
    bytes::Bytes,
    hash::*,
    string::String,
};
use helpers::hex::*;

use standards::src16::{
    TypedDataHash,
    DataEncoder,
    EncoderType
};


// --- Test encoding of data:

// forc test src16_encode_data --logs
//
// Examle encoding Big-Endian:
// let expected_a6: b256 = 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1;
//
//  Big-endian byte layout (32 bytes total):
//
//  Position:     00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31
//  Value:        ff fe fd fc fb fa f9 f8 f7 f6 f5 f4 f3 f2 f1 f0 ef ee ed ec eb ea e9 e8 e7 e6 e5 e4 e3 e2 e1 e0
//  Significance: ^^ Most significant byte                                                   Least significant ^^
//
//  Grouped as 8-byte chunks for asm:
//  (0xfffefdfcfbfaf9f8,  // bytes 0-7
//   0xf7f6f5f4f3f2f1f0,  // bytes 8-15
//   0xefeeedecebeae9e8,  // bytes 16-23
//   0xe7e6e5e4e3e2e1e0)  // bytes 24-31
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
    // let a2_encoded = DataEncoder::encode_u16(0xfedc);
    let a2_encoded = DataEncoder::encode_u16(65244u16);
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

    // test u256 --> b256 encoding:
    let expected_a5: b256 = 0x0000000000000004000000000000000300000000000000020000000000000001;
    let a5_encoded = DataEncoder::encode_u256(
        asm(r1: (
            0x0000000000000004,
            0x0000000000000003,
            0x0000000000000002,
            0x0000000000000001
        )) { r1: u256 }
    );
    // log(b256_to_hex(a5_encoded));
    assert_eq(a5_encoded, expected_a5);

    // test b256 --> b256 encoding:
    let expected_a6: b256 = 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0;
    let a6_encoded = DataEncoder::encode_b256(
        asm(r1: (
            0xfffefdfcfbfaf9f8,
            0xf7f6f5f4f3f2f1f0,
            0xefeeedecebeae9e8,
            0xe7e6e5e4e3e2e1e0
        )) { r1: b256 }
    );
    // log(b256_to_hex(a6_encoded));
    assert_eq(a6_encoded, expected_a6);

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

    // test dynamic u256 array encoding:
    let mut u256_array = Vec::new();
    u256_array.push(0x1111111111111111111111111111111111111111111111111111111111111111);
    u256_array.push(0x2222222222222222222222222222222222222222222222222222222222222222);
    u256_array.push(0x3333333333333333333333333333333333333333333333333333333333333333);
    let u256_array_encoded = DataEncoder::dynamic_b256_array(u256_array);
    let u256_expected_array = 0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573;
    // log(u256_to_hex(b256_array_encoded));
    assert_eq(u256_array_encoded, u256_expected_array);

    // test dynamic b256 array encoding:
    let mut b256_array = Vec::new();
    b256_array.push(0x1111111111111111111111111111111111111111111111111111111111111111);
    b256_array.push(0x2222222222222222222222222222222222222222222222222222222222222222);
    b256_array.push(0x3333333333333333333333333333333333333333333333333333333333333333);
    let b256_array_encoded = DataEncoder::dynamic_b256_array(b256_array);
    let b256_expected_array = 0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573;
    // log(b256_to_hex(b256_array_encoded));
    assert_eq(b256_array_encoded, b256_expected_array);

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

    // Test Address --> b256 encoding
    let expected_a13 = asm(r1: (
        0x1111111111111111,
        0x2222222222222222,
        0x3333333333333333,
        0x4444444444444444 )) { r1: b256 };
    let a13_address = Address::from(expected_a13);
    let a13_encoded = DataEncoder::encode_address(a13_address);
    // log(b256_to_hex(a13_encoded));
    assert_eq(a13_encoded, expected_a13);

    // Test ContractId --> b256 encoding
    let expected_a14 = asm(r1: (
        0x5555555555555555,
        0x6666666666666666,
        0x7777777777777777,
        0x8888888888888888 )) { r1: b256 };
    let a14_contractid = ContractId::from(expected_a14);
    let a14_encoded = DataEncoder::encode_contract_id(a14_contractid);
    // log(b256_to_hex(a14_encoded));
    assert_eq(a14_encoded, expected_a14);

    // Test Identity Address variant
    let expected_a15 = Address::from(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0);
    let a15_identity_address = Identity::Address(expected_a15);
    let a15_encoded_address = DataEncoder::encode_identity(a15_identity_address);
    // log(b256_to_hex(a15_encoded_address));
    assert_eq(a15_encoded_address, 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0);

    // Test Identity ContractId variant
    let expected_a16 = ContractId::from(0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0);
    let a16_identity_contract = Identity::ContractId(expected_a16);
    let a16_encoded_contract = DataEncoder::encode_identity(a16_identity_contract);
    // log(b256_to_hex(a16_encoded_contract));
    assert_eq(a16_encoded_contract, 0xfffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0);

}

// forc test src16_encode_fixed_aray --logs
//
#[test]
fn src16_encode_fixed_aray(){

    // test fixed string array encoding:
    // 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
    // 8452c9b9140222b08593a26daa782707297be9f7b3e8281d7b4974769f19afd0
    // e96f302788d6ba77f831293e5308c6a8543e125b1eed5edcecc9d56eb5a7c842
    // 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac88452c9b9140222b08593a26daa782707297be9f7b3e8281d7b4974769f19afd0e96f302788d6ba77f831293e5308c6a8543e125b1eed5edcecc9d56eb5a7c842
    // c354479b8018dfc78e54faf781f959121f6ee85e61262d92ca3bee451cf826cd
    // Start with fixed array of str (using correct array syntax)
    let test_strings = ["hello", "world", "sway"];  // [str; 3]
    let string_array: [String; 3] = [
        String::from_ascii_str(test_strings[0]),
        String::from_ascii_str(test_strings[1]),
        String::from_ascii_str(test_strings[2])
    ];
    let fa01_slice = raw_slice::from_parts::<String>(__addr_of(string_array), 3);
    let fa01_encoded = DataEncoder::encode_fixed_array(fa01_slice, EncoderType::String);
    // log(b256_to_hex(fa01_encoded));
    assert_eq(fa01_encoded, 0xc354479b8018dfc78e54faf781f959121f6ee85e61262d92ca3bee451cf826cd);

    // Test u8 array:
    // 0000000000000000000000000000000000000000000000000000000000000001
    // 0000000000000000000000000000000000000000000000000000000000000002
    // 0000000000000000000000000000000000000000000000000000000000000003
    // 000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000003
    // 6e0c627900b24bd432fe7b1f713f1b0744091a646a9fe4a65a18dfed21f2949c
    let u8_array: [u8; 3] = [1, 2, 3];
    let fa02_slice = raw_slice::from_parts::<u8>(__addr_of(u8_array), 3);
    let fa02_encoded = DataEncoder::encode_fixed_array(fa02_slice, EncoderType::U8);
    // log(b256_to_hex(fa02_encoded));
    assert_eq(fa02_encoded, 0x6e0c627900b24bd432fe7b1f713f1b0744091a646a9fe4a65a18dfed21f2949c);

    // Test u16 array:
    // 0000000000000000000000000000000000000000000000000000000000000100
    // 0000000000000000000000000000000000000000000000000000000000000101
    // 0000000000000000000000000000000000000000000000000000000000000102
    // 000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001010000000000000000000000000000000000000000000000000000000000000102
    // f6b5ace2d22e4b8444e275ff6138da0d51fd6d4112618cb42beaa71aa32276c6
    let u16_array: [u16; 3] = [256, 257, 258];
    let fa03_slice = raw_slice::from_parts::<u16>(__addr_of(u16_array), 3);
    let fa03_encoded = DataEncoder::encode_fixed_array(fa03_slice, EncoderType::U16);
    // log(b256_to_hex(fa03_encoded));
    assert_eq(fa03_encoded, 0xf6b5ace2d22e4b8444e275ff6138da0d51fd6d4112618cb42beaa71aa32276c6);

    // Test u32 array:
    // 0000000000000000000000000000000000000000000000000000000000010000
    // 0000000000000000000000000000000000000000000000000000000000010001
    // 0000000000000000000000000000000000000000000000000000000000010002
    // 000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100010000000000000000000000000000000000000000000000000000000000010002
    // 6bac0b74b317eaf6699c6317c288e7c63110b7e94005cb614c668e7de9c88d84
    let u32_array: [u32; 3] = [65536, 65537, 65538];
    let fa04_slice = raw_slice::from_parts::<u32>(__addr_of(u32_array), 3);
    let fa04_encoded = DataEncoder::encode_fixed_array(fa04_slice, EncoderType::U32);
    // log(b256_to_hex(fa04_encoded));
    assert_eq(fa04_encoded, 0x6bac0b74b317eaf6699c6317c288e7c63110b7e94005cb614c668e7de9c88d84);

    // Test u64 array:
    // 0000000000000000000000000000000000000000000000000000000100000000
    // 0000000000000000000000000000000000000000000000000000000100000001
    // 0000000000000000000000000000000000000000000000000000000100000002
    // 000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000010000000000000000000000000000000000000000000000000000000100000002
    // 651f1983f9ec6baebd1c7743c66fb8c188d65a9946f1d00e46aeb124514bf144
    let u64_array: [u64; 3] = [4294967296, 4294967297, 4294967298];
    let fa05_slice = raw_slice::from_parts::<u64>(__addr_of(u64_array), 3);
    let fa05_encoded = DataEncoder::encode_fixed_array(fa05_slice, EncoderType::U64);
    // log(b256_to_hex(fa05_encoded));
    assert_eq(fa05_encoded, 0x651f1983f9ec6baebd1c7743c66fb8c188d65a9946f1d00e46aeb124514bf144);

    // Test u256 array:
    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
    let u256_array: [u256; 3] = [
        u256::from(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff),
        u256::from(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe),
        u256::from(0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd)
    ];
    let fa06_slice = raw_slice::from_parts::<u256>(__addr_of(u256_array), 3);
    let fa06_encoded = DataEncoder::encode_fixed_array(fa06_slice, EncoderType::U256);
    // log(b256_to_hex(fa06_encoded));
    assert_eq(fa06_encoded, 0x62016e7a171824b475a7f991899509be91098c47473e3b0dbead26608192e6a0);

    // Test b256 array:
    // fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
    let b256_array: [b256; 3] = [
        0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe,
        0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
    ];
    let fa07_slice = raw_slice::from_parts::<b256>(__addr_of(b256_array), 3);
    let fa07_encoded = DataEncoder::encode_fixed_array(fa07_slice, EncoderType::B256);
    // log(b256_to_hex(fa07_encoded));
    assert_eq(fa07_encoded, 0x62016e7a171824b475a7f991899509be91098c47473e3b0dbead26608192e6a0);

    // Test Address array:
    // 111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333
    let address_array: [Address; 3] = [
        Address::from(0x1111111111111111111111111111111111111111111111111111111111111111),
        Address::from(0x2222222222222222222222222222222222222222222222222222222222222222),
        Address::from(0x3333333333333333333333333333333333333333333333333333333333333333)
    ];
    let fa08_slice = raw_slice::from_parts::<Address>(__addr_of(address_array), 3);
    let fa08_encoded = DataEncoder::encode_fixed_array(fa08_slice, EncoderType::Address);
    assert_eq(fa08_encoded, 0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573);

    // Test ContractId array:
    let contract_id_array: [ContractId; 3] = [
        ContractId::from(0x1111111111111111111111111111111111111111111111111111111111111111),
        ContractId::from(0x2222222222222222222222222222222222222222222222222222222222222222),
        ContractId::from(0x3333333333333333333333333333333333333333333333333333333333333333)
    ];
    let fa09_slice = raw_slice::from_parts::<ContractId>(__addr_of(contract_id_array), 3);
    let fa09_encoded = DataEncoder::encode_fixed_array(fa09_slice, EncoderType::ContractId);
    assert_eq(fa09_encoded, 0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573);

    // Test Identity array:
    let identity_array: [Identity; 3] = [
        Identity::Address(Address::from(0x1111111111111111111111111111111111111111111111111111111111111111)),
        Identity::ContractId(ContractId::from(0x2222222222222222222222222222222222222222222222222222222222222222)),
        Identity::Address(Address::from(0x3333333333333333333333333333333333333333333333333333333333333333))
    ];
    let fa10_slice = raw_slice::from_parts::<Identity>(__addr_of(identity_array), 3);
    let fa10_encoded = DataEncoder::encode_fixed_array(fa10_slice, EncoderType::Identity);
    assert_eq(fa10_encoded, 0x41524791bda53e6da2158f10c15e3672835515d6135111d11c7e9880cfcbe573);


}

