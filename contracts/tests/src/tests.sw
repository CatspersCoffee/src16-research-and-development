library;

use std::{
    bytes::Bytes,
    hash::*,
    string::String,
};
use ::hex::*;

use standards::src16::{
    SRC16,
    SRC16Domain,
    TypedDataHash,
    TypedDataEncoder,
    DefaultEncoder,
    SRC16Payload
};


// forc test src20_boiler_domain_hash --logs
// test the calculation of domain hash that exists in the standard
#[test]
fn src20_boiler_domain_hash(){

    let dummy_contractid: b256 = 0x0000000000000000000000000000000000000000000000000000000000000001;

    let domain_type_hash = SRC16Domain::new(
        String::from_ascii_str("MyDomain"),
        String::from_ascii_str("1"),
        9889u64,
        dummy_contractid
    ).domain_hash();
    log(b256_to_hex(domain_type_hash));

    let expected_domain_hash: b256 = 0xcdf6328e5f89cab9b3f1cae206af45e1ce8c9dde811e3c42717f44d9f8347ffb;
    assert(domain_type_hash == expected_domain_hash );
    /*
        https://emn178.github.io/online-tools/keccak_256.html?input=ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc600000000000000000000000000000000000000000000000000000000000026a10000000000000000000000000000000000000000000000000000000000000001&input_type=hex&output_type=hex

        ae9189d496944f7c643961cf1b7975c30fea464263ed19e76881ddb5625bb9bd --> SRC16_DOMAIN_TYPE_HASH
        49df7211c4cf1749975aefc051c32b30ddc90cbb9d8b1de59ba5c6eb5cb36b20 --> Name Hash
        c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6 --> Version Hash
        00000000000000000000000000000000000000000000000000000000000026a1 --> Chain ID
        0000000000000000000000000000000000000000000000000000000000000001 --> Verifying Contract

        cdf6328e5f89cab9b3f1cae206af45e1ce8c9dde811e3c42717f44d9f8347ffb --> final hash
    */
}

//--------------------------------------------------------------------------------------------------------------------------------------------------------
// Test encoding and hashing of some typed data:

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
        let g1 = DefaultEncoder::encode_bytes32(self.from);
        log(b256_to_hex(g1));

        log(String::from_ascii_str("encode_bytes32 self.to (b256):"));
        let g2 = DefaultEncoder::encode_bytes32(self.to);
        log(b256_to_hex(g2));

        log(String::from_ascii_str("encode_string self.contents (string):"));
        let g3 = DefaultEncoder::encode_string(self.contents);
        log(b256_to_hex(g3));

        log(String::from_ascii_str("final hash:"));
        let g4 = keccak256(encoded);
        log(b256_to_hex(g4));
        */
        // Use the DefaultEncoder to encode each field
        encoded.append(
            MAIL_TYPE_HASH.to_be_bytes()
        );
        encoded.append(
            DefaultEncoder::encode_bytes32(self.from).to_be_bytes()
        );
        encoded.append(
            DefaultEncoder::encode_bytes32(self.to).to_be_bytes()
        );
        encoded.append(
            DefaultEncoder::encode_string(self.contents).to_be_bytes()
        );

        keccak256(encoded)
    }
}

// forc test src20_demo_typed_data_hash --logs
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
fn src20_demo_typed_data_hash(){
    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: from_addr,
        to: to_addr,
        contents: String::from_ascii_str("A message from Alice to Bob."),
    };
    let mail_encoded_hash = mail_data.struct_hash();
    let expected_mail_encoded_hash = 0x23dd3d8fadde568374db0b57b0d5e17254b4df0abca45f56da433f5c97f49775;

    log(b256_to_hex(mail_encoded_hash));
    assert(mail_encoded_hash == expected_mail_encoded_hash );
}


// forc test src20_demo_encode_hash --logs
//
#[test]
fn src20_demo_encode_hash(){

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
    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: from_addr,
        to: to_addr,
        contents: String::from_ascii_str("A message from Alice to Bob."),
    };
    let mail_encoded_hash = mail_data.struct_hash();

    let expected_final_hash = 0xf625875586c6c393f389e320cfc1b5076ab4e836c90e09c2af155feefc69333d;

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