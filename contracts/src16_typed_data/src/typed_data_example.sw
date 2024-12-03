contract;

use standards::src16::{
    SRC16,
    SRC16Domain,
    TypedDataHash,
    TypedDataEncoder,
    DefaultEncoder,
    SRC16Payload,
};
use std::{
    bytes::Bytes,
    string::String,
    hash::*,
    contract_id::*,
};


configurable {
    /// The name of the signing domain.
    DOMAIN: str[8] = __to_str_array("MyDomain"),
    /// The current major version for the signing domain.
    VERSION: str[1] = __to_str_array("1"),
    /// The active chain ID where the signing is intended to be used.
    CHAIN_ID: u64 = 9889u64,
    // The address of the contract that will be verifying the signature.
    // VERIFYING_CONTRACT: b256 = 0x0000000000000000000000000000000000000000000000000000000000000000,
}


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
        // Add the Mail type hash.
        encoded.append(
            MAIL_TYPE_HASH.to_be_bytes()
        );
        // Use the DefaultEncoder to encode each field for known types
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


impl SRC16 for Contract {

    fn domain_separator() -> SRC16Domain {
        get_domain_separator()
    }

    fn domain_separator_hash() -> b256 {
        get_domain_separator().domain_hash()
    }

    fn data_struct_hash() -> b256 {
        // populate some Mail and hash
        get_some_mail().struct_hash()
    }

    fn encode(data_hash: b256) -> Option<b256> {
        let payload = SRC16Payload {
            domain: get_domain_separator(),
            data_hash: data_hash,
        };
        payload.encode_hash()
    }

}

abi MailMe {
    fn send_mail_get_hash(
        from_addr: b256,
        to_addr: b256,
        contents: String,
    ) -> b256;
}

impl MailMe for Contract {

    /// Sends a some mail and returns its encoded hash
    ///
    /// # Arguments
    ///
    /// * `from_addr`: [b256] - The sender's address
    /// * `to_addr`: [b256] - The recipient's address
    /// * `contents`: [String] - The message contents
    ///
    /// # Returns
    ///
    /// * [b256] - The encoded hash of the mail data
    fn send_mail_get_hash(
        from_addr: b256,
        to_addr: b256,
        contents: String,
    ) -> b256 {
        // Create the mail struct
        let mail = Mail {
            from: from_addr,
            to: to_addr,
            contents: contents,
        };

        // Get the struct hash
        let data_hash = mail.struct_hash();

        // Get the encoded hash
        // match encode(data_hash) {
        //     Some(hash) => hash,
        //     None => revert(0),
        // }

        b256::zero()
    }

}



fn get_domain_separator() -> SRC16Domain {
    SRC16Domain::new(
        String::from_ascii_str(from_str_array(DOMAIN)),
        String::from_ascii_str(from_str_array(VERSION)),
        CHAIN_ID,
        ContractId::this().into()
    )
}

fn get_some_mail() -> Mail {
    // populate demo Mail struct.
    let from_addr: b256 = 0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB;
    let to_addr: b256 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD;
    let mail_data = Mail {
        from: from_addr,
        to: to_addr,
        contents: String::from_ascii_str("A message from Alice to Bob."),
    };
    mail_data
}




