library;

use std::{
    bytes::Bytes,
    string::String,
};

use src16::{TypedDataHash, DataEncoder};

/// A generated struct representing a Mail message
pub struct Mail {

    /// The from field
    pub from: b256,
    /// The to field
    pub to: b256,
    /// The contents field
    pub contents: String,
}


/// The Keccak256 hash of the type Mail as UTF8 encoded bytes.
///
/// "Mail(bytes32 from,bytes32 to,string contents)"
///
/// cfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056
///
const Mail_TYPE_HASH: b256 = 0xcfc972d321844e0304c5a752957425d5df13c3b09c563624a806b517155d7056;

impl TypedDataHash for Mail {
    fn struct_hash(self) -> b256 {
        let mut encoded = Bytes::new();
        // Add the Mail type hash.
        encoded.append(
            Mail_TYPE_HASH.to_be_bytes()
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

