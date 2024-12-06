use fuels::prelude::*;

pub fn convert_hex_string_to_address(hex_string: String) -> Address {
    let some_addr_bytes = hex::decode(hex_string).unwrap();
    let some_array: [u8; 32] = some_addr_bytes.try_into()
        .expect("slice has incorrect length");
    let some_addr = Address::from_bytes_ref(&some_array);

    some_addr.to_owned()
}


