# src16-research-and-development

This is demo research and development project that utilizes SRC-16 Structured Typed Data within a Contact `MailMe` to encode a typed data struct `Mail` with data. The contract call returns the value of the encoded data hash with the user supplied data.


## Run MailMe Contract call:

This calls the function `send_mail_get_hash()` in a deployed `MailMe` example contract with the data for a `Mail` struct. The
contract Utilizes SRC-16 to encode and hash the contents to spec.
```console

cargo test --package test-mail-me --lib -- test_mail_me::test_mailme_encode --exact --show-output

```

## Ethers EIP712 Encoding Tests with logs:

SRC-16 Is also backwards compatible with EIP712 encoding
```console

cargo test --package test-mail-me --lib -- test_eth_mail_me::test_mailme_encode_w_eip712domain --exact --show-output
```

## SRC-16 Backwards Compatibility:

SRC-16 uses superabis in from Sway. This means that developers can use the `SRC16Domain` or `EIP712Domain` separators.

```sway
/// Base ABI interface for structured data hashing and signing
///
/// # Additional Information
///
/// This base ABI provides the common hashing functionality that is
/// shared between the Fuel (SRC16) and Ethereum (EIP712) implementations.
abi SRC16Base {

    fn domain_separator_hash() -> b256;

    fn data_type_hash() -> b256;
}

/// Fuel-specific implementation of structured data signing
///
/// # Additional Information
///
/// Extends SRC16Base with Fuel-specific domain separator handling using
/// "SRC16Domain(string name,string version,uint64 chainId,address verifyingContract)"
abi SRC16 : SRC16Base {
    /// Returns the domain separator struct for Fuel
    ///
    /// # Returns
    ///
    /// * [SRC16Domain] - The domain separator containing Fuel-specific parameters
    fn domain_separator() -> SRC16Domain;
}

/// Ethereum-compatible implementation of structured data signing
///
/// # Additional Information
///
/// Extends SRC16Base with Ethereum-compatible domain separator handling using
/// "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
abi EIP712 : SRC16Base {
    /// Returns the domain separator struct for Ethereum compatibility
    ///
    /// # Returns
    ///
    /// * [EIP712Domain] - The domain separator containing Ethereum-compatible parameters
    fn domain_separator() -> EIP712Domain;
}

```



## SRC-16 Tests with logs:

These tests validate the encoding schemes for the `SRC16Domain` Separator, Type hash and Data Encoding within SRC-16.

This uses only Fuel-rs related types and an external keccak256 crate, i.e., no Ethers-rs. i.e., A lite custom Token encoder for
this demo project has been made and simple encoding mechanics make it easy for developers to use this demo as a "how to".
```console

# Run domain type hash test:
cargo test --package custom-src16-encoder --lib -- src16_v2::custom02_src16::domain_type_hash --exact --show-output

# Run domain separator test with `demo` values:
cargo test --package custom-src16-encoder --lib -- src16_v2::custom02_src16::test_domain_separator_hash_fuel_address --exact --show-output

# Run structured hash for Mail data test:
cargo test --package custom-src16-encoder --lib -- src16_v2::custom02_src16::test_struct_hash_for_mail --exact --show-output

# Run full encoding and hash test for Domain and Mail struct with `demo` values:
cargo test --package custom-src16-encoder --lib -- src16_v2::custom02_src16::test_final_encoding_for_mail --exact --show-output

```

## Ethers EIP712 Encoding Tests with logs:


```console

# Run the Domain, Type, Struct and Final Encoding with the demo Mail values using ethers-rs:
cargo test --package eip712-encoder --lib -- eip712_v1::eip712_encoder_generic::test_eip712_final_encoding_for_mail --exact --show-output

# With the static contract address: verifying_contract = "0xc563dea1a8c6b7dace5a1412a26b8a71637b08a7"
cargo test --package eip712-encoder --lib -- eip712_v1::eip712_encoder_v1::test_eip712_final_encoding_for_mail --exact --show-output

```


## Compiling Contracts:

Use forc version:
```
forc 0.66.5
```

### Units tests for .sw files
```
$ forc test

# SRC-16 Specific Tests:
src16_test_contract_id_conversion
src16_boiler_src16_domain_hash
src16_boiler_eip712_domain_hash
src16_encode_data
src16_demo_typed_data_hash
src16_demo_encode_hash
eip712_demo_encode_hash

# You can also uncomment out the log()'s to see the actual data (use  --logs posfix ).

# Tests only for debugging helpers:
test_hex_conversions
test_b256_to_hex_string_conversion

```