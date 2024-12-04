# src16-research-and-development

This is demo research and development project that utilizes SRC-16 Structured Types Data within a Contact `MailMe` to encode a typed data struct `Mail` with data. The contract call returns the value of the encoded data hash.


## Run MailMe Contract call:

This calls the function `send_mail_get_hash()` in a deployed `MailMe` example contract with the data for a `Mail` struct. The
contract Utilizes SRC-16 to encode and hash the contents to spec.
```console

cargo test --package test-mail-me --lib -- test_mail_me::test_mailme_encode --exact --show-output

```

## Other Tests with logs:

These tests validate the encoding schemes for Domain Separator, Type hash and Data Encoding within SRC-16.
```console

# Run domain type hash test:
cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::domain_type_hash --exact --show-output


# Run domain separator test with `demo` values:
cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_domain_separator_hash_fuel_address --exact --show-output

# Run structured hash for Mail data test:
cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_struct_hash_for_mail --exact --show-output

# Run full encoding and hash test for Domain and Mail struct with `demo` values:
cargo test --package custom-src16-encoder --lib -- src16_v1::custom01_src16::test_final_encoding_for_mail --exact --show-output

```


# Compiling Contracts:

Use forc version:
```
forc 0.66.5
```