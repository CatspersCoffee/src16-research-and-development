# Solidity vs Sway Type System Comparison

## Value Types / Primitive Types

| Solidity               | Sway                    | Notes                                        |
|------------------------|-------------------------|----------------------------------------------|
| `uint8` to `uint256`   | `u8` to `u256`          | Sway only has unsigned integers              |
| `int8` to `int256`     | ❌                      | Sway has no signed integers                  |
| `bool`                 | `bool`                  | Same in both                                 |
| `address`              | `Address`               | Sway's Address is a type-safe wrapper        |
| `bytes1` to `bytes32`  | `b256`                  | Sway only has b256 for fixed-size bytes      |
| `fixed/ufixed`         | ❌                      | Sway has no floating point types             |

## String Types

| Solidity               | Sway                    | Notes                                        |
|------------------------|-------------------------|----------------------------------------------|
| `string`               | `str`                   | Sway's string slice (reference type)         |
|                        | `str[]`                 | Sway's fixed-length string array             |
| `string memory`        | `String`                | Dynamic string type in Sway                  |

## Dynamic Types

| Solidity               | Sway                    | Notes                                        |
|------------------------|-------------------------|----------------------------------------------|
| `bytes`                | `Bytes`                 | Dynamic byte arrays                          |
| `T[]`                  | ❌                      | Sway doesn't have dynamic arrays             |

## Reference Types

| Solidity               | Sway                    | Notes                                        |
|------------------------|-------------------------|----------------------------------------------|
| `T[N]`                 | `[T; N]`                | Fixed-size arrays                            |
| `struct`               | `struct`                | Similar implementation                       |
| `mapping`              | `StorageMap`            | Different syntax but similar concept         |
| `enum`                 | `enum`                  | Similar implementation                       |

## Contract Types

| Solidity               | Sway                    | Notes                                        |
|------------------------|-------------------------|----------------------------------------------|
| `address`              | `ContractId`            | For contract references                      |
| `contract`             | `Contract`              | Contract type                                |
|                        | `Identity`              | Can be either Address or ContractId          |

## Key Differences

1. **Integer Types**:
   - Solidity: Both signed and unsigned
   - Sway: Only unsigned integers

2. **Bytes**:
   - Solidity: Has bytes1 to bytes32 plus dynamic bytes
   - Sway: Only has b256 and dynamic Bytes

3. **Arrays**:
   - Solidity: Both dynamic and fixed-size
   - Sway: Only fixed-size arrays

4. **Strings**:
   - Solidity: Single string type
   - Sway: Multiple string types (str, str[], String)

5. **Contract Identity**:
   - Solidity: Uses address for both contracts and EOAs
   - Sway: Separates Address and ContractId with Identity enum

6. **Storage**:
   - Solidity: Uses memory/storage keywords
   - Sway: Different memory model (no explicit memory/storage)

7. **Type Safety**:
   - Solidity: More implicit conversions
   - Sway: Stricter type system with explicit conversions