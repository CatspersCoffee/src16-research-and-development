use std::fs::File;
use std::io::Write;
use std::path::Path;

use serde_json::json;

use crate::src16_encoder2::keccak256;


pub fn generate_sway_struct_hash(type_name: &str, typed_data_json: &serde_json::Value) -> Result<String, Box<dyn std::error::Error>> {
    let types = typed_data_json["types"].as_object().ok_or("Invalid types")?;
    let type_fields = types.get(type_name).ok_or("Type not found")?;
    
    // First, generate the type hash string and compute its constant
    let type_string = type_fields.as_array()
        .unwrap()
        .iter()
        .map(|field| {
            format!("{} {}", 
                field["type"].as_str().unwrap(),
                field["name"].as_str().unwrap()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let full_type_string = format!("{}({})", type_name, type_string);
    let type_hash = keccak256(full_type_string.as_bytes());

    // Generate the Sway code
    let mut code = format!(r#"
/// The Keccak256 hash of the type {type_name} as UTF8 encoded bytes.
///
/// "{full_type_string}"
///
/// {type_hash_hex}
///
const {type_name}_TYPE_HASH: b256 = 0x{type_hash_hex};

impl TypedDataHash for {type_name} {{
    fn struct_hash(self) -> b256 {{
        let mut encoded = Bytes::new();
        // Add the {type_name} type hash.
        encoded.append(
            {type_name}_TYPE_HASH.to_be_bytes()
        );
"#, 
        type_name = type_name,
        full_type_string = full_type_string,
        type_hash_hex = hex::encode(type_hash)
    );

    // Generate encoding for each field
    for field in type_fields.as_array().unwrap() {
        let field_name = field["name"].as_str().unwrap();
        let field_type = field["type"].as_str().unwrap();
        
        let encoder_call = match field_type {
            "bytes32" => "encode_bytes32",
            "string" => "encode_string",
            "uint8" => "encode_u8",
            "uint16" => "encode_u16",
            "uint32" => "encode_u32",
            "uint64" => "encode_u64",
            "bool" => "encode_bool",
            "address" => "encode_bytes32", // For Fuel, addresses are 32 bytes
            _ => return Err("Unsupported type".into())
        };

        code.push_str(&format!(r#"
        encoded.append(
            DataEncoder::{encoder_call}(self.{field_name}).to_be_bytes()
        );"#,
            encoder_call = encoder_call,
            field_name = field_name
        ));
    }

    // Add the final hash computation
    code.push_str(r#"

        keccak256(encoded)
    }
}
"#);

    Ok(code)
}



pub fn generate_sway_file(type_name: &str, typed_data_json: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    // First generate the struct code
    let struct_code = format!(r#"/// A generated struct representing a {type_name} message
pub struct {type_name} {{
"#, type_name = type_name);

    // Generate struct fields
    let mut struct_fields = String::new();
    let types = typed_data_json["types"].as_object().ok_or("Invalid types")?;
    let type_fields = types.get(type_name).ok_or("Type not found")?;

    for field in type_fields.as_array().unwrap() {
        let field_name = field["name"].as_str().unwrap();
        let field_type = match field["type"].as_str().unwrap() {
            "bytes32" => "b256",
            "string" => "String",
            "uint8" => "u8",
            "uint16" => "u16",
            "uint32" => "u32",
            "uint64" => "u64",
            "bool" => "bool",
            "address" => "b256", // For Fuel, addresses are 32 bytes
            _ => return Err("Unsupported type".into())
        };

        struct_fields.push_str(&format!("    /// The {field_name} field\n    pub {field_name}: {field_type},\n"));
    }

    // Generate the struct hash implementation
    let impl_code = generate_sway_struct_hash(type_name, typed_data_json)?;

    // Combine all parts
    let full_code = format!(r#"library;

use std::{{
    bytes::Bytes,
    string::String,
}};

use src16::{{TypedDataHash, DataEncoder}};

{struct_code}
{struct_fields}}}

{impl_code}
"#);

    // Write to file
    let filename = format!("{}.sw", type_name.to_lowercase());
    let path = Path::new(&filename);
    let mut file = File::create(path)?;
    file.write_all(full_code.as_bytes())?;

    println!("Generated Sway file: {}", filename);
    Ok(())
}




// cargo test --package custom-src16-encoder --lib -- generate_struct_hash::test_generate_mail_file --exact --show-output
#[test]
fn test_generate_mail_file() {
    let json_data = json!({
        "types": {
            "Mail": [
                {"name": "from", "type": "bytes32"},
                {"name": "to", "type": "bytes32"},
                {"name": "contents", "type": "string"}
            ]
        }
    });

    generate_sway_file("Mail", &json_data).unwrap();
}



// Example usage:
#[test]
fn test_generate_mail_struct_hash() {
    let json_data = json!({
        "types": {
            "Mail": [
                {"name": "from", "type": "bytes32"},
                {"name": "to", "type": "bytes32"},
                {"name": "contents", "type": "string"}
            ]
        }
    });

    let generated_code = generate_sway_struct_hash("Mail", &json_data).unwrap();
    println!("Generated Sway code:\n{}", generated_code);
}