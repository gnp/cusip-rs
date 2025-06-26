//! JSON Schema generation support for CUSIP and CINS identifiers.
//!
//! This module provides [JSON Schema](https://json-schema.org/) generation for the CUSIP type
//! via the [schemars](https://crates.io/crates/schemars) crate. The generated schemas describe
//! valid CUSIP formats and can be used for validation, documentation, and code generation.
//!
//! The schema validates that CUSIP values are strings matching the expected format:
//! - 9 characters in length
//! - Uppercase alphanumeric characters only (A-Z, 0-9)
//!
//! # Examples
//!
//! Generate a JSON Schema for the CUSIP type:
//!
//! ```
//! use cusip::CUSIP;
//! use schemars::schema_for;
//!
//! let schema = schema_for!(CUSIP);
//! let json = serde_json::to_string_pretty(&schema).unwrap();
//! println!("{}", json);
//! ```

use crate::CUSIP;
use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject, SingleOrVec, StringValidation},
    JsonSchema,
};

impl JsonSchema for CUSIP {
    fn schema_name() -> String {
        "CUSIP".to_string()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        // CUSIP identifiers are 9-character strings with uppercase alphanumeric characters
        let schema = SchemaObject {
            instance_type: Some(SingleOrVec::Single(Box::new(InstanceType::String))),
            string: Some(Box::new(StringValidation {
                pattern: Some("^[0-9A-Z]{9}$".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        schema.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schemars::schema_for;

    #[test]
    fn schema_generation() {
        let schema = schema_for!(CUSIP);
        let schema_json = serde_json::to_value(&schema).unwrap();
        assert_eq!(schema_json["title"], "CUSIP");
    }

    #[test]
    fn schema_validation() {
        let schema = schema_for!(CUSIP);
        let compiled = jsonschema::Validator::new(&serde_json::to_value(&schema).unwrap()).unwrap();

        // Valid CUSIPs
        let valid_values = vec![
            serde_json::json!("09739D100"), // Boise Cascade
            serde_json::json!("023135106"), // Amazon.com Inc
            serde_json::json!("S08000AA9"), // CINS example
            serde_json::json!("837649128"), // Example from standard
        ];

        for value in valid_values {
            let result = compiled.validate(&value);
            assert!(result.is_ok(), "Expected {:?} to be valid", value);
        }

        // Invalid CUSIPs
        let invalid_values = vec![
            serde_json::json!("09739D10"),   // Too short
            serde_json::json!("09739D1000"), // Too long
            serde_json::json!("09739d100"),  // Lowercase
            serde_json::json!("09739D10!"),  // Invalid character
            serde_json::json!(""),           // Empty
            serde_json::json!(123456789),    // Number instead of string
            serde_json::json!(null),         // Null
        ];

        for value in invalid_values {
            let result = compiled.validate(&value);
            assert!(result.is_err(), "Expected {:?} to be invalid", value);
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn schema_matches_serde() {
        use serde_json::Value;

        let schema = schema_for!(CUSIP);
        let compiled = jsonschema::Validator::new(&serde_json::to_value(&schema).unwrap()).unwrap();

        // Test cases that serde can deserialize
        let test_cases = vec![
            "09739D100", // Boise Cascade
            "023135106", // Amazon.com Inc
            "S08000AA9", // CINS example
            "837649128", // Example from standard
        ];

        for cusip_str in test_cases {
            // Verify serde can deserialize it
            let cusip: CUSIP =
                serde_json::from_value(Value::String(cusip_str.to_string())).unwrap();

            // Verify schema accepts the serialized form
            let serialized = serde_json::to_value(cusip).unwrap();
            let result = compiled.validate(&serialized);
            assert!(
                result.is_ok(),
                "Schema should accept serde-serialized CUSIP: {}",
                cusip_str
            );
        }
    }

    #[test]
    fn struct_with_cusip_roundtrip() {
        #[derive(schemars::JsonSchema)]
        #[allow(dead_code)]
        struct Security {
            cusip: CUSIP,
            name: String,
        }

        let schema = schema_for!(Security);
        let compiled = jsonschema::Validator::new(&serde_json::to_value(&schema).unwrap()).unwrap();

        let valid_security = serde_json::json!({
            "cusip": "09739D100",
            "name": "Boise Cascade"
        });

        let result = compiled.validate(&valid_security);
        assert!(result.is_ok(), "Schema should accept valid Security object");

        let invalid_security = serde_json::json!({
            "cusip": "invalid",
            "name": "Test Corp"
        });

        let result = compiled.validate(&invalid_security);
        assert!(
            result.is_err(),
            "Schema should reject Security with invalid CUSIP"
        );
    }
}
