//! Example of generating JSON Schema for CUSIP type

use cusip::CUSIP;
use schemars::schema_for;

fn main() {
    // Generate the JSON schema for CUSIP
    let schema = schema_for!(CUSIP);

    // Convert to JSON and print
    let schema_json = serde_json::to_string_pretty(&schema).unwrap();
    println!("JSON Schema for CUSIP:");
    println!("{}", schema_json);
}
