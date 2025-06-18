use cusip::CUSIP;

fn main() {
    let cusip: CUSIP = "023135106".parse().unwrap();

    let serialized = serde_json::to_string(&cusip).unwrap();
    println!("Serialized CUSIP: {}", serialized);

    let deserialized: CUSIP = serde_json::from_str(&serialized).unwrap();

    println!("Deserialized CUSIP: {}", deserialized); // "023135106"
    println!("  Issuer number: {}", deserialized.issuer_num()); // "023135"
    println!("  Issue number: {}", deserialized.issue_num()); // "10"
    println!("  Check digit: {}", deserialized.check_digit()); // '6'
    assert_eq!(cusip, deserialized);
}
