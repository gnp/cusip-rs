use cusip::CUSIP;

fn main() {
    let cusip: CUSIP = "023135106".parse().unwrap();
    println!("Parsed CUSIP: {}", cusip); // "023135106"
    println!("  Issuer number: {}", cusip.issuer_num()); // "023135"
    println!("  Issue number: {}", cusip.issue_num()); // "10"
    println!("  Check digit: {}", cusip.check_digit()); // '6'
}
