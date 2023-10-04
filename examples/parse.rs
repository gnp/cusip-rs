use cusip;

fn main() {
    let cusip_string = "023135106"; // Amazon.com Inc - Common Stock
    match cusip::parse(cusip_string) {
        Ok(cusip) => {
            println!("Parsed CUSIP: {}", cusip); // "023135106"
            println!("  Issuer number: {}", cusip.issuer_num()); // "023135"
            println!("  Issue number: {}", cusip.issue_num()); // "10"
            println!("  Check digit: {}", cusip.check_digit()); // '6'
        }
        Err(err) => panic!("Unable to parse CUSIP {}: {}", cusip_string, err),
    }
}
