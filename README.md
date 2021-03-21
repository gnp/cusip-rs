cusip
====
An `CUSIP` type for working with validated International Security Identifiers (CUSIPs) as defined by [ANSI X9.6-2020]
(https://webstore.ansi.org/standards/ascx9/ansix92020).


## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
cusip = "0.1"
```


## Example

```rust
use cusip;
let cusip_string = "023135106"; // Amazon.com Inc - Common Stock
match cusip::parse_strict(cusip_string) {
    Ok(cusip) => {
        println!("Parsed CUSIP: {}", cusip.to_string()); // "023135106"
        println!("  Issuer number: {}", cusip.issuer_num()); // "023135"
        println!("  Issue number: {}", cusip.issue_num()); // "10"
        println!("  Check digit: {}", cusip.check_digit()); // '6'
    }
    Err(err) => panic!("Unable to parse CUSIP {}: {}", cusip_string, err),
}
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.


## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
