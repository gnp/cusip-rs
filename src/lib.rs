//! # cusip
//!
//! `cusip` provides a `CUSIP` type for working with validated Committee on Uniform Security
//! Identification Procedures (CUSIP) identifiers as defined in
//! [ANSI X9.6-2020](https://webstore.ansi.org/standards/ascx9/ansix92020).
//!
//! [CUSIP Global Services (CGS)](https://www.cusip.com/) has [a page describing CUSIP
//! identifiers](https://www.cusip.com/identifiers.html).
//!
//! A CUSIP is comprised of 9 ASCII characters with the following parts, in order:
//!
//! 1. A six-character upper-case alphanumeric _Issuer number_.
//! 2. A two-character upper-case alphanumeric _Issue number_.
//! 3. A single decimal digit representing the _check digit_ computed using what the standard calls
//! the "modulus 10 'double-add-double' technique".
//!
//! Use the `parse_loose()` or `parse_strict()` methods to convert a string to a
//! validated CUSIP.
//!
//! The ANSI standard defines three non-alphanumeric character values to support a special use for
//! the "PPN System". They are '*' (value 36), '@' (value 37) and '#' (value 38). These CUSIP's are
//! not supported by this crate because the additional characters are not supported by ISINs, and
//! CUSIPs are incorporated as the _security identifier_ for ISINs for certain _country codes_.

use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use bstr::ByteSlice;

pub mod checksum;

use checksum::checksum_table;

#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The input length is not exactly 9 bytes.
    InvalidLength { was: usize },
    /// The input issuer id is not six uppercase ASCII alphanumeric characters.
    InvalidIssuerId { was: [u8; 6] },
    /// The input issue id is not two uppercase ASCII alphanumeric characters.
    InvalidIssueId { was: [u8; 2] },
    /// The input check digit is not a single ASCII decimal digit character.
    InvalidCheckDigit { was: u8 },
    /// The input check digit has in a valid format, but has an incorrect value.
    IncorrectCheckDigit { was: u8, expected: u8 },
}

impl Debug for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidLength { was } => {
                write!(f, "InvalidLength {{ was: {:?} }}", was)
            }
            ParseError::InvalidIssuerId { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(f, "InvalidIssuerId {{ was: {:?} }}", s)
                }
                Err(_) => {
                    write!(f, "InvalidIssuerId {{ was: (invalid UTF-8) {:?} }}", was)
                }
            },
            ParseError::InvalidIssueId { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(f, "InvalidIssueId {{ was: {:?} }}", s)
                }
                Err(_) => {
                    write!(f, "InvalidIssueId {{ was: (invalid UTF-8) {:?} }}", was)
                }
            },
            ParseError::InvalidCheckDigit { was } => {
                write!(f, "InvalidCheckDigit {{ was: {:?} }}", char::from(*was))
            }
            ParseError::IncorrectCheckDigit { was, expected } => {
                write!(
                    f,
                    "IncorrectCheckDigit {{ was: {:?}, expected: {:?} }}",
                    char::from(*was),
                    char::from(*expected)
                )
            }
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::InvalidLength { was } => {
                write!(f, "invalid length {} bytes when expecting 9", was)
            }
            ParseError::InvalidIssuerId { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(
                        f,
                        "issuer id {:?} is not six uppercase ASCII alphanumeric characters",
                        s
                    )
                }
                Err(_) => {
                    write!(f,
                    "issuer id (invalid UTF-8) {:?} is not six uppercase ASCII alphanumeric characters",
                    was)
                }
            },
            ParseError::InvalidIssueId { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(
                        f,
                        "issue id {:?} is not two uppercase ASCII alphanumeric characters",
                        s
                    )
                }
                Err(_) => {
                    write!(f,
                "issue id (invalid UTF-8) {:?} is not two uppercase ASCII alphanumeric characters",
                    was)
                }
            },
            ParseError::InvalidCheckDigit { was } => {
                write!(
                    f,
                    "check digit {:?} is not one ASCII decimal digit",
                    *was as char
                )
            }
            ParseError::IncorrectCheckDigit { was, expected } => {
                write!(
                    f,
                    "incorrect check digit {:?} when expecting {:?}",
                    char::from(*was),
                    char::from(*expected)
                )
            }
        }
    }
}

impl Error for ParseError {}

/// Compute the _check digit_ for an array of u8. No attempt is made to ensure the input string
/// is in the CUSIP payload format or length. If an illegal character (not an ASCII digit and not
/// an ASCII uppercase letter) is encountered, this function will panic.
pub fn compute_check_digit(s: &[u8]) -> u8 {
    let sum = checksum_table(s);
    b'0' + sum
}

fn validate_issuer_id_format(id: &[u8]) -> Result<(), ParseError> {
    for b in id {
        if !(b.is_ascii_digit() || (b.is_ascii_alphabetic() && b.is_ascii_uppercase())) {
            let mut id_copy: [u8; 6] = [0; 6];
            id_copy.copy_from_slice(id);
            return Err(ParseError::InvalidIssuerId { was: id_copy });
        }
    }
    Ok(())
}

fn validate_issue_id_format(id: &[u8]) -> Result<(), ParseError> {
    for b in id {
        if !(b.is_ascii_digit() || (b.is_ascii_alphabetic() && b.is_ascii_uppercase())) {
            let mut id_copy: [u8; 2] = [0; 2];
            id_copy.copy_from_slice(id);
            return Err(ParseError::InvalidIssueId { was: id_copy });
        }
    }
    Ok(())
}

fn validate_check_digit_format(cd: u8) -> Result<(), ParseError> {
    if !cd.is_ascii_digit() {
        Err(ParseError::InvalidCheckDigit { was: cd })
    } else {
        Ok(())
    }
}

/// Parse a string to a valid CUSIP or an error, requiring the string to already be only
/// uppercase alphanumerics with no leading or trailing whitespace in addition to being the
/// right length and format.
pub fn parse(value: &str) -> Result<CUSIP, ParseError> {
    let v: String = value.into();

    if v.len() != 9 {
        return Err(ParseError::InvalidLength { was: v.len() });
    }

    // We make the preliminary assumption that the string is pure ASCII, so we work with the
    // underlying bytes. If there is Unicode in the string, the bytes will be outside the
    // allowed range and format validations will fail.

    let b = v.as_bytes();

    // We slice out the three fields and validate their formats.

    let issuer: &[u8] = &b[0..6];
    validate_issuer_id_format(issuer)?;

    let issue: &[u8] = &b[6..8];
    validate_issue_id_format(issue)?;

    let cd = b[8];
    validate_check_digit_format(cd)?;

    // Now, we need to compute the correct check digit value from the "payload" (everything except
    // the check digit).

    let payload = &b[0..8];

    let computed_check_digit = compute_check_digit(payload);

    let incorrect_check_digit = cd != computed_check_digit;
    if incorrect_check_digit {
        return Err(ParseError::IncorrectCheckDigit {
            was: cd,
            expected: computed_check_digit,
        });
    }

    let mut bb = [0u8; 9];
    bb.copy_from_slice(b);
    Ok(CUSIP(bb))
}

/// Parse a string to a valid CUSIP or an error message, allowing the string to contain leading
/// or trailing whitespace and/or lowercase letters as long as it is otherwise the right length
/// and format.
pub fn parse_loose(value: &str) -> Result<CUSIP, ParseError> {
    let uc = value.to_ascii_uppercase();
    let temp = uc.trim();
    parse(temp)
}

pub fn validate(value: &str) -> bool {
    let temp = checksum_table(value.as_bytes());
    println!("validate(): Checksum of {} is {}", value, temp);
    temp == 0
}

#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Hash, Debug)]
#[repr(transparent)]
pub struct CUSIP([u8; 9]);

impl Display for CUSIP {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let temp = unsafe { self.as_bytes().to_str_unchecked() }; // This is safe because we know it is ASCII
        write!(f, "{}", temp)
    }
}

impl FromStr for CUSIP {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_loose(s)
    }
}

impl CUSIP {
    /// Internal convenience function for treating the ASCII characters as a byte-array slice.
    fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier, false otherwise.
    pub fn is_cins(&self) -> bool {
        match self.as_bytes()[0] {
            (b'0'..=b'9') => false,
            (b'A'..=b'Z') => true,
            x => panic!(
                "It should not be possible to have a non-ASCII-alphanumeric value here: {:?}",
                x
            ),
        }
    }

    /// Returns Some(c) containing the first character of the CUSIP if it is actually a CUSIP
    /// International Numbering System (CINS) identifier, None otherwise.
    pub fn cins_country_code(&self) -> Option<char> {
        match self.as_bytes()[0] {
            (b'0'..=b'9') => None,
            x @ (b'A'..=b'Z') => Some(x as char),
            x => panic!(
                "It should not be possible to have a non-ASCII-alphanumeric value here: {:?}",
                x
            ),
        }
    }

    /// Return just the _issuer number_ portion of the CUSIP.
    pub fn issuer_num(&self) -> &str {
        unsafe { self.as_bytes()[0..6].to_str_unchecked() } // This is safe because we know it is ASCII
    }

    /// Return just the _issue number_ portion of the CUSIP.
    pub fn issue_num(&self) -> &str {
        unsafe { self.as_bytes()[6..8].to_str_unchecked() } // This is safe because we know it is ASCII
    }

    /// Return the &ldquo;payload&rdquo; &mdash; everything except the check digit.
    pub fn payload(&self) -> &str {
        unsafe { self.as_bytes()[0..8].to_str_unchecked() } // This is safe because we know it is ASCII
    }

    /// Return just the _check digit_ portion of the CUSIP.
    pub fn check_digit(&self) -> char {
        self.as_bytes()[8] as char
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_cusip_for_bcc_strict() {
        match parse("09739D100") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "09739D100");
                assert_eq!(cusip.issuer_num(), "09739D");
                assert_eq!(cusip.issue_num(), "10");
                assert_eq!(cusip.check_digit(), '0');
                assert_eq!(cusip.is_cins(), false);
            }
            Err(err) => assert!(false, "Did not expect parsing to fail: {}", err),
        }
    }

    #[test]
    fn parse_cusip_for_bcc_loose() {
        match parse_loose("\t09739d100    ") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "09739D100");
                assert_eq!(cusip.issuer_num(), "09739D");
                assert_eq!(cusip.issue_num(), "10");
                assert_eq!(cusip.check_digit(), '0');
                assert_eq!(cusip.is_cins(), false);
            }
            Err(err) => assert!(false, "Did not expect parsing to fail: {}", err),
        }
    }

    #[test]
    fn validate_cusip_for_bcc() {
        assert!(true, validate("09739D100"))
    }

    #[test]
    fn parse_cins() {
        match parse("S08000AA9") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "S08000AA9");
                assert_eq!(cusip.issuer_num(), "S08000");
                assert_eq!(cusip.issue_num(), "AA");
                assert_eq!(cusip.check_digit(), '9');
                assert_eq!(cusip.is_cins(), true);
            }
            Err(err) => assert!(false, "Did not expect parsing to fail: {}", err),
        }
    }

    /// This test case appears on page 3 of ANSI X9.6-2020, in the section "Annex A (Normative):
    /// Modulus 10 Double-Add-Double Technique".
    #[test]
    fn parse_example_from_standard() {
        match parse("837649128") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "837649128");
                assert_eq!(cusip.issuer_num(), "837649");
                assert_eq!(cusip.issue_num(), "12");
                assert_eq!(cusip.check_digit(), '8');
                assert_eq!(cusip.is_cins(), false);
            }
            Err(err) => assert!(false, "Did not expect parsing to fail: {}", err),
        }
    }

    /// This test case appears on page 3 of ANSI X9.6-2020, in the section "Annex A (Normative):
    /// Modulus 10 Double-Add-Double Technique".
    #[test]
    fn validate_example_from_standard() {
        assert!(true, validate("837649128"))
    }

    #[test]
    fn reject_empty_string() {
        let res = parse("");
        assert!(res.is_err());
    }

    #[test]
    fn reject_lowercase_issuer_id_if_strict() {
        match parse("99999zAA5") {
            Err(ParseError::InvalidIssuerId { was: _ }) => {} // Ok
            Err(err) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssuerId {{ ... }}), but got: Err({:?})",
                    err
                )
            }
            Ok(cusip) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssuerId {{ ... }}), but got: Ok({:?})",
                    cusip
                )
            }
        }
    }

    #[test]
    fn reject_lowercase_issue_id_if_strict() {
        match parse("99999Zaa5") {
            Err(ParseError::InvalidIssueId { was: _ }) => {} // Ok
            Err(err) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssueId {{ ... }}), but got: Err({:?})",
                    err
                )
            }
            Ok(cusip) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssueId {{ ... }}), but got: Ok({:?})",
                    cusip
                )
            }
        }
    }

    #[test]
    fn parse_cusip_with_0_check_digit() {
        parse("09739D100").unwrap(); // BCC aka Boise Cascade
    }

    #[test]
    fn parse_cusip_with_1_check_digit() {
        parse("00724F101").unwrap(); // ADBE aka Adobe
    }

    #[test]
    fn parse_cusip_with_2_check_digit() {
        parse("02376R102").unwrap(); // AAL aka American Airlines
    }

    #[test]
    fn parse_cusip_with_3_check_digit() {
        parse("053015103").unwrap(); // ADP aka Automatic Data Processing
    }

    #[test]
    fn parse_cusip_with_4_check_digit() {
        parse("457030104").unwrap(); // IMKTA aka Ingles Markets
    }

    #[test]
    fn parse_cusip_with_5_check_digit() {
        parse("007800105").unwrap(); // AJRD aka Aerojet Rocketdyne Holdings
    }

    #[test]
    fn parse_cusip_with_6_check_digit() {
        parse("98421M106").unwrap(); // XRX aka Xerox
    }

    #[test]
    fn parse_cusip_with_7_check_digit() {
        parse("007903107").unwrap(); // AMD aka Advanced Micro Devices
    }

    #[test]
    fn parse_cusip_with_8_check_digit() {
        parse("921659108").unwrap(); // VNDA aka Vanda Pharmaceuticals
    }

    #[test]
    fn parse_cusip_with_9_check_digit() {
        parse("020772109").unwrap(); // APT aka AlphaProTec
    }

    /// A bunch of test cases obtained from pubic SEC data via a PDF at
    /// https://www.sec.gov/divisions/investment/13flists.htm
    #[test]
    fn parse_bulk() {
        let cases = [
            "25470F104",
            "254709108",
            "254709108",
            "25470F104",
            "25470F302",
            "25470M109",
            "25490H106",
            "25490K273",
            "25490K281",
            "25490K323",
            "25490K331",
            "25490K596",
            "25490K869",
            "25525P107",
            "255519100",
            "256135203",
            "25614T309",
            "256163106",
            "25659T107",
            "256677105",
            "256746108",
            "25746U109",
            "25754A201",
            "257554105",
            "257559203",
            "257651109",
            "257701201",
            "257867200",
            "25787G100",
            "25809K105",
            "25820R105",
            "258278100",
            "258622109",
            "25960P109",
            "25960R105",
            "25985W105",
            "260003108",
            "260174107",
            "260557103",
            "26140E600",
            "26142R104",
            "26152H301",
            "262037104",
            "262077100",
            "26210C104",
            "264120106",
            "264147109",
            "264411505",
            "26441C204",
            "26443V101",
            "26484T106",
            "265504100",
            "26614N102",
            "266605104",
            "26745T101",
            "267475101",
            "268150109",
            "268158201",
            "26817Q886",
            "268311107",
            "26856L103",
            "268603107",
            "26874R108",
            "26884L109",
            "26884U109",
            "268948106",
            "26922A230",
            "26922A248",
            "26922A289",
            "26922A305",
        ];
        for case in cases.iter() {
            parse(case).unwrap();
        }
    }

    proptest! {
        #[test]
        #[allow(unused_must_use)]
        fn doesnt_crash(s in "\\PC*") {
            parse(&s);
        }
    }
}
