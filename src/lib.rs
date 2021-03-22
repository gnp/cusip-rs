#![warn(missing_docs)]
//! # cusip
//!
//! `cusip` provides a `CUSIP` type for working with validated Committee on Uniform Security
//! Identification Procedures (CUSIP) identifiers as defined in [ANSI X9.6-2020 Financial Services -
//! Committee on Uniform Security Identification Procedures Securities Identification CUSIP](https://webstore.ansi.org/standards/ascx9/ansix92020)
//! ("The Standard").
//!
//! [CUSIP Global Services (CGS)](https://www.cusip.com/) has [a page describing CUSIP
//! identifiers](https://www.cusip.com/identifiers.html).
//!
//! A CUSIP "number" (so-called by The Standard because originally they were composed only of
//! decimal digits, but now they can also use letters) is comprised of 9 ASCII characters with the
//! following parts, in order (Section 3.1 "CUSIP number length" of the standard):
//!
//! 1. A six-character uppercase alphanumeric _Issuer Number_.
//! 2. A two-character uppercase alphanumeric _Issue Number_.
//! 3. A single decimal digit representing the _Check Digit_ computed using what The Standard calls
//! the "modulus 10 'double-add-double' technique".
//!
//! Note: The Standard does not specify uppercase for the alphabetic characters but uniformly
//! presents examples only using uppercase. Therefore this implementation treats uppercase as
//! required for both parsing and validation, while offering a `parse_loose()` alternative that
//! allows mixed case. There is no "loose" version of validation because of the risk of confusion
//! if it were used to validate a set of strings -- the number of distinct string values could
//! differ from the number of distinct CUSIP identifiers because each identifier could have multiple
//! string representations in the set, potentially resulting in data integrity problems.
//!
//! Although The Standard asserts that CUSIP numbers are not assigned using alphbetic 'I' and 'O'
//! nor using digits '1' and '0' to avoid confusion, digits '1' and '0' are common in current
//! real-world CUSIP numbers. A survey of a large set of values turned up none using letter 'I' or
//! letter 'O', so it is plausible that 'I' and 'O' are indeed not used. In any case, this crate
//! does _not_ treat any of these four character values as invalid.
//!
//! CUSIP number "issuance and dissemination" are managed by
//! [CUSIP Global Services (CGS)](https://www.cusip.com/) per section B.1 "Registration Authority"
//! of The Standard. In addition, there are provisions for privatly assigned identifiers (see
//! below).
//!
//! ## Usage
//!
//! Use the `parse()` or `parse_loose()` functions to convert a string to a validated CUSIP:
//!
//! ```
//! # let some_string = "09739D100";
//! match cusip::parse(some_string) {
//!     Ok(cusip) => { /* ... */ }
//!     Err(err) => { /* ... */ }
//! }
//! ```
//!
//! or take advantage of CUSIP's implementation of the `FromStr` trait and use the `parse()` method
//! on the `str` type:
//!
//! ```
//! # let some_string = "09739D100";
//! let cusip: cusip::CUSIP = some_string.parse().unwrap();
//! ```
//!
//! If you just want to check if a string value is in a valid CUSIP format (with the correct _Check
//! Digit_), use `validate()`.
//!
//! ```
//! # let some_string = "09739D100";
//! let is_valid_cusip = cusip::validate(some_string);
//! ```
//!
//! ## CUSIP
//!
//! Since its adoption in 1968, CUSIP has been the standard security identifier for:
//!
//! * United States of America
//! * Canada
//! * Bermuda
//! * Cayman Islands
//! * British Virgin Islands
//! * Jamaica
//!
//! Since the introduction of the ISIN standard
//! ([ISO 6166](https://www.iso.org/standard/78502.html)), CUSIP has been adopted as the ISIN
//! _Security Identifier_ for many more territories in the creation of ISIN identifiers.
//!
//! ## Private use
//!
//! The CUSIP code space has allocations for both private _Issuer Numbers_ and private _Issue
//! Numbers_.
//!
//! You can determine whether or not a CUSIP is intended for private use by using the
//! `CUSIP::is_private_use()` method. A private use CUSIP is one that either `has_private_issuer()`
//! or `is_private_issue()`. The has/is distinction is because a CUSIP represents ("is") an Issue
//! (Security) offered by an "Issuer" (the Security "has" an Issuer).
//!
//! ### Private Issue Numbers
//!
//! In Section 3.2 "Issuer Number" of The Standard, "privately assigned identifiers" are defined as
//! those having _Issuer Number_ ending in "990" through "999".
//!
//! In Section C.8.1.3 "Issuer Numbers Reserved for Internal Use" of the Standard, expands that set
//! with the following additional _Issuer Numbers_:
//!
//! * those ending in "99A" through "99Z"
//! * those from "990000" through "999999"
//! * those from "99000A" through "99999Z"
//!
//! Such CUSIPs are reserved for this use only, and will not be assigned by the Registration
//! Authority.
//!
//! You can use the `CUSIP::has_private_issuer()` method to detect this case.
//!
//! Note that The Standard says that in all cases a "Z" in the "5th and 6th position has been
//! reserved for use by the Canadian Depository for Securities." There are no examples given, and it
//! is not clear whether this means literally "and" ("0000ZZ005" would be reserved but "0000Z0002"
//! and "00000Z003" would not) or if it actually means "and/or" (all of "0000ZZ005", "0000Z0002" and
//! "00000Z003" would be reserved). Because this is not clear from the text of the standard, this
//! rule is not represented in this crate.
//!
//! ### Private Issuer Numbers
//!
//! In Section C.8.2.6 "Issue Numbers Reserved for Internal Use", The Standard specifies that
//! _Issue Numbers_ "90" through "99" and "9A" through "9Y" are reserved for private use,
//! potentially in combination with non-private-use _Issuer Numbers_.
//!
//! ## CUSIP International Numbering System (CINS)
//!
//! While the primary motivation for the creation of the CUSIP standard was representation of U.S.
//! and Canadian securites, it was extended in 1989 for non-North American issues through definition
//! of a CUSIP International Numbering System (CINS). On 1991-01-01 CINS became the only allowed way
//! of issuing CUSIP identifiers for non-North American securities.
//!
//! A CUSIP with a letter in the first position is a CINS number, and that letter identifies the
//! country or geographic region of the _Issuer_.
//!
//! Use the `CUSIP::is_cins()` method to discriminate between CINS and conventional CUSIPs, and the
//! `CUSIP::cins_country_code()` method to extract the CINS Country Code as an `Option<char>`.
//!
//! The country codes are:
//!
//! |code|region        |code|region     |code|region       |code|region         |
//! |----|--------------|----|-----------|----|-------------|----|---------------|
//! |`A` |Austria       |`H` |Switzerland|`O` |(Unused)     |`V` |Africa - Other |
//! |`B` |Belgium       |`I` |(Unused)   |`P` |South America|`W` |Sweden         |
//! |`C` |Canada        |`J` |Japan      |`Q` |Australia    |`X` |Europe - Other |
//! |`D` |Germany       |`K` |Denmark    |`R` |Norway       |`Y` |Asia           |
//! |`E` |Spain         |`L` |Luxembourg |`S` |South Africa |`Z` |(Unused)       |
//! |`F` |France        |`M` |Mid-East   |`T` |Italy        |    |               |
//! |`G` |United Kingdom|`N` |Netherlands|`U` |United States|    |               |
//!
//! Even though country codes `I`, `O` and `Z` are unused, this crate reports CUSIPs starting
//! with those letters as being in the CINS format via `CUSIP::is_cins()` and returns them via
//! `CUSIP::cins_country_code()` because The Standard says CINS numbers are those CUSIPs starting
//! with a letter. If you care about the distinction between the two, use `CUSIP::is_cins_base()`
//! and `CUSIP::is_cins_extended()`.
//!
//! See section C.7.2 "Non-North American Issues -- CUSIP International Numbering System" of The
//! Standard.
//!
//! ## Private Placement Number (PPN)
//!
//! According to Section C.7.2 "Private Placements" of The Standard,
//! The Standard defines three non-alphanumeric character values to support a special use for
//! the "PPN System". They are '`*`' (value 36), '`@`' (value 37) and '`#`' (value 38) (see section
//! A.3 "Treatment of Alphabetic Characters".
//!
//! CUSIPs using these extended characters are not supported by this crate because the extended
//! characters are not supported by ISINs, and CUSIPs are incorporated as the _Security Identifier_
//! for ISINs for certain _Country Codes_.
//!
//! ## Related crates
//!
//! This crate is part of the Financial Identifiers series:
//!
//! * CUSIP -- Committee on Uniform Security Identification Procedures
//! * [ISIN](https://crates.io/crates/isin) -- International Securities Identification Number
//!

use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Debug, Display};
use std::str::FromStr;

use bstr::ByteSlice;

pub mod checksum;

use checksum::checksum_table;

/// All the ways parsing could fail.
#[non_exhaustive]
#[derive(Clone, PartialEq, Eq)]
pub enum CUSIPError {
    /// The CUSIP length is not exactly 9 bytes (checked when parsing).
    InvalidCUSIPLength {
        /// The length we found
        was: usize,
    },
    /// The _Payload_ length is not exactly 8 bytes (checked when building).
    InvalidPayloadLength {
        /// The length we found
        was: usize,
    },
    /// The _Issuer Number_ length is not exactly 6 bytes (checked when building).
    InvalidIssuerNumLength {
        /// The length we found
        was: usize,
    },
    /// The _Issue Number_ length is not exactly 6 bytes (checked when building).
    InvalidIssueNumLength {
        /// The length we found
        was: usize,
    },
    /// The input issuer id is not six uppercase ASCII alphanumeric characters (checked when parsing or building).
    InvalidIssuerNum {
        /// The _Issuer Number_ we found
        was: [u8; 6],
    },
    /// The input issue id is not two uppercase ASCII alphanumeric characters (checked when parsing or building).
    InvalidIssueNum {
        /// The _Issue Number_ we found
        was: [u8; 2],
    },
    /// The input check digit is not a single ASCII decimal digit character (checked when parsing).
    InvalidCheckDigit {
        /// The _Check Digit_ we found
        was: u8,
    },
    /// The input check digit has in a valid format, but has an incorrect value (checked when parsing).
    IncorrectCheckDigit {
        /// The _Check Digit_ we found
        was: u8,
        /// The _Check Digit_ we expected
        expected: u8,
    },
}

impl Debug for CUSIPError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CUSIPError::InvalidCUSIPLength { was } => {
                write!(f, "InvalidCUSIPLength {{ was: {:?} }}", was)
            },
            CUSIPError::InvalidPayloadLength { was } => {
                write!(f, "InvalidPayloadLength {{ was: {:?} }}", was)
            },
            CUSIPError::InvalidIssuerNumLength { was } => {
                write!(f, "InvalidIssuerNumLength {{ was: {:?} }}", was)
            },
            CUSIPError::InvalidIssueNumLength { was } => {
                write!(f, "InvalidIssueNumLength {{ was: {:?} }}", was)
            },
            CUSIPError::InvalidIssuerNum { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(f, "InvalidIssuerNum {{ was: {:?} }}", s)
                }
                Err(_) => {
                    write!(f, "InvalidIssuerNum {{ was: (invalid UTF-8) {:?} }}", was)
                }
            },
            CUSIPError::InvalidIssueNum { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(f, "InvalidIssueNum {{ was: {:?} }}", s)
                }
                Err(_) => {
                    write!(f, "InvalidIssueNum {{ was: (invalid UTF-8) {:?} }}", was)
                }
            },
            CUSIPError::InvalidCheckDigit { was } => {
                write!(f, "InvalidCheckDigit {{ was: {:?} }}", char::from(*was))
            }
            CUSIPError::IncorrectCheckDigit { was, expected } => {
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

impl Display for CUSIPError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CUSIPError::InvalidCUSIPLength { was } => {
                write!(f, "invalid CUSIP length {} bytes when expecting 9", was)
            }
            CUSIPError::InvalidPayloadLength { was } => {
                write!(f, "invalid Payload length {} bytes when expecting 8", was)
            }
            CUSIPError::InvalidIssuerNumLength { was } => {
                write!(f, "invalid Issuer Number length {} bytes when expecting 6", was)
            }
            CUSIPError::InvalidIssueNumLength { was } => {
                write!(f, "invalid Issue Number length {} bytes when expecting 2", was)
            }
            CUSIPError::InvalidIssuerNum { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(
                        f,
                        "Issuer Number {:?} is not six uppercase ASCII alphanumeric characters",
                        s
                    )
                }
                Err(_) => {
                    write!(f,
                    "Issuer Number (invalid UTF-8) {:?} is not six uppercase ASCII alphanumeric characters",
                    was)
                }
            },
            CUSIPError::InvalidIssueNum { was } => match std::str::from_utf8(was) {
                Ok(s) => {
                    write!(
                        f,
                        "Issue Number {:?} is not two uppercase ASCII alphanumeric characters",
                        s
                    )
                }
                Err(_) => {
                    write!(f,
                "Issue Number (invalid UTF-8) {:?} is not two uppercase ASCII alphanumeric characters",
                    was)
                }
            },
            CUSIPError::InvalidCheckDigit { was } => {
                write!(
                    f,
                    "Check Digit {:?} is not one ASCII decimal digit",
                    *was as char
                )
            }
            CUSIPError::IncorrectCheckDigit { was, expected } => {
                write!(
                    f,
                    "incorrect Check Digit {:?} when expecting {:?}",
                    char::from(*was),
                    char::from(*expected)
                )
            }
        }
    }
}

impl Error for CUSIPError {}

/// Compute the _Check Digit_ for an array of u8. No attempt is made to ensure the input string
/// is in the CUSIP payload format or length. If an illegal character (not an ASCII digit and not
/// an ASCII uppercase letter) is encountered, this function will panic.
pub fn compute_check_digit(s: &[u8]) -> u8 {
    let sum = checksum_table(s);
    b'0' + sum
}

/// Check whether or not the passed _Issuer Number_ has a valid format.
fn validate_issuer_num_format(num: &[u8]) -> Result<(), CUSIPError> {
    for b in num {
        if !(b.is_ascii_digit() || (b.is_ascii_alphabetic() && b.is_ascii_uppercase())) {
            let mut id_copy: [u8; 6] = [0; 6];
            id_copy.copy_from_slice(num);
            return Err(CUSIPError::InvalidIssuerNum { was: id_copy });
        }
    }
    Ok(())
}

/// Check whether or not the passed _Issue Number_ has a valid format.
fn validate_issue_num_format(num: &[u8]) -> Result<(), CUSIPError> {
    for b in num {
        if !(b.is_ascii_digit() || (b.is_ascii_alphabetic() && b.is_ascii_uppercase())) {
            let mut id_copy: [u8; 2] = [0; 2];
            id_copy.copy_from_slice(num);
            return Err(CUSIPError::InvalidIssueNum { was: id_copy });
        }
    }
    Ok(())
}

/// Check whether or not the passed _Check Digit_ has a valid format.
fn validate_check_digit_format(cd: u8) -> Result<(), CUSIPError> {
    if !cd.is_ascii_digit() {
        Err(CUSIPError::InvalidCheckDigit { was: cd })
    } else {
        Ok(())
    }
}

/// Parse a string to a valid CUSIP or an error, requiring the string to already be only
/// uppercase alphanumerics with no leading or trailing whitespace in addition to being the
/// right length and format.
pub fn parse(value: &str) -> Result<CUSIP, CUSIPError> {
    if value.len() != 9 {
        return Err(CUSIPError::InvalidCUSIPLength { was: value.len() });
    }

    // We make the preliminary assumption that the string is pure ASCII, so we work with the
    // underlying bytes. If there is Unicode in the string, the bytes will be outside the
    // allowed range and format validations will fail.

    let b = value.as_bytes();

    // We slice out the three fields and validate their formats.

    let issuer_num: &[u8] = &b[0..6];
    validate_issuer_num_format(issuer_num)?;

    let issue_num: &[u8] = &b[6..8];
    validate_issue_num_format(issue_num)?;

    let cd = b[8];
    validate_check_digit_format(cd)?;

    // Now, we need to compute the correct _Check Digit_ value from the "payload" (everything except
    // the _Check Digit_).

    let payload = &b[0..8];

    let computed_check_digit = compute_check_digit(payload);

    let incorrect_check_digit = cd != computed_check_digit;
    if incorrect_check_digit {
        return Err(CUSIPError::IncorrectCheckDigit {
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
pub fn parse_loose(value: &str) -> Result<CUSIP, CUSIPError> {
    let uc = value.to_ascii_uppercase();
    let temp = uc.trim();
    parse(temp)
}

/// Build a CUSIP from a _Payload_ (an already-concatenated _Issuer Number_ and _Issue Number_). The
/// _Check Digit is automatically computed.
pub fn build_from_payload(payload: &str) -> Result<CUSIP, CUSIPError> {
    if payload.len() != 8 {
        return Err(CUSIPError::InvalidPayloadLength { was: payload.len() });
    }
    let b = &payload.as_bytes()[0..8];

    let issuer_num = &b[0..6];
    validate_issuer_num_format(issuer_num)?;

    let issue_num = &b[6..8];
    validate_issue_num_format(issue_num)?;

    let mut bb = [0u8; 9];

    bb[0..8].copy_from_slice(b);
    bb[8] = compute_check_digit(b);

    Ok(CUSIP(bb))
}

/// Build a CUSIP from its parts: an _Issuer Number_ and an _Issue Number_. The _Check Digit_ is
/// automatically computed.
pub fn build_from_parts(issuer_num: &str, issue_num: &str) -> Result<CUSIP, CUSIPError> {
    if issuer_num.len() != 6 {
        return Err(CUSIPError::InvalidIssuerNumLength { was: issuer_num.len() });
    }
    let issuer_num: &[u8] = &issuer_num.as_bytes()[0..6];
    validate_issuer_num_format(issuer_num)?;

    if issue_num.len() != 2 {
        return Err(CUSIPError::InvalidIssueNumLength { was: issue_num.len() });
    }
    let issue_num: &[u8] = &issue_num.as_bytes()[0..2];
    validate_issue_num_format(issue_num)?;

    let mut bb = [0u8; 9];

    bb[0..6].copy_from_slice(issuer_num);
    bb[6..8].copy_from_slice(issue_num);
    bb[8] = compute_check_digit(&bb[0..8]);

    Ok(CUSIP(bb))
}

/// Test whether or not the passed string is in valid CUSIP format, without producing a CUSIP struct
/// value.
pub fn validate(value: &str) -> bool {
    if value.len() != 9 {
        println!("Bad length: {:?}", value);
        return false;
    }

    // We make the preliminary assumption that the string is pure ASCII, so we work with the
    // underlying bytes. If there is Unicode in the string, the bytes will be outside the
    // allowed range and format validations will fail.

    let b = value.as_bytes();

    // We slice out the three fields and validate their formats.

    let issuer_num: &[u8] = &b[0..6];
    if validate_issuer_num_format(issuer_num).is_err() {
        return false;
    }

    let issue_num: &[u8] = &b[6..8];
    if validate_issue_num_format(issue_num).is_err() {
        return false;
    }

    let cd = b[8];
    if validate_check_digit_format(cd).is_err() {
        return false;
    }

    let payload = &b[0..8];

    let computed_check_digit = compute_check_digit(payload);

    let incorrect_check_digit = cd != computed_check_digit;

    !incorrect_check_digit
}

/// A CUSIP in confirmed valid format.
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
    type Err = CUSIPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_loose(s)
    }
}

impl CUSIP {
    /// Internal convenience function for treating the ASCII characters as a byte-array slice.
    fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Returns true if this CUSIP number is actually a CUSIP International Numbering System
    /// (CINS) number, false otherwise (i.e., that it has a letter as the first character of its
    /// _issuer number_). See also `is_cins_base()` and `is_cins_extended()`.
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

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier (with the further restriction that it *does not* use 'I', 'O' or 'Z' as
    /// its country code), false otherwise. See also `is_cins()` and `is_cins_extended()`.
    pub fn is_cins_base(&self) -> bool {
        match self.as_bytes()[0] {
            (b'0'..=b'9') => false,
            (b'A'..=b'H') => true,
            b'I' => false,
            (b'J'..=b'N') => true,
            b'O' => false,
            (b'P'..=b'Y') => true,
            b'Z' => false,
            x => panic!(
                "It should not be possible to have a non-ASCII-alphanumeric value here: {:?}",
                x
            ),
        }
    }

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier (with the further restriction that it *does* use 'I', 'O' or 'Z' as its
    /// country code), false otherwise.
    pub fn is_cins_extended(&self) -> bool {
        match self.as_bytes()[0] {
            (b'0'..=b'9') => false,
            (b'A'..=b'H') => false,
            b'I' => true,
            (b'J'..=b'N') => false,
            b'O' => true,
            (b'P'..=b'Y') => false,
            b'Z' => true,
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

    /// Return just the _Issuer Number_ portion of the CUSIP.
    pub fn issuer_num(&self) -> &str {
        unsafe { self.as_bytes()[0..6].to_str_unchecked() } // This is safe because we know it is ASCII
    }

    /// Returns true if the _Issuer Number_ is reserved for private use.
    pub fn has_private_issuer(&self) -> bool {
        let bs = self.as_bytes();

        // "???99?"
        let case1 = bs[3] == b'9' && bs[4] == b'9';

        // "99000?" to "99999?"
        let case2 = bs[0] == b'9' && bs[1] == b'9'
            && (b'0'..=b'9').contains(&bs[2])
            && (b'0'..=b'9').contains(&bs[3])
            && (b'0'..=b'9').contains(&bs[4]);

        case1 || case2
    }

    /// Return just the _Issue Number_ portion of the CUSIP.
    pub fn issue_num(&self) -> &str {
        unsafe { self.as_bytes()[6..8].to_str_unchecked() } // This is safe because we know it is ASCII
    }

    /// Returns true if the _Issue Number_ is reserved for private use.
    pub fn is_private_issue(&self) -> bool {
        let bs = self.as_bytes();
        let nine_tens = bs[6] == b'9';
        let digit_ones = (b'0'..=b'9').contains(&bs[7]);
        let letter_ones = (b'A'..=b'Y').contains(&bs[7]);
        nine_tens && (digit_ones || letter_ones)
    }

    /// Returns true if the CUSIP is reserved for private use (i.e., either it has a private issuer
    /// or it is a private issue).
    pub fn is_private_use(&self) -> bool {
        self.has_private_issuer() || self.is_private_issue()
    }

    /// Return the _Payload_ &mdash; everything except the _Check Digit_.
    pub fn payload(&self) -> &str {
        unsafe { self.as_bytes()[0..8].to_str_unchecked() } // This is safe because we know it is ASCII
    }

    /// Return just the _Check Digit_ portion of the CUSIP.
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
        // Boise Cascade
        assert!(true, validate("09739D100"))
    }

    #[test]
    fn validate_cusip_for_dfs() {
        // Discover Financial Services
        assert!(true, validate("254709108"))
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
            Err(CUSIPError::InvalidIssuerNum { was: _ }) => {} // Ok
            Err(err) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssuerNum {{ ... }}), but got: Err({:?})",
                    err
                )
            }
            Ok(cusip) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssuerNum {{ ... }}), but got: Ok({:?})",
                    cusip
                )
            }
        }
    }

    #[test]
    fn reject_lowercase_issue_id_if_strict() {
        match parse("99999Zaa5") {
            Err(CUSIPError::InvalidIssueNum { was: _ }) => {} // Ok
            Err(err) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssueNum {{ ... }}), but got: Err({:?})",
                    err
                )
            }
            Ok(cusip) => {
                assert!(
                    false,
                    "Expected Err(InvalidIssueNum {{ ... }}), but got: Ok({:?})",
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
            assert_eq!(
                true,
                validate(case),
                "Successfully parsed {:?} but got false from validate()!",
                case
            );
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
