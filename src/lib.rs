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
//!    the "modulus 10 'double-add-double' technique".
//!
//! Note: The Standard does not specify uppercase for the alphabetic characters but uniformly
//! presents examples only using uppercase. Therefore this implementation treats uppercase as
//! required for both parsing and validation, while offering a `parse_loose()` alternative that
//! allows mixed case. There is no "loose" version of validation because of the risk of confusion
//! if it were used to validate a set of strings -- the number of distinct string values could
//! differ from the number of distinct CUSIP identifiers because each identifier could have multiple
//! string representations in the set, potentially resulting in data integrity problems.
//!
//! Although The Standard asserts that CUSIP numbers are not assigned using alphabetic 'I' and 'O'
//! nor using digits '1' and '0' to avoid confusion, digits '1' and '0' are common in current
//! real-world CUSIP numbers. A survey of a large set of values turned up none using letter 'I' or
//! letter 'O', so it is plausible that 'I' and 'O' are indeed not used. In any case, this crate
//! does _not_ treat any of these four character values as invalid.
//!
//! CUSIP number "issuance and dissemination" are managed by
//! [CUSIP Global Services (CGS)](https://www.cusip.com/) per section B.1 "Registration Authority"
//! of The Standard. In addition, there are provisions for privately assigned identifiers (see
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
//! and Canadian securities, it was extended in 1989 for non-North American issues through definition
//! of a CUSIP International Numbering System (CINS). On 1991-01-01 CINS became the only allowed way
//! of issuing CUSIP identifiers for non-North American securities.
//!
//! A CUSIP with a letter in the first position is a CINS number, and that letter identifies the
//! country or geographic region of the _Issuer_.
//!
//! Use the `CUSIP::is_cins()` method to discriminate between CINS and conventional CUSIPs, and the
//! `CUSIP::cins_country_code()` method to extract the CINS Country Code as an `Option<char>`.
//!
//! This crate provides a `CINS` type for working with CINS identifiers. You can convert a `CUSIP`
//! to a `CINS` using `CINS::new`, `TryFrom<&CUSIP>`, or `CUSIP::as_cins`. Once you have a `CINS`,
//! you can access the CINS _Country Code_ using `CINS::country_code``, and the (one character
//! shorter) CINS _Issuer Number_ using `CINS::issuer_num`). You can also get the _Issue Number_
//! via `CINS::issue_num`, though its the same as for the CUSIP. See the CINS documentation for
//! more details.
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
//! * [CIK](https://crates.io/crates/cik): Central Index Key (SEC EDGAR)
//! * [CUSIP](https://crates.io/crates/cusip): Committee on Uniform Security Identification Procedures (ANSI X9.6-2020)
//! * [ISIN](https://crates.io/crates/isin): International Securities Identification Number (ISO 6166:2021)
//! * [LEI](https://crates.io/crates/lei): Legal Entity Identifier (ISO 17442:2020)
//!

use std::fmt;
use std::str::from_utf8_unchecked;
use std::str::FromStr;

pub mod checksum;

use checksum::checksum_table;

pub mod error;
pub use error::CUSIPError;

/// Compute the _Check Digit_ for an array of u8. No attempt is made to ensure the input string
/// is in the CUSIP payload format or length. If an illegal character (not an ASCII digit and not
/// an ASCII uppercase letter) is encountered, this function will panic.
pub fn compute_check_digit(s: &[u8]) -> u8 {
    let sum = checksum_table(s);
    b'0' + sum
}

/// Check whether or not the passed _Issuer Number_ has a valid format.
fn validate_issuer_num_format(num: &[u8]) -> Result<(), CUSIPError> {
    if num.len() != 6 {
        panic!("Expected 6 bytes for Issuer Num, but got {}", num.len());
    }

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
    if num.len() != 2 {
        panic!("Expected 2 bytes for Issue Num, but got {}", num.len());
    }

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
#[deprecated(note = "Use CUSIP::parse instead.")]
#[inline]
pub fn parse(value: &str) -> Result<CUSIP, CUSIPError> {
    CUSIP::parse(value)
}

/// Parse a string to a valid CUSIP or an error message, allowing the string to contain leading
/// or trailing whitespace and/or lowercase letters as long as it is otherwise the right length
/// and format.
#[deprecated(note = "Use CUSIP::parse_loose instead.")]
#[inline]
pub fn parse_loose(value: &str) -> Result<CUSIP, CUSIPError> {
    CUSIP::parse_loose(value)
}

/// Build a CUSIP from a _Payload_ (an already-concatenated _Issuer Number_ and _Issue Number_). The
/// _Check Digit_ is automatically computed.
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
        return Err(CUSIPError::InvalidIssuerNumLength {
            was: issuer_num.len(),
        });
    }
    let issuer_num: &[u8] = &issuer_num.as_bytes()[0..6];
    validate_issuer_num_format(issuer_num)?;

    if issue_num.len() != 2 {
        return Err(CUSIPError::InvalidIssueNumLength {
            was: issue_num.len(),
        });
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

    let check_digit = b[8];
    if validate_check_digit_format(check_digit).is_err() {
        return false;
    }

    let payload = &b[0..8];

    let computed_check_digit = compute_check_digit(payload);

    let incorrect_check_digit = check_digit != computed_check_digit;

    !incorrect_check_digit
}

/// Returns true if this CUSIP number is actually a CUSIP International Numbering System
/// (CINS) number, false otherwise (i.e., that it has a letter as the first character of its
/// _issuer number_). See also `is_cins_base()` and `is_cins_extended()`.
fn is_cins(byte: u8) -> bool {
    match byte {
        (b'0'..=b'9') => false,
        (b'A'..=b'Z') => true,
        x => panic!("It should not be possible to have a non-ASCII-alphanumeric value here: {x:?}"),
    }
}

/// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
/// (CINS) identifier (with the further restriction that it *does not* use 'I', 'O' or 'Z' as
/// its country code), false otherwise. See also `is_cins()` and `is_cins_extended()`.
fn is_cins_base(byte: u8) -> bool {
    match byte {
        (b'0'..=b'9') => false,
        (b'A'..=b'H') => true,
        b'I' => false,
        (b'J'..=b'N') => true,
        b'O' => false,
        (b'P'..=b'Y') => true,
        b'Z' => false,
        x => panic!("It should not be possible to have a non-ASCII-alphanumeric value here: {x:?}"),
    }
}

/// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
/// (CINS) identifier (with the further restriction that it *does* use 'I', 'O' or 'Z' as its
/// country code), false otherwise.
fn is_cins_extended(byte: u8) -> bool {
    match byte {
        (b'0'..=b'9') => false,
        (b'A'..=b'H') => false,
        b'I' => true,
        (b'J'..=b'N') => false,
        b'O' => true,
        (b'P'..=b'Y') => false,
        b'Z' => true,
        x => panic!("It should not be possible to have a non-ASCII-alphanumeric value here: {x:?}"),
    }
}

/// Returns Some(c) containing the first character of the CUSIP if it is actually a CUSIP
/// International Numbering System (CINS) identifier, None otherwise.
fn cins_country_code(byte: u8) -> Option<char> {
    match byte {
        (b'0'..=b'9') => None,
        x @ (b'A'..=b'Z') => Some(x as char),
        x => panic!("It should not be possible to have a non-ASCII-alphanumeric value here: {x:?}"),
    }
}

#[doc = include_str!("../README.md")]
#[cfg(doctest)]
pub struct ReadmeDoctests;

/// A CUSIP in confirmed valid format.
///
/// You cannot construct a CUSIP value manually. This does not compile:
///
/// ```compile_fail
/// use cusip;
/// let cannot_construct = cusip::CUSIP([0_u8; 9]);
/// ```
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Hash)]
#[repr(transparent)]
#[allow(clippy::upper_case_acronyms)]
pub struct CUSIP([u8; 9]);

impl fmt::Display for CUSIP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        let temp = unsafe { from_utf8_unchecked(self.as_bytes()) }; // This is safe because we know it is ASCII
        write!(f, "{temp}")
    }
}

impl fmt::Debug for CUSIP {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let temp = unsafe { from_utf8_unchecked(self.as_bytes()) }; // This is safe because we know it is ASCII
        write!(f, "CUSIP({temp})")
    }
}

impl FromStr for CUSIP {
    type Err = CUSIPError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_loose(s)
    }
}

impl CUSIP {
    /// Constructs a `CUSIP` from a byte array of length 9.
    ///
    /// The byte array must contain only ASCII alphanumeric characters.
    /// The first 8 characters represent the issuer and issue numbers,
    /// and the 9th character is the check digit.
    ///
    /// # Errors
    ///
    /// Returns `CUSIPError` if the byte array is not a valid CUSIP.
    ///
    /// # Examples
    ///
    /// ```
    /// use cusip::{CUSIP, CUSIPError};
    ///
    /// let bytes = *b"037833100";
    /// let cusip = CUSIP::from_bytes(&bytes).unwrap();
    /// assert_eq!(cusip.to_string(), "037833100");
    ///
    /// let invalid_bytes = *b"invalid!!";
    /// assert!(CUSIP::from_bytes(&invalid_bytes).is_err());
    /// ```
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CUSIPError> {
        if bytes.len() != 9 {
            return Err(CUSIPError::InvalidCUSIPLength { was: bytes.len() });
        }

        // We slice out the three fields and validate their formats.

        let issuer_num: &[u8] = &bytes[0..6];
        validate_issuer_num_format(issuer_num)?;

        let issue_num: &[u8] = &bytes[6..8];
        validate_issue_num_format(issue_num)?;

        let cd = bytes[8];
        validate_check_digit_format(cd)?;

        // Now, we need to compute the correct _Check Digit_ value from the "payload" (everything except
        // the _Check Digit_).

        let payload = &bytes[0..8];

        let computed_check_digit = compute_check_digit(payload);

        let incorrect_check_digit = cd != computed_check_digit;
        if incorrect_check_digit {
            return Err(CUSIPError::IncorrectCheckDigit {
                was: cd,
                expected: computed_check_digit,
            });
        }

        let mut bb = [0u8; 9];
        bb.copy_from_slice(bytes);
        Ok(CUSIP(bb))
    }

    /// Parse a string to a valid CUSIP or an error, requiring the string to already be only
    /// uppercase alphanumerics with no leading or trailing whitespace in addition to being the
    /// right length and format.
    pub fn parse(value: &str) -> Result<CUSIP, CUSIPError> {
        let bytes = value.as_bytes();

        Self::from_bytes(bytes)
    }

    /// Parse a string to a valid CUSIP or an error message, allowing the string to contain leading
    /// or trailing whitespace and/or lowercase letters as long as it is otherwise the right length
    /// and format.
    #[inline]
    pub fn parse_loose(value: &str) -> Result<CUSIP, CUSIPError> {
        let uc = value.to_ascii_uppercase();
        let temp = uc.trim();
        Self::parse(temp)
    }

    /// Internal convenience function for treating the ASCII characters as a byte-array slice.
    fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }

    /// Returns a reference to the `CINS` representation of this `CUSIP`,
    /// if it is a valid CINS identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use cusip::{CUSIP, CINS};
    ///
    /// let cusip = CUSIP::parse("S08000AA9").unwrap();
    /// if let Some(cins) = cusip.as_cins() {
    ///     assert_eq!(cins.country_code(), 'S');
    ///     assert_eq!(cins.issuer_num(), "08000");
    /// } else {
    ///     println!("Not a CINS");
    /// }
    ///
    /// let non_cins_cusip = CUSIP::parse("037833100").unwrap();
    /// assert!(non_cins_cusip.as_cins().is_none());
    /// ```
    pub fn as_cins(&self) -> Option<CINS> {
        CINS::new(self)
    }

    /// Returns true if this CUSIP number is actually a CUSIP International Numbering System
    /// (CINS) number, false otherwise (i.e., that it has a letter as the first character of its
    /// _issuer number_). See also `is_cins_base()` and `is_cins_extended()`.
    pub fn is_cins(&self) -> bool {
        is_cins(self.as_bytes()[0])
    }

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier (with the further restriction that it *does not* use 'I', 'O' or 'Z' as
    /// its country code), false otherwise. See also `is_cins()` and `is_cins_extended()`.
    #[deprecated(note = "Use CUSIP::as_cins and CINS::is_cins_base.")]
    pub fn is_cins_base(&self) -> bool {
        is_cins_base(self.as_bytes()[0])
    }

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier (with the further restriction that it *does* use 'I', 'O' or 'Z' as its
    /// country code), false otherwise.
    #[deprecated(note = "Use CUSIP::as_cins and CINS::is_cins_extended.")]
    pub fn is_cins_extended(&self) -> bool {
        is_cins_extended(self.as_bytes()[0])
    }

    /// Returns Some(c) containing the first character of the CUSIP if it is actually a CUSIP
    /// International Numbering System (CINS) identifier, None otherwise.
    #[deprecated(note = "Use CUSIP::as_cins and CINS::country_code.")]
    pub fn cins_country_code(&self) -> Option<char> {
        cins_country_code(self.as_bytes()[0])
    }

    /// Return just the _Issuer Number_ portion of the CUSIP.
    pub fn issuer_num(&self) -> &str {
        unsafe { from_utf8_unchecked(&self.as_bytes()[0..6]) } // This is safe because we know it is ASCII
    }

    /// Returns true if the _Issuer Number_ is reserved for private use.
    pub fn has_private_issuer(&self) -> bool {
        let bs = self.as_bytes();

        // "???99?"
        let case1 = bs[3] == b'9' && bs[4] == b'9';

        // "99000?" to "99999?"
        let case2 = bs[0] == b'9'
            && bs[1] == b'9'
            && (bs[2].is_ascii_digit())
            && (bs[3].is_ascii_digit())
            && (bs[4].is_ascii_digit());

        case1 || case2
    }

    /// Return just the _Issue Number_ portion of the CUSIP.
    pub fn issue_num(&self) -> &str {
        unsafe { from_utf8_unchecked(&self.as_bytes()[6..8]) } // This is safe because we know it is ASCII
    }

    /// Returns true if the _Issue Number_ is reserved for private use.
    pub fn is_private_issue(&self) -> bool {
        let bs = self.as_bytes();
        let nine_tens = bs[6] == b'9';
        let digit_ones = bs[7].is_ascii_digit();
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
        unsafe { from_utf8_unchecked(&self.as_bytes()[0..8]) } // This is safe because we know it is ASCII
    }

    /// Return just the _Check Digit_ portion of the CUSIP.
    pub fn check_digit(&self) -> char {
        self.as_bytes()[8] as char
    }
}

/// A CINS (CUSIP International Numbering System) identifier.
///
/// CINS is a subset of CUSIP used for international securities.
/// It is distinguished by having a letter as the first character.
///
/// # Creating CINS instances
///
/// There are several ways to create a `CINS` instance from a `CUSIP`:
///
/// 1. Using `CINS::new`:
///
///    ```
///    use cusip::{CUSIP, CINS};
///
///    let cusip = CUSIP::parse("S08000AA9").unwrap();
///    if let Some(cins) = CINS::new(&cusip) {
///        println!("CINS: {}", cins);
///    } else {
///        println!("Not a valid CINS");
///    }
///    ```
///
/// 2. Using `TryFrom<&CUSIP>`:
///
///    ```
///    use cusip::{CUSIP, CINS};
///    use std::convert::TryFrom;
///
///    let cusip = CUSIP::parse("S08000AA9").unwrap();
///    match CINS::try_from(&cusip) {
///        Ok(cins) => println!("CINS: {}", cins),
///        Err(err) => println!("Error: {}", err),
///    }
///    ```
///
/// 3. Using `CUSIP::as_cins`:
///
///    ```
///    use cusip::{CUSIP, CINS};
///
///    let cusip = CUSIP::parse("S08000AA9").unwrap();
///    if let Some(cins) = cusip.as_cins() {
///        println!("CINS: {}", cins);
///    } else {
///        println!("Not a valid CINS");
///    }
///    ```
///
/// # Accessing the underlying CUSIP
///
/// You can call `as_cusip` on a `CINS` instance to access the underlying `CUSIP`:
///
/// ```
/// use cusip::{CUSIP, CINS};
///
/// let cusip = CUSIP::parse("S08000AA9").unwrap();
/// let cins = CINS::new(&cusip).unwrap();
/// println!("CUSIP: {}", cins.as_cusip());
/// ```
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[allow(clippy::upper_case_acronyms)]
pub struct CINS<'a>(&'a CUSIP);

impl<'a> fmt::Display for CINS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> fmt::Debug for CINS<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CINS({})", self.0) // The wrapped CUSIP is written as a string not in debug form
    }
}

impl<'a> TryFrom<&'a CUSIP> for CINS<'a> {
    type Error = &'static str;

    fn try_from(cusip: &'a CUSIP) -> Result<Self, Self::Error> {
        CINS::new(cusip).ok_or("Not a valid CINS")
    }
}

impl<'a> CINS<'a> {
    /// Constructs a new `CINS` from a reference to a `CUSIP`.
    ///
    /// Returns `Some(CINS)` if the given `CUSIP` is a valid CINS identifier,
    /// i.e., its first character is a letter (A-Z). Otherwise, returns `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cusip::{CUSIP, CINS};
    ///
    /// let cusip = CUSIP::parse("S08000AA9").unwrap();
    /// let cins = CINS::new(&cusip).unwrap();
    ///
    /// let non_cins_cusip = CUSIP::parse("037833100").unwrap();
    /// assert!(CINS::new(&non_cins_cusip).is_none());
    /// ```
    pub fn new(cusip: &'a CUSIP) -> Option<Self> {
        if is_cins(cusip.as_bytes()[0]) {
            Some(CINS(cusip))
        } else {
            None
        }
    }

    /// Returns a reference to the underlying `CUSIP`.
    ///
    /// # Examples
    ///
    /// ```
    /// use cusip::{CUSIP, CINS};
    ///
    /// let cusip = CUSIP::parse("S08000AA9").unwrap();
    /// let cins = CINS::new(&cusip).unwrap();
    /// assert_eq!(cins.as_cusip().to_string(), "S08000AA9");
    /// ```
    pub fn as_cusip(&self) -> &CUSIP {
        self.0
    }

    /// Returns the CINS country code.
    ///
    /// The country code is the first character of the CINS identifier,
    /// which is always a letter (A-Z).
    ///
    /// # Examples
    ///
    /// ```
    /// use cusip::{CUSIP, CINS};
    ///
    /// let cusip = CUSIP::parse("S08000AA9").unwrap();
    /// let cins = CINS::new(&cusip).unwrap();
    /// assert_eq!(cins.country_code(), 'S');
    /// ```
    pub fn country_code(&self) -> char {
        self.0.as_bytes()[0] as char
    }

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier (with the further restriction that it *does not* use 'I', 'O' or 'Z' as
    /// its country code), false otherwise. See also `is_cins()` and `is_cins_extended()`.
    pub fn is_base(&self) -> bool {
        is_cins_base(self.0.as_bytes()[0])
    }

    /// Returns true if this CUSIP identifier is actually a CUSIP International Numbering System
    /// (CINS) identifier (with the further restriction that it *does* use 'I', 'O' or 'Z' as its
    /// country code), false otherwise.
    pub fn is_extended(&self) -> bool {
        is_cins_extended(self.0.as_bytes()[0])
    }

    /// Returns the CINS issuer number.
    ///
    /// The issuer number is the 5 characters following the country code
    /// in the CINS identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use cusip::{CUSIP, CINS};
    ///
    /// let cusip = CUSIP::parse("S08000AA9").unwrap();
    /// let cins = CINS::new(&cusip).unwrap();
    /// assert_eq!(cins.issuer_num(), "08000");
    /// ```
    pub fn issuer_num(&self) -> &str {
        unsafe { from_utf8_unchecked(&self.0.as_bytes()[1..6]) }
    }

    /// Return just the _Issue Number_ portion of the CINS.
    pub fn issue_num(&self) -> &str {
        unsafe { from_utf8_unchecked(&self.0.as_bytes()[6..8]) } // This is safe because we know it is ASCII
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parse_cusip_for_bcc_strict() {
        match CUSIP::parse("09739D100") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "09739D100");
                assert_eq!(cusip.issuer_num(), "09739D");
                assert_eq!(cusip.issue_num(), "10");
                assert_eq!(cusip.check_digit(), '0');
                assert!(!cusip.is_cins());
            }
            Err(err) => panic!("Did not expect parsing to fail: {}", err),
        }
    }

    #[test]
    fn parse_cusip_for_bcc_loose() {
        match CUSIP::parse_loose("\t09739d100    ") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "09739D100");
                assert_eq!(cusip.issuer_num(), "09739D");
                assert_eq!(cusip.issue_num(), "10");
                assert_eq!(cusip.check_digit(), '0');
                assert!(!cusip.is_cins());
            }
            Err(err) => panic!("Did not expect parsing to fail: {}", err),
        }
    }

    #[test]
    fn validate_cusip_for_bcc() {
        // Boise Cascade
        assert!(validate("09739D100"))
    }

    #[test]
    fn validate_cusip_for_dfs() {
        // Discover Financial Services
        assert!(validate("254709108"))
    }

    #[test]
    fn parse_cins() {
        match CUSIP::parse("S08000AA9") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "S08000AA9");
                assert_eq!(cusip.issuer_num(), "S08000");
                assert_eq!(cusip.issue_num(), "AA");
                assert_eq!(cusip.check_digit(), '9');
                assert!(cusip.is_cins());
            }
            Err(err) => panic!("Did not expect parsing to fail: {}", err),
        }
    }

    /// This test case appears on page 3 of ANSI X9.6-2020, in the section "Annex A (Normative):
    /// Modulus 10 Double-Add-Double Technique".
    #[test]
    fn parse_example_from_standard() {
        match CUSIP::parse("837649128") {
            Ok(cusip) => {
                assert_eq!(cusip.to_string(), "837649128");
                assert_eq!(cusip.issuer_num(), "837649");
                assert_eq!(cusip.issue_num(), "12");
                assert_eq!(cusip.check_digit(), '8');
                assert!(!cusip.is_cins());
            }
            Err(err) => panic!("Did not expect parsing to fail: {}", err),
        }
    }

    /// This test case appears on page 3 of ANSI X9.6-2020, in the section "Annex A (Normative):
    /// Modulus 10 Double-Add-Double Technique".
    #[test]
    fn validate_example_from_standard() {
        assert!(validate("837649128"))
    }

    #[test]
    fn reject_empty_string() {
        let res = CUSIP::parse("");
        assert!(res.is_err());
    }

    #[test]
    fn reject_lowercase_issuer_id_if_strict() {
        match CUSIP::parse("99999zAA5") {
            Err(CUSIPError::InvalidIssuerNum { was: _ }) => {} // Ok
            Err(err) => {
                panic!(
                    "Expected Err(InvalidIssuerNum {{ ... }}), but got: Err({:?})",
                    err
                )
            }
            Ok(cusip) => {
                panic!(
                    "Expected Err(InvalidIssuerNum {{ ... }}), but got: Ok({:?})",
                    cusip
                )
            }
        }
    }

    #[test]
    fn reject_lowercase_issue_id_if_strict() {
        match CUSIP::parse("99999Zaa5") {
            Err(CUSIPError::InvalidIssueNum { was: _ }) => {} // Ok
            Err(err) => {
                panic!(
                    "Expected Err(InvalidIssueNum {{ ... }}), but got: Err({:?})",
                    err
                )
            }
            Ok(cusip) => {
                panic!(
                    "Expected Err(InvalidIssueNum {{ ... }}), but got: Ok({:?})",
                    cusip
                )
            }
        }
    }

    #[test]
    fn parse_cusip_with_0_check_digit() {
        CUSIP::parse("09739D100").unwrap(); // BCC aka Boise Cascade
    }

    #[test]
    fn parse_cusip_with_1_check_digit() {
        CUSIP::parse("00724F101").unwrap(); // ADBE aka Adobe
    }

    #[test]
    fn parse_cusip_with_2_check_digit() {
        CUSIP::parse("02376R102").unwrap(); // AAL aka American Airlines
    }

    #[test]
    fn parse_cusip_with_3_check_digit() {
        CUSIP::parse("053015103").unwrap(); // ADP aka Automatic Data Processing
    }

    #[test]
    fn parse_cusip_with_4_check_digit() {
        CUSIP::parse("457030104").unwrap(); // IMKTA aka Ingles Markets
    }

    #[test]
    fn parse_cusip_with_5_check_digit() {
        CUSIP::parse("007800105").unwrap(); // AJRD aka Aerojet Rocketdyne Holdings
    }

    #[test]
    fn parse_cusip_with_6_check_digit() {
        CUSIP::parse("98421M106").unwrap(); // XRX aka Xerox
    }

    #[test]
    fn parse_cusip_with_7_check_digit() {
        CUSIP::parse("007903107").unwrap(); // AMD aka Advanced Micro Devices
    }

    #[test]
    fn parse_cusip_with_8_check_digit() {
        CUSIP::parse("921659108").unwrap(); // VNDA aka Vanda Pharmaceuticals
    }

    #[test]
    fn parse_cusip_with_9_check_digit() {
        CUSIP::parse("020772109").unwrap(); // APT aka AlphaProTec
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
            CUSIP::parse(case).unwrap();
            assert!(
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
            CUSIP::parse(&s);
        }
    }
}
