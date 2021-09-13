#![warn(missing_docs)]
//! # cusip::error
//!
//! Error type for CUSIP parsing and building.

use std::error::Error;
use std::fmt::Formatter;
use std::fmt::{Debug, Display};

/// All the ways parsing or building could fail.
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
            }
            CUSIPError::InvalidPayloadLength { was } => {
                write!(f, "InvalidPayloadLength {{ was: {:?} }}", was)
            }
            CUSIPError::InvalidIssuerNumLength { was } => {
                write!(f, "InvalidIssuerNumLength {{ was: {:?} }}", was)
            }
            CUSIPError::InvalidIssueNumLength { was } => {
                write!(f, "InvalidIssueNumLength {{ was: {:?} }}", was)
            }
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
                write!(
                    f,
                    "invalid Issuer Number length {} bytes when expecting 6",
                    was
                )
            }
            CUSIPError::InvalidIssueNumLength { was } => {
                write!(
                    f,
                    "invalid Issue Number length {} bytes when expecting 2",
                    was
                )
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
