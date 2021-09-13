#![warn(missing_docs)]
//! # cusip::checksum
//!
//! Implementation of the checksum algorithm for CUSIP

/// The numeric value of a u8 ASCII character. Digit characters '0' through '9' map to values 0
/// through 9, and letter characters 'A' through 'Z' map to values 10 through 35.
///
/// # Panics
///
/// If anything other than an uppercase ASCII alphanumeric character is passed in, this function
/// panics because it is only intended to be called from locations where the input has already been
/// validated to match the character set requirements.
fn char_value(c: &u8) -> u8 {
    if (b'0'..=b'9').contains(c) {
        c - b'0'
    } else if (b'A'..=b'Z').contains(c) {
        c - b'A' + 10
    } else {
        panic!("Non-ASCII-alphanumeric characters should be impossible here!");
    }
}

/// The maximum value the accumulator can have and still be able to go another iteration without
/// overflowing. Used to determine when to reduce the accumulator with a modulus operation.
///
/// The maximum amount that can be added in a single iteration occurs when the underlying character
/// value is 34 (letter 'Y') and it is in a doubling position. In that case, the double value is 68,
/// and we add 6 + 8 = 14 to the sum. So, we subtract that value from the maximum u8 value to get
/// the threshold at which we must pre-mod the sum before adding at that step.
///
/// You can see this easily with the Mathematica code to generate the table:
///
/// ```mathematica
/// Table[{n, n*2, Quotient[n * 2, 10],
///     Mod[n * 2, 10], Quotient[n * 2, 10] + Mod[n * 2, 10]}, {n, 0,
///     35}] // TableForm
/// ```
const MAX_ACCUM_SIMPLE: u8 = u8::MAX - 14;

const MAX_ACCUM_TABLE: u8 = u8::MAX - 9;

#[rustfmt::skip]
const ODDS: [u8; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    2, 3, 4, 5, 6, 7, 8, 9, 0, 1,
    3, 4, 5, 6, 7, 8
];

#[rustfmt::skip]
const EVENS: [u8; 36] = [
    0, 2, 4, 6, 8,
    1, 3, 5, 7, 9,
    2, 4, 6, 8, 0,
    3, 5, 7, 9, 1,
    4, 6, 8, 0, 2,
    5, 7, 9, 1, 3,
    6, 8, 0, 2, 4,
    7
];

/// Compute the _checksum_ for a u8 array. No attempt is made to ensure the input string is in
/// the CUSIP payload format or length.
///
/// The algorithm processes the input ASCII characters left-to-right, and counting from one, doubles
/// the even ones and leaves the odd ones with their regular values. The sum of these values is
/// reduced mod 10. The final result is (10 - sum) % 10.
///
/// # Panics
///
/// If an illegal character (not an ASCII digit and not an
/// ASCII uppercase letter) is encountered, the char_value() function this calls will panic.
// This should not be public, but it must be so tests and benches can see it
pub fn checksum_simple(s: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for (i, c) in s.iter().enumerate() {
        let v = char_value(c);
        let vv = if ((i + 1) % 2) == 0 { v * 2 } else { v };
        // Cannot trigger on input < 18 bytes long because floor((255 - 14) / 14) = 17.
        if sum > MAX_ACCUM_SIMPLE {
            sum %= 10
        }
        sum += (vv / 10) + (vv % 10)
    }
    sum %= 10;

    (10 - sum) % 10
}

/// This version iterates from right to left, the same way the algorithm works for the isin crate.
/// For an input of even length (in this case, 8), deciding even-vs-odd from left-to-right with
/// one-based indexing is equivalent to deciding from right-to-left with zero-based indexing. We
/// are using the latter to emphasize the similarities with the ISIN algorithm, even though there
/// are important differences.
///
/// The values of entries in the EVENS and ODDS tables can be found by evaluating this Mathematica
/// expression and reading off the values in the "ODD%10" and "EVEN%10" columns:
///
/// ```mathematica
/// Dataset[Table[<|
///     "N" -> n, "N/10" -> Quotient[n, 10],
///     "N%10" -> Mod[n, 10],
///     "ODD" -> Quotient[n, 10] + Mod[n, 10],
///     "ODD%10" -> Mod[Quotient[n, 10] + Mod[n, 10], 10],
///     "N*2" -> n*2, "(N*2)/10" -> Quotient[n * 2, 10],
///     "(N*2)%10" -> Mod[n * 2, 10],
///     "EVEN" -> Quotient[n * 2, 10] + Mod[n * 2, 10],
///     "EVEN%10" -> Mod[Quotient[n * 2, 10] + Mod[n * 2, 10], 10]
///     |>, {n, 0, 35}]]
/// ```
pub fn checksum_table(s: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    for (i, c) in s.iter().rev().enumerate() {
        let v = char_value(c);
        let v = if (i & 0x1) == 0 {
            EVENS[v as usize]
        } else {
            ODDS[v as usize]
        };
        // Cannot trigger on input < 28 bytes long because floor((255 - 14) / 14) = 27.
        if sum > MAX_ACCUM_TABLE {
            sum %= 10
        }
        sum += v
    }
    sum %= 10;
    (10 - sum) % 10
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    // Ensure the table-driven method gets the same answer as the simple style implementation
    // for each allowed symbol preceded just by a single zero (to ensure even input length),
    // which exercises the EVEN table, as counted from the *right*.
    #[test]
    fn single_chars_right_of_zero() {
        for c in ('0'..='9').into_iter().chain(('A'..='Z').into_iter()) {
            let s = format!("0{}", c);
            let ss = s.as_bytes();
            let a = checksum_simple(&ss);
            let b = checksum_table(&ss);
            assert_eq!(
                a, b,
                "checksum from table style {} should equal that from simple style {} for \"{}\"",
                b, a, s
            );
        }
    }

    // Ensure the table-driven method gets the same answer as the simple style implementation
    // for each allowed symbol followed just by a single zero (to ensure even input length),
    // which exercises the ODD table, as counted from the *right*.
    #[test]
    fn single_chars_left_of_zero() {
        for c in ('0'..='9').into_iter().chain(('A'..='Z').into_iter()) {
            let s = format!("{}0", c);
            let ss = s.as_bytes();
            let a = checksum_simple(&ss);
            let b = checksum_table(&ss);
            assert_eq!(
                a, b,
                "checksum from table style {} should equal that from simple style {} for \"{}\"",
                b, a, s
            );
        }
    }

    proptest! {
        #[test]
        fn processes_all_valid_strings(s in "[0-9A-Z]{8}") {
            let ss = s.as_bytes();
            let a = checksum_simple(&ss);
            let b = checksum_table(&ss);
            assert_eq!(
                a, b,
                "checksum from table style {} should equal that from simple style {} for \"{}\"",
                b, a, s
            );
        }
    }
}
