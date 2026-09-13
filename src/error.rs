use core::error::Error as BaseError;
use core::fmt::{Display, Formatter, Result as FmtResult};

/// An error produced while encoding or decoding structured binary data.
///
/// # Examples
///
/// Errors can be inspected to distinguish incomplete input from structurally
/// invalid data:
///
/// ```
/// use netfp::Error;
///
/// let error = Error::UnexpectedEof {
///     needed: 4,
///     remaining: 2,
/// };
///
/// assert_eq!(
///     error.to_string(),
///     "unexpected end of data: needed 4 bytes, but only 2 remain",
/// );
/// ```
#[derive(Debug)]
pub enum Error {
    /// An encoded value is too large for its length field or format limit.
    LengthOverflow {
        /// Maximum supported length, in bytes.
        max: usize,
        /// Length that was requested or calculated, in bytes.
        actual: usize,
    },

    /// The input ended before a complete field or message could be read.
    UnexpectedEof {
        /// Number of bytes required by the attempted read.
        needed: usize,
        /// Number of unread bytes that were available.
        remaining: usize,
    },

    /// The input is complete enough to inspect but violates the expected
    /// structure or a semantic constraint enforced by this crate.
    Malformed(
        /// Static description of the violated constraint.
        &'static str,
    ),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::LengthOverflow { max, actual } => {
                write!(f, "length exceeds maximum: {actual} > {max}")
            }
            Self::UnexpectedEof { needed, remaining } => {
                write!(
                    f,
                    "unexpected end of data: needed {needed} bytes, but only {remaining} remain"
                )
            }
            Self::Malformed(message) => {
                write!(f, "malformed data: {message}")
            }
        }
    }
}

impl BaseError for Error {}
