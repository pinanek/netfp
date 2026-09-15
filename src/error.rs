use core::error::Error as BaseError;
use core::fmt::{Display, Formatter, Result as FmtResult};

/// Errors that can occur while constructing, encoding, or parsing network
/// protocol data.
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

    /// The data violates an expected format or constraint.
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
