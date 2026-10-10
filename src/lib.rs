#![doc = include_str!("../README.md")]

//! See [`tls`] for message parsing and encoding. Fingerprint functions are
//! available with the `ja3` and `jarm` features, both enabled by default.

mod error;
#[cfg(feature = "ja3")]
mod ja3;
#[cfg(feature = "jarm")]
mod jarm;
pub mod primitives;
pub mod tls;
mod utils;

pub use error::Error;
#[cfg(feature = "ja3")]
pub use ja3::{ja3_fingerprint, ja3s_fingerprint};
#[cfg(feature = "jarm")]
pub use jarm::{generate_jarm_probes, jarm_fingerprint};
