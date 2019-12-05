//! `Miscreant`: Misuse resistant symmetric encryption library providing the
//! AES-SIV (RFC 5297), AES-PMAC-SIV, and STREAM constructions
//!
//! ## Minimum Supported Rust Version (MSRV)
//!
//! - Rust **1.36.0**
//!
//! ### `x86`/`x86_64` targets with AES-NI support
//!
//! To build this crate with hardware acceleration support on `x86`/`x86_64`
//! targets with [AES-NI] support, set the following `RUSTFLAGS` environment
//! variable:
//!
//! `RUSTFLAGS=-Ctarget-feature=+aes,+ssse3`
//!
//! You can configure your `~/.cargo/config` to always pass these flags:
//!
//! ```toml
//! [build]
//! rustflags = ["-Ctarget-feature=+aes,+ssse3"]
//! ```
//!
//! [AES-NI]: https://en.wikipedia.org/wiki/AES_instruction_set#x86_architecture_processors

#![no_std]
#![doc(html_root_url = "https://docs.rs/miscreant/0.5.1")]
#![warn(missing_docs, rust_2018_idioms, unsafe_code, unused_qualifications)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod aead;
pub mod ffi;
#[cfg(feature = "stream")]
pub mod stream;

pub use crate::aead::{Aead, Aes128SivAead, Aes256SivAead, SivAead};
pub use aes_siv::{
    aead::{generic_array, Error},
    siv::{self, Aes128Siv, Aes256Siv},
};

#[cfg(feature = "pmac")]
pub use crate::aead::{Aes128PmacSivAead, Aes256PmacSivAead};
#[cfg(feature = "pmac")]
pub use aes_siv::siv::{Aes128PmacSiv, Aes256PmacSiv};
