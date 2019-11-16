//! `Miscreant`: Misuse resistant symmetric encryption library providing the
//! AES-SIV (RFC 5297), AES-PMAC-SIV, and STREAM constructions
//!
//! ## Minimum Supported Rust Version (MSRV)
//!
//! - Rust 1.36.0
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
#![doc(html_root_url = "https://docs.rs/miscreant/0.4.2")]
#![warn(
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unused_qualifications
)]

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

pub mod aead;
mod error;
pub mod ffi;
pub mod siv;
#[cfg(feature = "stream")]
pub mod stream;

pub use crate::{
    aead::{Aead, Aes128PmacSivAead, Aes128SivAead, Aes256PmacSivAead, Aes256SivAead},
    error::Error,
    siv::{s2v, Aes128PmacSiv, Aes128Siv, Aes256PmacSiv, Aes256Siv},
};

pub(crate) use aes::{Aes128, Aes256};

/// Size of the (synthetic) initialization vector in bytes
pub const IV_SIZE: usize = 16;

#[cfg(not(any(feature = "std", test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
