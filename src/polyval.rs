//! WARNING! WARNING! WARNING!
//!
//! This implementation is incomplete, broken, and insecure.
//!
//! DO NOT USE!

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use std::marker::PhantomData;
use zeroize::Zeroize;

/// The POLYVAL universal hash function
pub type Polyval = PolyvalCore<LittleEndian>;

/// The GHASH universal hash function
pub type GHash = PolyvalCore<BigEndian>;

/// WARNING! WARNING! WARNING! BROKEN, INCOMPLETE IMPLEMENTATION!
///
/// POLYVAL: GHASH-like universal hash over GF(2^128).
///
/// From the latest `draft-irtf-cfrg-gcmsiv`, Appendix A:
///
/// > The relationship between POLYVAL and GHASH
/// >
/// > GHASH and POLYVAL both operate in GF(2^128), although with different
/// > irreducible polynomials: POLYVAL works modulo x^128 + x^127 + x^126 +
/// > x^121 + 1 and GHASH works modulo x^128 + x^7 + x^2 + x + 1.  Note
/// > that these irreducible polynomials are the "reverse" of each other.
///
/// Using this property, we are able to implement both the POLYVAL and GHASH
/// functions in terms of POLYVAL simply by being generic over the byte order.
/// However, POLYVAL has the advantage of being optimized for natively
/// little-endian CPUs.
#[repr(align(16))]
pub struct PolyvalCore<O: ByteOrder> {
    h: u128,
    s: u128,
    o: PhantomData<O>,
}

const XMM_MASK: u128 = 0x0001_c200_0000_0000_0000;

impl<O> PolyvalCore<O>
where
    O: ByteOrder,
{
    /// Create a new POLYVAL instance
    pub fn new(h: &[u8; 16]) -> Self {
        Self {
            h: O::read_u128(h),
            s: 0,
            o: PhantomData,
        }
    }

    /// Input a block into the POLYVAL function
    pub fn input(&mut self, block: &[u8; 16]) {
        let x = self.s ^ O::read_u128(block);

        let t1 = pclmulqdq(x, self.h, 0x00);
        let t2 = pclmulqdq(x, self.h, 0x01);
        let t3 = pclmulqdq(x, self.h, 0x10);
        let t4 = pclmulqdq(x, self.h, 0x11);
        let t5 = t2 ^ t3;

        let mut t6 = t1 ^ ((t5 & 0xFFFF_FFFF) << 64);
        t6 = pclmulqdq(XMM_MASK, t6, 0x01) ^ t6.rotate_left(64);
        t6 = pclmulqdq(XMM_MASK, t6, 0x01) ^ t6.rotate_left(64);

        self.s = t4 ^ (t5 >> 64) ^ t6
    }

    /// Get the serialized result
    pub fn result(self) -> [u8; 16] {
        let mut output = [0u8; 16];
        O::write_u128(&mut output, self.s);
        output
    }
}

impl<O> Drop for PolyvalCore<O>
where
    O: ByteOrder,
{
    fn drop(&mut self) {
        self.h.zeroize();
        self.s.zeroize();
    }
}

/// Software polyfill for the PCLMULQDQ CPU instruction
fn pclmulqdq(a: u128, b: u128, imm: u8) -> u128 {
    match imm {
        0x00 => clmul((a & 0xFFFF_FFFF) as u64, (b & 0xFFFF_FFFF) as u64),
        0x01 => clmul(((a >> 64) & 0xFFFF_FFFF) as u64, (b & 0xFFFF_FFFF) as u64),
        0x10 => clmul((a & 0xFFFF_FFFF) as u64, ((b >> 64) & 0xFFFF_FFFF) as u64),
        0x11 => clmul(
            ((a >> 64) & 0xFFFF_FFFF) as u64,
            ((b >> 64) & 0xFFFF_FFFF) as u64,
        ),
        _ => panic!("invalid immediate byte value: 0x{:02x}", imm),
    }
}

/// Carryless multiplication
fn clmul(a: u64, b: u64) -> u128 {
    let mut r = [0u64; 2];

    for i in 0..64 {
        if b & 1 << i != 0 {
            r[1] ^= a;
        }

        r[0] >>= 1;

        if r[1] & 1 != 0 {
            r[0] ^= 1 << 63;
        }

        r[1] >>= 1;
    }

    (u128::from(r[0]) << 64) | u128::from(r[1])
}
