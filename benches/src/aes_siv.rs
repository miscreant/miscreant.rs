//! AES-(CMAC-)SIV benchmarks

#![deny(warnings)]

#[macro_use]
extern crate criterion;

use criterion::{Benchmark, Criterion, Throughput};
use miscreant::Aes128Siv;

// WARNING: Do not ever actually use a key of all zeroes
// NOTE: AES-SIV keys are 2 * the security level, since they include
//       independent encryption and MAC keys.
const KEY_256_BIT: [u8; 32] = [0u8; 32];
const NONCE: [u8; 12] = [0u8; 12];

fn aes_siv_128_encrypt_benchmark(msg_size: usize) -> Benchmark {
    Benchmark::new(format!("encrypt ({} bytes)", msg_size), move |b| {
        let mut siv = Aes128Siv::new(&KEY_256_BIT);

        // Plaintext length + 16-byte tag
        let mut buffer = vec![0u8; msg_size + 16];

        b.iter(|| siv.seal_in_place(&[NONCE], &mut buffer));
    })
    .throughput(Throughput::Bytes(msg_size as u32))
}

fn aes_siv_128_encrypt_128_bytes(c: &mut Criterion) {
    c.bench("AES-128-CMAC-SIV", aes_siv_128_encrypt_benchmark(128));
}

fn aes_siv_128_encrypt_1024_bytes(c: &mut Criterion) {
    c.bench("AES-128-CMAC-SIV", aes_siv_128_encrypt_benchmark(1024));
}

fn aes_siv_128_encrypt_16384_bytes(c: &mut Criterion) {
    c.bench("AES-128-CMAC-SIV", aes_siv_128_encrypt_benchmark(16384));
}

criterion_group! {
    name = aes_siv_128_encrypt;
    config = Criterion::default();
    targets = aes_siv_128_encrypt_128_bytes, aes_siv_128_encrypt_1024_bytes, aes_siv_128_encrypt_16384_bytes
}

criterion_main!(aes_siv_128_encrypt);
