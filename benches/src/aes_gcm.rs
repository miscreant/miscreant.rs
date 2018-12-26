//! AES-GCM benchmarks (using *ring*) as a reference data point

#![deny(warnings)]

#[macro_use]
extern crate criterion;

use criterion::{Benchmark, Criterion, Throughput};
use ring::aead;

// WARNING: Do not ever actually use a key of all zeroes
const KEY_128_BIT: [u8; 16] = [0u8; 16];
const NONCE: [u8; 12] = [0u8; 12];

fn aes_gcm_128_encrypt_benchmark(msg_size: usize) -> Benchmark {
    Benchmark::new(format!("encrypt ({} bytes)", msg_size), move |b| {
        let sealing_key =
            aead::SealingKey::new(&aead::AES_128_GCM, &KEY_128_BIT[..]).expect("valid key");

        // Plaintext length + 16-byte tag
        let mut buffer = vec![0u8; msg_size + 16];

        b.iter(|| {
            aead::seal_in_place(
                &sealing_key,
                &NONCE,
                &b""[..],
                &mut buffer,
                sealing_key.algorithm().tag_len(),
            )
            .unwrap();
        })
    })
    .throughput(Throughput::Bytes(msg_size as u32))
}

fn aes_gcm_128_encrypt_128_bytes(c: &mut Criterion) {
    c.bench("AES-128-GCM", aes_gcm_128_encrypt_benchmark(128));
}

fn aes_gcm_128_encrypt_1024_bytes(c: &mut Criterion) {
    c.bench("AES-128-GCM", aes_gcm_128_encrypt_benchmark(1024));
}

fn aes_gcm_128_encrypt_16384_bytes(c: &mut Criterion) {
    c.bench("AES-128-GCM", aes_gcm_128_encrypt_benchmark(16384));
}

criterion_group! {
    name = aes_gcm_128_encrypt;
    config = Criterion::default();
    targets = aes_gcm_128_encrypt_128_bytes, aes_gcm_128_encrypt_1024_bytes, aes_gcm_128_encrypt_16384_bytes
}

criterion_main!(aes_gcm_128_encrypt);
