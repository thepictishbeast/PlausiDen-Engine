//! Criterion benchmark for `engine_core::duress::verify`.
//!
//! Primary purpose: track the wall-clock cost of a constant-time
//! passphrase check across different match conditions. The three
//! match paths (Real, Duress, NoMatch) should cluster tightly — if
//! any future change to `verify` makes one path materially faster
//! than the others, this bench will flag it (a regression in the
//! constant-time invariant from `duress.rs`'s module docs §1).
//!
//! Criterion is NOT a formal constant-time prover — it averages over
//! noise and the `matched_duress_response.clone()` branch is taken
//! unconditionally in the match arm, so some variance is expected.
//! Treat large divergences (> 2× across paths at the same list size)
//! as a signal to inspect, not an automatic failure.
//!
//! Run:  cargo bench --bench duress_verify -p engine-core
//!
//! Parameterized across duress-list sizes {1, 4, 16} to confirm work
//! is linear in list length (the all-or-nothing iteration invariant).

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use engine_core::duress::{verify, DuressConfig, DuressEntry, DuressResponse};
use std::hint::black_box;

/// Build a config with `n` duress entries. Uses a stable byte pattern
/// for each hash so runs are reproducible across invocations.
fn build_config(n: usize) -> (DuressConfig, Vec<u8>, Vec<u8>) {
    // 32-byte hashes match the size of BLAKE3 / Argon2id output.
    let real_hash: Vec<u8> = (0..32u8).collect();
    let duress: Vec<DuressEntry> = (0..n)
        .map(|i| {
            // Each duress hash is distinct: XOR the index into every
            // byte so no two entries collide and no entry collides
            // with real_hash (which has bytes 0..32).
            let hash: Vec<u8> = real_hash
                .iter()
                .map(|&b| b ^ (i as u8).wrapping_add(1))
                .collect();
            DuressEntry {
                hash,
                response: DuressResponse::MountDecoy,
                label: None,
            }
        })
        .collect();
    let first_duress_hash = duress.first().map(|d| d.hash.clone()).unwrap_or_default();
    let cfg = DuressConfig {
        real_hash: real_hash.clone(),
        duress,
    };
    (cfg, real_hash, first_duress_hash)
}

fn bench_verify(c: &mut Criterion) {
    for &n in &[1usize, 4, 16] {
        let mut group = c.benchmark_group(format!("duress_verify/list_len_{n}"));
        group.throughput(Throughput::Elements(1));

        let (cfg, real_hash, duress_hash) = build_config(n);
        let no_match_hash: Vec<u8> = vec![0xA5u8; 32];

        group.bench_with_input(BenchmarkId::new("match_real", n), &cfg, |b, cfg| {
            b.iter(|| {
                let out = verify(black_box(cfg), black_box(&real_hash)).unwrap();
                black_box(out);
            });
        });

        group.bench_with_input(BenchmarkId::new("match_duress_first", n), &cfg, |b, cfg| {
            b.iter(|| {
                let out = verify(black_box(cfg), black_box(&duress_hash)).unwrap();
                black_box(out);
            });
        });

        group.bench_with_input(BenchmarkId::new("no_match", n), &cfg, |b, cfg| {
            b.iter(|| {
                let out = verify(black_box(cfg), black_box(&no_match_hash)).unwrap();
                black_box(out);
            });
        });

        group.finish();
    }
}

criterion_group!(benches, bench_verify);
criterion_main!(benches);
