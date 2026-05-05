// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Benchmark: steady-state heap memory per in-flight request.
//!
//! Models the hot path of `handle_request`:
//!   parse request bytes → RPC verify (slow) → BLS extract → return
//!
//! For each concurrency level N, spawns N tasks that each hold simulated
//! request-parse allocations across a slow mock-RPC `.await`.  The main
//! thread samples the heap at the midpoint when all N tasks are blocked,
//! producing a table and a `max_concurrent` formula.
//!
//! Usage (release build for representative numbers):
//!   cargo run -p network-node --bin bench-request-mem --release

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// ── Tracking allocator ────────────────────────────────────────────────────────

static CURRENT: AtomicUsize = AtomicUsize::new(0);

struct TrackingAlloc;

unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            CURRENT.fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = System.realloc(ptr, layout, new_size);
        if !new_ptr.is_null() {
            if new_size > layout.size() {
                CURRENT.fetch_add(new_size - layout.size(), Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        new_ptr
    }
}

#[global_allocator]
static ALLOC: TrackingAlloc = TrackingAlloc;

// ── Mock RPC server ───────────────────────────────────────────────────────────

// Simulates a chain RPC endpoint that takes ~300 ms to respond.
const MOCK_DELAY_MS: u64 = 300;

async fn start_mock_server() -> SocketAddr {
    use axum::{routing::get, Router};
    let app = Router::new().route(
        "/verify",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(MOCK_DELAY_MS)).await;
            "ok"
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

// ── Simulated request ─────────────────────────────────────────────────────────

/// Mimics `handle_request` memory footprint:
///   - allocates typical-sized parse buffers that live across the RPC await
///   - calls the mock server (slow — this is where tasks pile up)
///   - runs BLS extraction after the await returns
async fn simulate_request(client: &reqwest::Client, url: &str) {
    // Typical wire sizes from a real RequestForDecryptionKey:
    //   outer PKE ciphertext  ≈ 200 B
    //   decrypted payload     ≈ 340 B  (32 keypair_id + 8 epoch + 64 FDD + 96 proof + 67 enc_key)
    //   FDD slice             ≈  64 B
    //   proof slice           ≈  96 B
    let _ct_bytes: Vec<u8> = vec![1u8; 200];
    let _req_bytes: Vec<u8> = vec![2u8; 340];
    let _fdd_bytes: Vec<u8> = vec![3u8; 64];
    let _proof_bytes: Vec<u8> = vec![4u8; 96];

    // Chain RPC verification — the slow step that keeps all these allocations live.
    let _ = client.get(url).send().await;

    // BLS partial extraction runs after verification returns.
    let scalar = [42u8; 32];
    let _ = network_node::crypto::partial_extract_idk_share(
        network_node::crypto::SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
        &_fdd_bytes,
        &scalar,
        1,
    );
}

// ── Measurement ───────────────────────────────────────────────────────────────

/// Spawns `n` simulated requests, sleeps to the midpoint of the mock delay
/// (when all tasks are blocked waiting for RPC), snapshots the heap, then
/// waits for all tasks to finish.  Returns the raw heap counter at midpoint.
async fn sample_at_concurrency(n: usize, url: &str, client: &reqwest::Client) -> usize {
    let handles: Vec<_> = (0..n)
        .map(|_| {
            let c = client.clone();
            let u = url.to_string();
            tokio::spawn(async move { simulate_request(&c, &u).await })
        })
        .collect();

    // All N tasks should be blocked inside the server's delay by this point.
    tokio::time::sleep(Duration::from_millis(MOCK_DELAY_MS / 2)).await;
    let snapshot = CURRENT.load(Ordering::Relaxed);

    for h in handles {
        let _ = h.await;
    }
    snapshot
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let addr = start_mock_server().await;
    let url = format!("http://{}/verify", addr);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Warm up: one full request to stabilise the tokio runtime, reqwest
    // connection pool, and any lazy-init allocations before recording baseline.
    simulate_request(&client, &url).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let baseline = CURRENT.load(Ordering::Relaxed);
    println!(
        "baseline heap (after warm-up): {} B  ({:.1} KiB)",
        baseline,
        baseline as f64 / 1024.0,
    );
    println!();

    const LEVELS: &[usize] = &[1, 5, 10, 25, 50, 100];

    println!(
        "{:>8}  {:>16}  {:>12}  {:>13}",
        "n_conc", "heap_at_midpoint", "delta_bytes", "per_req_bytes",
    );
    println!("{}", "-".repeat(58));

    let mut per_req_at_100 = 0usize;

    for &n in LEVELS {
        let snapshot = sample_at_concurrency(n, &url, &client).await;
        let delta = snapshot.saturating_sub(baseline);
        let per_req = delta / n.max(1);
        if n == *LEVELS.last().unwrap() {
            per_req_at_100 = per_req;
        }
        println!(
            "{:>8}  {:>16}  {:>12}  {:>13}",
            n, snapshot, delta, per_req,
        );
        // Let connections drain between levels to keep measurements independent.
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let per_req_kib = per_req_at_100 as f64 / 1024.0;
    println!();
    println!("=== Recommendation ===");
    println!(
        "  per_request_heap  ≈  {} B  ({:.1} KiB)   [at n={}]",
        per_req_at_100,
        per_req_kib,
        LEVELS.last().unwrap(),
    );
    println!(
        "  max_concurrent = (memory_limit_bytes - {}) / {}",
        baseline, per_req_at_100,
    );
    println!();
    if per_req_at_100 > 0 {
        println!("  Examples:");
        for &mb in &[128usize, 256, 512, 1024, 2048] {
            let limit: usize = mb * 1024 * 1024;
            let max = limit.saturating_sub(baseline) / per_req_at_100;
            println!("    {:5} MiB  →  max_concurrent ≈ {}", mb, max);
        }
    }
}
