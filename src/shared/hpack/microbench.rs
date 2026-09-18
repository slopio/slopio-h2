//! TEMPORARY — decode-path micro-benchmark, to be removed.
//!
//! cargo test --release --lib microbench -- --ignored --nocapture

use std::hint::black_box;
use std::io::Cursor;
use std::time::Instant;

use super::huffman;
use super::{Decoder, Header};

/// HPACK integer, `prefix` bits in the first byte (RFC 7541 §5.1).
fn put_int(out: &mut Vec<u8>, mut value: usize, prefix: u8, first: u8) {
    let max = (1usize << prefix) - 1;
    if value < max {
        out.push(first | value as u8);
        return;
    }
    out.push(first | max as u8);
    value -= max;
    while value >= 128 {
        out.push((value % 128 + 128) as u8);
        value /= 128;
    }
    out.push(value as u8);
}

/// `if-none-match: <value>`, name from the static table (index 41), value as
/// a Huffman literal — the shape nghttp2 sends for a header it will not index.
fn block_field(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_int(&mut out, 41, 4, 0x00); // literal without indexing, indexed name
    let mut huff = bytes::BytesMut::new();
    huffman::encode(value, &mut huff);
    put_int(&mut out, huff.len(), 7, 0x80);
    out.extend_from_slice(&huff);
    out
}

/// `:path: <value>`, static index 4, Huffman literal — the pseudo-header
/// path, which hands the `Bytes` over without copying it.
fn block_path(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_int(&mut out, 4, 4, 0x00);
    let mut huff = bytes::BytesMut::new();
    huffman::encode(value, &mut huff);
    put_int(&mut out, huff.len(), 7, 0x80);
    out.extend_from_slice(&huff);
    out
}

fn time(label: &str, block: &[u8], iters: usize) {
    let mut decoder = Decoder::new(4096);
    // Warm the staging buffer and the table.
    for _ in 0..1000 {
        let mut buf = decoder.stage(block);
        let mut cur = Cursor::new(&mut buf);
        decoder.decode(&mut cur, |h| drop(black_box(h))).unwrap();
    }

    let mut best = f64::MAX;
    for _ in 0..5 {
        let start = Instant::now();
        for _ in 0..iters {
            let mut buf = decoder.stage(black_box(block));
            let mut cur = Cursor::new(&mut buf);
            decoder
                .decode(&mut cur, |h: Header| drop(black_box(h)))
                .unwrap();
        }
        let ns = start.elapsed().as_nanos() as f64 / iters as f64;
        best = best.min(ns);
    }
    println!("{label:44} {best:8.1} ns/block");
}

#[test]
#[ignore]
fn microbench_huffman() {
    // Realistic header text rather than one repeated character: the code
    // lengths differ per byte, so a single-character string would walk a
    // single path of the table and cache far better than real traffic does.
    let sample = b"/api/v3/tenants/acme/orders/items/detail?page=42&sort=created_at&filter=open";
    for reps in [1usize, 4, 16] {
        let mut text = Vec::new();
        for _ in 0..reps {
            text.extend_from_slice(sample);
        }
        let mut encoded = bytes::BytesMut::new();
        huffman::encode(&text, &mut encoded);

        let mut out = bytes::BytesMut::with_capacity(4096);
        for _ in 0..1000 {
            drop(black_box(huffman::decode(&encoded, &mut out).unwrap()));
        }

        let iters = 200_000;
        let mut best = f64::MAX;
        for _ in 0..5 {
            let start = Instant::now();
            for _ in 0..iters {
                drop(black_box(
                    huffman::decode(black_box(&encoded), &mut out).unwrap(),
                ));
            }
            best = best.min(start.elapsed().as_nanos() as f64 / iters as f64);
        }
        println!(
            "huffman decode {:5} B in -> {:5} B out {:8.1} ns  ({:.2} ns/byte out)",
            encoded.len(),
            text.len(),
            best,
            best / text.len() as f64
        );
    }
}

#[test]
#[ignore]
fn microbench_decode() {
    for len in [16usize, 64, 256] {
        let value = vec![b'7'; len];
        time(&format!("if-none-match, {len} B huffman literal"), &block_field(&value), 200_000);
        time(&format!(":path,         {len} B huffman literal"), &block_path(&value), 200_000);
    }
    // Indexed field, nothing decoded at all: the floor.
    time("indexed field (:method GET)", &[0x82], 200_000);
}
