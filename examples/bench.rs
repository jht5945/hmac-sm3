use benchmark_simple::{Bench, Options};

use hmac_sm3::hmac_sm3;

fn test_hmac_sm3(m: &mut [u8]) {
    let key = [0u8; 32];

    hmac_sm3(&key, m);
}

fn test_hmac_sha1(m: &mut [u8]) {
    let key = [0u8; 32];

    hmacsha1::hmac_sha1(&key, m);
}

fn test_hmac_sha256(m: &mut [u8]) {
    let key = [0u8; 32];

    let mut hsha256 = hmac_sha256::HMAC::new(&key);
    hsha256.update(m);
    hsha256.finalize();
}

fn main() {
    let bench = Bench::new();
    let mut m = vec![0xd0u8; 16384];

    let options = &Options {
        iterations: 1_000,
        warmup_iterations: 1_00,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    let res = bench.run(options, || test_hmac_sm3(&mut m));
    println!("HMAC-SM3         : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_hmac_sha1(&mut m));
    println!("HMAC-SHA1        : {}", res.throughput(m.len() as _));

    let res = bench.run(options, || test_hmac_sha256(&mut m));
    println!("HMAC-SHA256      : {}", res.throughput(m.len() as _));
}