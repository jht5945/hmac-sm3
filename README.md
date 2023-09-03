HMAC-SM3 by `hmac_sm3`

```rust
let message = b"Hello World";
let key = b"TestSecret";

let hmac1 = hmac_sm3(key, message);
assert_eq!("9d91da552268ddf11b9f69662773a66c6375b250336dfb9293e7e2611c36d79f", hex::encode(hmac1));
```

or use stream style:

```rust
let mut hm = HmacSm3::new(key);
hm.update(b"Hello");
hm.update(b" ");
hm.update(b"World");
let hmac2 = hm.finalize();
assert_eq!("9d91da552268ddf11b9f69662773a66c6375b250336dfb9293e7e2611c36d79f", hex::encode(hmac2));
```

Benchmark @MacBook Pro (Retina, 15-inch, Late 2013/2 GHz Quad-Core Intel Core i7)
```text
$ cargo run --release --example bench
HMAC-SM3         : 219.19 M/s
HMAC-SHA1        : 228.57 M/s
HMAC-SHA256      : 204.96 M/s
```
