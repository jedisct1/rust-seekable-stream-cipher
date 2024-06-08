# Seekable Stream Cipher And Encryption/Decryption For Rust

This crate derives a deterministic 2^64 byte key stream from a secret key, and allows applications to randomly read that stream from any offset.

The key stream can also be used to encrypt or decrypt arbitrary ranges of a large message.

## [API documentation](https://docs.rs/seekable-stream-cipher)

## Usage Example

### Filling Buffers With The Seekable Key Stream

```rust
use seekable_stream_cipher::keccak::StreamCipher;

/// Create a new 32-byte secret key using a secure random number generator
let mut key = [0u8; StreamCipher::KEY_LENGTH];
getrandom::getrandom(&mut key).unwrap();

/// Initialize the stream cipher using the key, and a context.
/// A key used with different contexts produces different key streams.
let st = StreamCipher::new(&key, b"fill test");

/// Fill a buffer with 10000 bytes from the key stream starting at offset 10
let mut out = [0u8; 10000];
st.fill(&mut out, 10).unwrap();

/// Fill another buffer with 50 bytes from key key stream starting at offset 100
let mut out2 = [0u8; 50];
st.fill(&mut out2, 100).unwrap();

/// Verify that the second buffer is a slice of the first one, since the ranges overlap.
assert_eq!(out[90..][..50], out2);
```

### Encrypting/Decrypting Arbitrary Ranges

```rust
use seekable_stream_cipher::keccak::StreamCipher;

/// Create a new 32-byte secret key using a secure random number generator
let mut key = [0u8; StreamCipher::KEY_LENGTH];
getrandom::getrandom(&mut key).unwrap();

/// Initialize the stream cipher using the key, and a context.
/// A key used with different contexts produces different key streams.
let st = StreamCipher::new(&key, b"encryption test");

/// Create a large message filled with random junk
let mut msg = [0u8; 10000];
getrandom::getrandom(&mut msg).unwrap();

/// Create a copy of the message
let mut msg2 = msg.clone();

/// Encrypt range 5..500 of that message
st.apply_keystream(&mut msg2[5..500], 5);

/// Now, that range is encrypted.
assert!(msg != msg2);

/// Decrypt range 5.500 by calling the same function as for encryption, with the same parameters
st.apply_keystream(&mut msg2[5..500], 5);

/// Check that we recovered the original message.
assert_eq!(msg, msg2);
```

## Primitives Selection

### Rationale

The main selection criteria for the primitive were:

- ability to encrypt from arbitrary offsets, with a byte granularity, and without having access to previously encrypted content.
- security and efficiency in a WebAssembly environment.

The first constraint disqualifies any block cipher larger than 8 bits.

On WebAssembly, AES-based constructions are either very slow or unprotected against side channel attacks.

That leaves us with uncommon/deprecated stream ciphers, ChaCha20 variants, or stream ciphers built on top of standard public permutations.

Due to limitations in Rust and WebAssembly, ChaCha20's performance is not great compared to native, optimized implementations, especially when using Wasmtime on an x86_64 platform (for some reason, results are more consistent on aarch64).

Keccak and Ascon are a better fit for WebAssembly. They only use bitwise boolean operations on 64-bit words, require minimal temporary registers and can be efficiently scheduled by most compilers. Furthermore, they don't use look-up tables, so they are inherently more secure against side channels than e.g. AES.

Using Keccak, a stream cipher with at least 128-bit security can be built using Keccak-f[1600] with 12 rounds and a 320-bit capacity, leaving 160 bytes for the rate to absorb the context.

The Ascon permutation is smaller. We use the parameters of the Ascon-PRF construction, which absorbs the context as 32 byte blocks.

### Benchmarks

WebAssembly (Wasmtime, Zen4 CPU)

| Primitive   | Throughput |
| ----------- | ---------- |
| ChaCha20/12 | 494.33 M/s |
| Keccak      | 452.72 M/s |
| Ascon       | 534.18 M/s |
| AES-128     | 77.55 M/s  |

On WebAssembly, ChaCha20/12, Keccak and Ascon are in the same ballpark, while bitsliced AES is about 7 times slower.

This crate implements an Ascon-based stream cipher, a Keccak-based stream cipher and the ChaCha20/12 stream cipher. All these options are decent choices for WebAssemby, and are made of standard building blocks.

Performance can be improved by using SIMD instructions, but they are not stable nor universally supported by WebAssembly runtimes yet.
