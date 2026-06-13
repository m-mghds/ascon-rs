# ASCON-Rust

![Rust CI](https://github.com/m-mghds/ascon-rs/actions/workflows/ci.yml/badge.svg)
![no_std](https://img.shields.io/badge/no__std-supported-brightgreen)

A `no_std` Rust implementation of **Ascon-AEAD128**, focusing on a clean, educational, allocation-free, and constrained-device-friendly design.

## Current Status

This project is currently a work in progress.

Implemented:

* Ascon permutation
* Ascon-AEAD128 initialization
* Associated data absorption
* Plaintext encryption
* Ciphertext decryption
* Finalization and authentication tag generation
* Authentication tag verification during decryption
* Plaintext buffer wiping on failed authentication
* `no_std` library core
* Caller-provided input/output buffers with no heap allocation in the core AEAD API
* Encryption and decryption checked against known-answer test vectors
* Interactive demo binary for default and custom hex-based encryption/decryption tests
* Ascon-Hash256
* Ascon-XOF128

Not implemented yet:

* Extended test suite
* External security audit

## Features

* `no_std` library core
* Allocation-free AEAD API
* Encryption with authentication tag generation
* Decryption with authentication tag verification
* Caller-provided ciphertext/plaintext buffers
* Suitable as a starting point for constrained-device and embedded cryptography experiments

## Usage as a Library

The core API does not allocate memory internally. The caller provides the output buffer.

### Encryption

```rust
use ascon_rs::aead;
use ascon_rs::key::Key;

let key = Key::from_bytes([0u8; 16]);
let nonce = [0u8; 16];
let ad = b"example associated data";
let plaintext = b"Hello, Ascon-AEAD128!";

let mut ciphertext = [0u8; 21];

let tag = aead::encrypt_into(
    &key,
    &nonce,
    ad,
    plaintext,
    &mut ciphertext,
)?;
```

The ciphertext buffer must have the same length as the plaintext.

### Decryption

```rust
let mut recovered = [0u8; 21];

aead::decrypt_into(
    &key,
    &nonce,
    ad,
    &ciphertext,
    &tag,
    &mut recovered,
)?;

assert_eq!(&recovered, plaintext);
```

If authentication fails, decryption returns an error and wipes the plaintext output buffer.

## Interactive Demo

The repository also includes an interactive demo binary using `std` for terminal input and output.

Run:

```bash
cargo run
```

The demo lets you choose between:

1. A default encrypt/decrypt example
2. Custom encryption using hex-encoded key, nonce, AD, and plaintext
3. Custom decryption using hex-encoded key, nonce, AD, ciphertext, and tag

Example custom encryption inputs:

```text
Key:
000102030405060708090A0B0C0D0E0F

Nonce:
101112131415161718191A1B1C1D1E1F

AD:
303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F

Plaintext:
202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F
```

For decryption, provide the ciphertext and 16-byte tag separately.

## Building and Testing

Format the code:

```bash
cargo fmt
```

Run Clippy:

```bash
cargo clippy
```

Run tests:

```bash
cargo test
```

Build the `no_std` library core:

```bash
cargo build --lib
```

Run the interactive demo:

```bash
cargo run
```

## Notes

The library core is written as `no_std`. The interactive demo binary uses `std` only for terminal input/output.

This implementation is intended for learning, experimentation, and future work on constrained-device-friendly cryptographic code. It has not been independently audited and should not be used in production without further review.
