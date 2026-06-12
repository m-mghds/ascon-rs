# ASCON-Rust

A Rust implementation of Ascon-AEAD128, focusing on a clean, educational, and `no_std`-friendly design.

## Current Status

This project is currently a work in progress.

Implemented:

* Ascon permutation
* Ascon-AEAD128 initialization
* Associated data absorption
* Plaintext encryption
* Finalization and tag generation
* `no_std` library core
* Encryption verified against known-answer test vectors

Not implemented yet:

* Decryption
* Authentication tag verification
* Ascon-Hash256
* Ascon-XOF128
* Extended test suite

## Usage

The library currently provides encryption through a caller-provided output buffer:

```rust
let mut ciphertext = [0u8; 32];

let tag = ascon_rs::aead::encrypt_into(
    &key,
    &nonce,
    ad,
    plaintext,
    &mut ciphertext,
)?;
```

The ciphertext buffer must have the same length as the plaintext.

## Notes

The library core is written as `no_std`. The example binary may use `std` only for demonstration and printing output.

This implementation is intended for learning, experimentation, and future work on constrained-device-friendly cryptographic code. It has not yet been audited for production use.
