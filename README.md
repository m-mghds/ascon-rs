# ASCON-Rust

![Rust CI](https://github.com/m-mghds/ascon-rs/actions/workflows/ci.yml/badge.svg)
![no\_std](https://img.shields.io/badge/no__std-supported-brightgreen)

A clean and educational `no_std` Rust implementation of the main Ascon primitives specified in **NIST SP 800-232**.

This repository currently supports:

* **Ascon-AEAD128**
* **Ascon-Hash256**
* **Ascon-XOF128**
* **Ascon-CXOF128**

The goal of this project is to provide a readable, testable, and constrained-device-friendly implementation of Ascon in Rust.

---

## Features

* `no_std` library core
* Allocation-free core APIs for variable-length outputs
* Ascon permutation implementation
* AEAD encryption and decryption
* Authentication tag generation and verification
* Plaintext buffer wiping on failed authentication
* Fixed-output hashing with Ascon-Hash256
* Extendable-output hashing with Ascon-XOF128
* Customized XOF support with Ascon-CXOF128
* Interactive demo CLI for AEAD, Hash, XOF, and CXOF
* GitHub Actions CI for formatting, linting, tests, and embedded-target library build

---

## Implemented Algorithms

| Algorithm       | Description                                                   |
| --------------- | ------------------------------------------------------------- |
| `Ascon-AEAD128` | Authenticated encryption with associated data                 |
| `Ascon-Hash256` | Fixed 256-bit hash output                                     |
| `Ascon-XOF128`  | Extendable-output function with caller-selected output length |
| `Ascon-CXOF128` | Customized XOF with domain separation input                   |

---

## `no_std` Design

The library core is written as `no_std`.

The cryptographic implementation does not rely on Rust's standard library and is designed around caller-provided buffers where variable-length output is needed.

The interactive demo in `src/main.rs` uses `std` for terminal input/output, `String`, `Vec`, and printing. This does not affect the `no_std` nature of the library core.

In short:

| Component            | Uses `std`? |
| -------------------- | ----------: |
| Library core         |          No |
| Interactive CLI demo |         Yes |

---

## Usage

### AEAD Encryption

```rust
use ascon_rs::aead;
use ascon_rs::key::Key;

let key = Key::from_bytes([0u8; 16]);
let nonce = [0u8; 16];

let ad = b"example associated data";
let plaintext = b"Hello, Ascon-AEAD128!";

let mut ciphertext = vec![0u8; plaintext.len()];

let tag = aead::encrypt(
    &key,
    &nonce,
    ad,
    plaintext,
    &mut ciphertext,
)?;
```

### AEAD Decryption

```rust
let mut recovered = vec![0u8; ciphertext.len()];

aead::decrypt(
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

### Hash256

```rust
use ascon_rs::hash;

let digest = hash::hash256(b"Hello, Ascon-Hash256!");

assert_eq!(digest.len(), 32);
```

### XOF128

```rust
use ascon_rs::hash;

let mut output = [0u8; 64];

hash::xof128(b"Hello, Ascon-XOF128!", &mut output);

assert_eq!(output.len(), 64);
```

### CXOF128

```rust
use ascon_rs::hash;

let customization = b"demo-context";
let message = b"Hello, Ascon-CXOF128!";
let mut output = [0u8; 32];

hash::cxof128(customization, message, &mut output)?;
```

---

## Interactive CLI Demo

Run:

```bash
cargo run
```

The demo provides a simple menu:

```text
ASCON Demo
1) ASCON AEAD
2) ASCON HASH
3) ASCON XOF
4) ASCON CXOF
```

The CLI supports default examples and custom inputs.

For custom input:

* key and nonce are entered as hex
* AD and plaintext can be entered as text or hex
* messages for Hash/XOF/CXOF can be entered as text or hex
* XOF and CXOF output length is selected by the user
* ciphertext, tags, digests, and XOF outputs are printed as hex

The CLI is intended for testing, demonstration, and known-answer-vector style experiments.

---

## Project Status

This project is educational and work-in-progress.

It has tests and CI, but it has not been independently audited.

Not currently provided:

* production security audit
* formal verification
* side-channel countermeasures
* full constant-time review
* integration with external Rust crypto traits

---

## License

This project is released under the MIT License.

---

## Disclaimer

This implementation is intended for learning, research, and experimentation. It should not be used in production without further validation and independent security review.
