# ASCON-Rust

![Rust CI](https://github.com/m-mghds/ascon-rs/actions/workflows/ci.yml/badge.svg)
![no\_std](https://img.shields.io/badge/no__std-supported-brightgreen)

A clean, educational, and `no_std` Rust implementation of the main Ascon primitives specified in **NIST SP 800-232**.

This project currently implements:

* **Ascon-AEAD128**
* **Ascon-Hash256**
* **Ascon-XOF128**
* **Ascon-CXOF128**

The library core is designed to be allocation-free and suitable as a starting point for constrained-device and embedded cryptography experiments.

---

## About Ascon

Ascon is a family of lightweight cryptographic primitives selected by NIST for lightweight cryptography standardization. The NIST SP 800-232 standard specifies Ascon-based algorithms for authenticated encryption, hashing, and extendable-output functions.

This repository focuses on the following NIST SP 800-232 primitives:

| Primitive       | Purpose                                                       |
| --------------- | ------------------------------------------------------------- |
| `Ascon-AEAD128` | Authenticated encryption with associated data                 |
| `Ascon-Hash256` | Fixed-length 256-bit hash function                            |
| `Ascon-XOF128`  | Extendable-output function with caller-selected output length |
| `Ascon-CXOF128` | Customized XOF with domain-separation/customization input     |

---

## Current Status

This project is currently intended for learning, experimentation, and implementation study.

Implemented:

* Ascon permutation
* Ascon-AEAD128

  * Initialization
  * Associated data absorption
  * Plaintext encryption
  * Ciphertext decryption
  * Finalization and authentication tag generation
  * Authentication tag verification during decryption
  * Plaintext buffer wiping on failed authentication
* Ascon-Hash256

  * Fixed 32-byte digest output
* Ascon-XOF128

  * Caller-selected output length
  * Prefix-compatible extendable output behavior
* Ascon-CXOF128

  * Customization string support
  * Caller-selected output length
* `no_std` library core
* Caller-provided input/output buffers for variable-length outputs
* Interactive demo binary for AEAD, Hash, XOF, and CXOF
* GitHub Actions CI for formatting, linting, tests, and `no_std` library build

Not yet included:

* Independent external security audit
* Side-channel countermeasures
* Constant-time verification using a dedicated external crate
* Formal verification
* Full production-hardening review

---

## Important Security Notice

This implementation is **not independently audited**.

It is intended for:

* learning Rust cryptographic implementation patterns
* understanding Ascon internals
* experimenting with `no_std`-friendly APIs
* studying lightweight cryptography implementation structure

It should **not** be used in production systems without further review, validation, and security auditing.

---

## `no_std` Design

The library core is written as `no_std`.

That means the core implementation does not depend on Rust's standard library and avoids heap allocation in the cryptographic core APIs.

The interactive demo in `src/main.rs` is different: it uses `std` for terminal input/output, `String`, `Vec`, and printing. This is intentional.

In short:

| Part                    | Uses `std`? | Purpose                               |
| ----------------------- | ----------: | ------------------------------------- |
| Library core            |          No | `no_std` cryptographic implementation |
| Interactive demo binary |         Yes | Human-friendly CLI/demo interface     |

So the project can still be considered a `no_std` library, even though the demo binary uses `std`.

---

## Project Structure

A simplified overview of the repository structure:

```text
src/
├── lib.rs              # no_std library entry point
├── main.rs             # std-based interactive demo
├── state.rs            # 320-bit Ascon state representation
├── permutation.rs      # Ascon permutation p[12] and p[8]
├── key.rs              # Key wrapper
├── initialization.rs   # AEAD initialization
├── finalization.rs     # AEAD finalization and tag generation
├── aead.rs             # Ascon-AEAD128 encryption/decryption
└── hash.rs             # Ascon-Hash256, XOF128, and CXOF128
```

---

## Implemented Primitives

### Ascon-AEAD128

`Ascon-AEAD128` provides authenticated encryption with associated data.

Inputs:

* 128-bit key
* 128-bit nonce
* associated data
* plaintext

Outputs:

* ciphertext
* 128-bit authentication tag

The ciphertext has the same length as the plaintext. The authentication tag is returned separately.

### Ascon-Hash256

`Ascon-Hash256` is a fixed-output hash function.

Input:

* message of arbitrary length

Output:

* 32-byte digest

The output size is always:

```text
256 bits = 32 bytes = 64 hex characters
```

### Ascon-XOF128

`Ascon-XOF128` is an extendable-output function.

Input:

* message of arbitrary length
* requested output length

Output:

* output buffer of caller-selected length

For example, the caller can request 16 bytes, 32 bytes, 64 bytes, or any other output length.

For the same message, a shorter XOF output should match the prefix of a longer XOF output.

### Ascon-CXOF128

`Ascon-CXOF128` is a customized extendable-output function.

Inputs:

* customization string
* message
* requested output length

Output:

* output buffer of caller-selected length

The customization string is useful for domain separation. For example, the same message can produce different outputs depending on the intended context:

```text
CXOF("firmware", message, 32 bytes)
CXOF("kdf",      message, 32 bytes)
CXOF("test",     message, 32 bytes)
```

---

## Usage as a Library

The core APIs avoid internal heap allocation for variable-length outputs. The caller provides output buffers.

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

The ciphertext buffer must have the same length as the plaintext.

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

let message = b"Hello, Ascon-Hash256!";
let digest = hash::hash256(message);

assert_eq!(digest.len(), 32);
```

### XOF128

```rust
use ascon_rs::hash;

let message = b"Hello, Ascon-XOF128!";
let mut output = [0u8; 64];

hash::xof128(message, &mut output);

assert_eq!(output.len(), 64);
```

### CXOF128

```rust
use ascon_rs::hash;

let customization = b"demo-context";
let message = b"Hello, Ascon-CXOF128!";
let mut output = [0u8; 32];

hash::cxof128(customization, message, &mut output)?;

assert_eq!(output.len(), 32);
```

---

## Interactive Demo

The repository includes an interactive demo binary in `src/main.rs`.

Run it with:

```bash
cargo run
```

The demo first asks which Ascon primitive you want to use:

```text
ASCON Demo
1) ASCON AEAD
2) ASCON HASH
3) ASCON XOF
4) ASCON CXOF
```

### AEAD Demo

The AEAD menu supports:

```text
1) Default encrypt/decrypt demo
2) Encrypt custom input
3) Decrypt custom input
```

For custom encryption/decryption:

* key is entered as hex
* nonce is entered as hex
* AD can be entered as text or hex
* plaintext can be entered as text or hex
* ciphertext and tag are printed as hex

The ciphertext and tag are also printed in KAT-style format:

```text
Ciphertext || Tag
```

### Hash Demo

The Hash menu supports:

```text
1) Default hash demo
2) Hash custom message
```

For a custom message, the demo allows text/UTF-8 or hex input.

The digest is always 32 bytes.

### XOF Demo

The XOF menu supports:

```text
1) Default XOF demo
2) XOF custom message
```

For custom XOF, the user chooses:

* message input format
* output length in bytes

### CXOF Demo

The CXOF menu supports:

```text
1) Default CXOF demo
2) CXOF custom message
```

For custom CXOF, the user chooses:

* customization input format
* message input format
* output length in bytes

---

## Example AEAD Input

Example values for custom AEAD encryption:

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

For decryption, provide the ciphertext and 16-byte authentication tag separately.

---

## Building and Testing

Format the code:

```bash
cargo fmt
```

Check formatting:

```bash
cargo fmt --check
```

Run Clippy:

```bash
cargo clippy --all-targets -- -D warnings
```

Run tests:

```bash
cargo test
```

Build the library core:

```bash
cargo build --lib
```

Check the `no_std` library build for an embedded target:

```bash
cargo build --lib --target thumbv7em-none-eabihf
```

Run the interactive demo:

```bash
cargo run
```

---

## Continuous Integration

This repository uses GitHub Actions CI.

The CI workflow checks:

* Rust formatting
* Clippy warnings
* unit tests
* `no_std` library build for an embedded target

The CI badge at the top of this README shows whether the current repository state passes these checks.

---

## Development Notes

Some important design choices:

* AEAD uses caller-provided ciphertext/plaintext buffers.
* Hash256 returns a fixed `[u8; 32]` digest.
* XOF128 and CXOF128 write into caller-provided output buffers.
* The library core is `no_std`.
* The demo binary uses `std` only for terminal interaction.
* Hex input is useful for known-answer tests and byte-exact crypto test vectors.
* Text input is converted to UTF-8 bytes before encryption or hashing.

---

## Limitations

This project does not currently provide:

* side-channel protections
* formal verification
* production audit
* constant-time guarantees beyond the implementation choices made in the code
* compatibility wrapper traits for external Rust crypto ecosystem crates

---

## License

This project is released under the MIT License.

---

## Author

Maintained by **Mostafa Moghaddas** (`m-mghds`).

---

## Disclaimer

This project is an educational and experimental implementation of Ascon primitives in Rust. It is useful for learning and research-oriented implementation work, but it should not be used in production without further validation and independent security review.
