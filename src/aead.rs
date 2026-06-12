use core::convert::TryInto;

use crate::finalization;
use crate::initialization;
use crate::key::Key;
use crate::permutation;
use crate::state::State;

const RATE: usize = 16; // 128 bits = 16 bytes
const DOMAIN_SEPARATOR: u64 = 0x8000_0000_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    OutputLengthMismatch,
    AuthenticationFailed,
}

pub fn encrypt(
    key: &Key,
    nonce: &[u8; 16],
    ad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> Result<[u8; 16], Error> {
    if ciphertext.len() != plaintext.len() {
        return Err(Error::OutputLengthMismatch);
    }
    let mut state = initialization::initialize(key, nonce);

    absorb_ad(&mut state, ad);

    encrypt_plaintext(&mut state, plaintext, ciphertext);

    let tag = finalization::finalize(&mut state, key);

    Ok(tag)
}

pub fn absorb_ad(state: &mut State, ad: &[u8]) {
    if !ad.is_empty() {
        let mut chunks = ad.chunks_exact(RATE);

        // Full 16-byte AD blocks
        for block in &mut chunks {
            absorb_full_rate_block(state, block);
            permutation::p8(state);
        }

        // final padded AD block
        let remainder = chunks.remainder();
        absorb_final_padded_block(state, remainder);
        permutation::p8(state);
    }

    // Domain separation after AD
    state.word_mut()[4] ^= DOMAIN_SEPARATOR;
}

fn absorb_full_rate_block(state: &mut State, block: &[u8]) {
    assert_eq!(block.len(), RATE, "Block size must be exactly 16 bytes");

    // XOR the 16-byte block into the first two words of the state
    let b0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let b1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

    let s = state.word_mut();

    // Absorb into the rate part of the state which is S0 || S1
    s[0] ^= b0;
    s[1] ^= b1;
}

fn absorb_final_padded_block(state: &mut State, block: &[u8]) {
    assert!(block.len() < RATE, "Final block must be less than 16 bytes");

    let s = state.word_mut();

    if block.len() < 8 {
        s[0] ^= load_u64_le(block);
        s[0] ^= pad(block.len());
    } else {
        s[0] ^= load_u64_le(&block[0..8]);
        s[1] ^= load_u64_le(&block[8..]);
        s[1] ^= pad(block.len() - 8);
    }
}

fn load_u64_le(bytes: &[u8]) -> u64 {
    assert!(bytes.len() <= 8, "Cannot load more than 8 bytes into a u64");

    let mut value = 0u64;

    for (i, &byte) in bytes.iter().enumerate() {
        value |= (byte as u64) << (8 * i);
    }
    value
}

fn pad(byte_position: usize) -> u64 {
    assert!(byte_position < 8);

    // Add the Ascon padding byte 0x01 at the next byte position.
    0x01u64 << (8 * byte_position)
}

pub fn encrypt_plaintext(state: &mut State, plaintext: &[u8], ciphertext: &mut [u8]) {
    let mut chunks = plaintext.chunks_exact(RATE);
    let mut offset = 0;

    // Full 16-byte plaintext blocks
    for block in &mut chunks {
        let out = &mut ciphertext[offset..offset + RATE];

        encrypt_full_plaintext_block(state, block, out);
        permutation::p8(state);

        offset += RATE;
    }

    // Final padded plaintext block
    let remainder = chunks.remainder();
    let out = &mut ciphertext[offset..];

    encrypt_final_padded_plaintext_block(state, remainder, out);
}

fn encrypt_full_plaintext_block(state: &mut State, block: &[u8], out: &mut [u8]) {
    assert_eq!(block.len(), RATE, "block must be exactly 16 bytes");
    assert_eq!(out.len(), RATE, "output block must be exactly 16 bytes");

    let p0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let p1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

    let s = state.word_mut();

    s[0] ^= p0;
    s[1] ^= p1;

    out[0..8].copy_from_slice(&s[0].to_le_bytes());
    out[8..16].copy_from_slice(&s[1].to_le_bytes());
}

fn encrypt_final_padded_plaintext_block(state: &mut State, block: &[u8], out: &mut [u8]) {
    assert!(
        block.len() < RATE,
        "final block must be shorter than 16 bytes"
    );

    assert_eq!(
        out.len(),
        block.len(),
        "output length must match final block length"
    );

    let s = state.word_mut();

    if block.len() < 8 {
        s[0] ^= load_u64_le(block);

        let c0 = s[0].to_le_bytes();
        out.copy_from_slice(&c0[..block.len()]);

        s[0] ^= pad(block.len());
    } else {
        s[0] ^= load_u64_le(&block[0..8]);
        s[1] ^= load_u64_le(&block[8..]);

        let c0 = s[0].to_le_bytes();
        let c1 = s[1].to_le_bytes();

        out[0..8].copy_from_slice(&c0);
        out[8..].copy_from_slice(&c1[..block.len() - 8]);

        s[1] ^= pad(block.len() - 8);
    }
}

// DECRYPTION PART
pub fn decrypt(
    key: &Key,
    nonce: &[u8; 16],
    ad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
    plaintext: &mut [u8],
) -> Result<(), Error> {
    if ciphertext.len() != plaintext.len() {
        return Err(Error::OutputLengthMismatch);
    }
    let mut state = initialization::initialize(key, nonce);

    absorb_ad(&mut state, ad);

    decrypt_ciphertext(&mut state, ciphertext, plaintext);

    let computed_tag = finalization::finalize(&mut state, key);

    if constant_time_eq_16(&computed_tag, tag) {
        Ok(())
    } else {
        // The plaintext is not authenticated!!
        for byte in plaintext.iter_mut() {
            *byte = 0;
        }
        Err(Error::AuthenticationFailed)
    }
}

fn decrypt_ciphertext(state: &mut State, ciphertext: &[u8], plaintext: &mut [u8]) {
    let mut chunks = ciphertext.chunks_exact(RATE);
    let mut offset = 0;

    // Full 16-byte ciphertext blocks
    for block in &mut chunks {
        let out = &mut plaintext[offset..offset + RATE];

        decrypt_full_ciphertext_block(state, block, out);
        permutation::p8(state);

        offset += RATE;
    }

    // Final padded ciphertext block
    let remainder = chunks.remainder();
    let out = &mut plaintext[offset..];

    decrypt_final_padded_ciphertext_block(state, remainder, out);
}

fn decrypt_full_ciphertext_block(state: &mut State, block: &[u8], out: &mut [u8]) {
    assert_eq!(block.len(), RATE, "block must be exactly 16 bytes");
    assert_eq!(out.len(), RATE, "output block must be exactly 16 bytes");

    let c0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
    let c1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

    let s = state.word_mut();

    let p0 = s[0] ^ c0;
    let p1 = s[1] ^ c1;

    out[0..8].copy_from_slice(&p0.to_le_bytes());
    out[8..16].copy_from_slice(&p1.to_le_bytes());

    // Update state rate part to ciphertext
    s[0] = c0;
    s[1] = c1;
}

fn decrypt_final_padded_ciphertext_block(state: &mut State, block: &[u8], out: &mut [u8]) {
    assert!(
        block.len() < RATE,
        "final block must be shorter than 16 bytes"
    );

    assert_eq!(
        out.len(),
        block.len(),
        "output length must match final block length"
    );

    let s = state.word_mut();

    if block.len() < 8 {
        let c0 = load_u64_le(block);
        let p0 = s[0] ^ c0;

        let p0_bytes = p0.to_le_bytes();
        out.copy_from_slice(&p0_bytes[..block.len()]);

        // Update state as if encryption had absorbed plaintext.
        s[0] ^= load_u64_le(out);
        s[0] ^= pad(block.len());
    } else {
        let c0 = u64::from_le_bytes(block[0..8].try_into().unwrap());
        let c1 = load_u64_le(&block[8..]);

        let p0 = s[0] ^ c0;
        let p1 = s[1] ^ c1;

        out[0..8].copy_from_slice(&p0.to_le_bytes());

        let p1_bytes = p1.to_le_bytes();
        out[8..].copy_from_slice(&p1_bytes[..block.len() - 8]);

        // Update state as if encryption had absorbed plaintext.
        s[0] = c0;
        s[1] ^= load_u64_le(&out[8..]);
        s[1] ^= pad(block.len() - 8);
    }
}

fn constant_time_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut result = 0u8;

    for i in 0..16 {
        result |= a[i] ^ b[i];
    }

    result == 0
}
