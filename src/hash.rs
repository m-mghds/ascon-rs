use crate::permutation::p12;
use crate::state::State;

const HASH_RATE: usize = 8;
const ASCON_HASH256_IV: u64 = 0x0000_0801_00cc_0002;
const ASCON_XOF128_IV: u64 = 0x0000_0800_00cc_0003;
const ASCON_CXOF128_IV: u64 = 0x0000_0800_00cc_0004;
const MAX_CUSTOMIZATION_LEN: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    CustomizationTooLong,
}

//Ascon-hash256
pub fn hash256(message: &[u8]) -> [u8; 32] {
    let mut state = init_hash256_state();

    absorb_message(&mut state, message);

    let mut digest = [0u8; 32];
    squeeze(&mut state, &mut digest);

    digest
}

//Ascon-XOF128
pub fn xof128(message: &[u8], output: &mut [u8]) {
    let mut state = init_state(ASCON_XOF128_IV);

    absorb_message(&mut state, message);

    squeeze(&mut state, output);
}

//Ascon-cxof128
pub fn cxof128(customization: &[u8], message: &[u8], output: &mut [u8]) -> Result<(), Error> {
    if customization.len() > MAX_CUSTOMIZATION_LEN {
        return Err(Error::CustomizationTooLong);
    }

    let mut state = init_state(ASCON_CXOF128_IV);

    absorb_customization(&mut state, customization);
    absorb_message(&mut state, message);

    squeeze(&mut state, output);
    Ok(())
}

fn init_state(iv: u64) -> State {
    let mut state = State::from_words(iv, 0, 0, 0, 0);
    p12(&mut state);
    state
}

fn init_hash256_state() -> State {
    init_state(ASCON_HASH256_IV)
}

fn absorb_message(state: &mut State, message: &[u8]) {
    let mut chunks = message.chunks_exact(HASH_RATE);

    for block in &mut chunks {
        state.word_mut()[0] ^= u64::from_le_bytes(block.try_into().unwrap());
        p12(state);
    }

    let remaining = chunks.remainder();

    state.word_mut()[0] ^= load_u64_le(remaining);
    state.word_mut()[0] ^= pad(remaining.len());

    p12(state);
}

fn absorb_customization(state: &mut State, customization: &[u8]) {
    let customization_len_bits = (customization.len() as u64) * 8;

    state.word_mut()[0] ^= customization_len_bits;
    p12(state);

    absorb_message(state, customization);
}

fn squeeze(state: &mut State, output: &mut [u8]) {
    let mut offset = 0;

    while offset < output.len() {
        let block = state.word()[0].to_le_bytes();

        let remaining = output.len() - offset;
        let take = remaining.min(HASH_RATE);

        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;

        if offset < output.len() {
            p12(state);
        }
    }
}

fn load_u64_le(bytes: &[u8]) -> u64 {
    assert!(
        bytes.len() <= 8,
        "Cannot load more than 8 bytes into a u64!"
    );

    let mut value = 0u64;

    for (i, &byte) in bytes.iter().enumerate() {
        value |= (byte as u64) << (8 * i);
    }

    value
}

fn pad(byte_position: usize) -> u64 {
    assert!(byte_position < HASH_RATE);
    0x01u64 << (8 * byte_position)
}
