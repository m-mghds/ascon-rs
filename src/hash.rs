use crate::permutation::p12;
use crate::state::State;

const HASH_RATE: usize = 8;
const IV: u64 = 0x0000_0801_00cc_0002;

pub fn hash256(message: &[u8]) -> [u8; 32] {
    let mut state = init_hash256_state();

    absorb_message(&mut state, message);

    squeeze_hash256(&mut state)
}

fn init_hash256_state() -> State {
    let mut state = State::from_words(IV, 0, 0, 0, 0);
    p12(&mut state);
    state
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

fn squeeze_hash256(state: &mut State) -> [u8; 32] {
    let mut digest = [0u8; 32];

    for i in 0..4 {
        let block = state.word()[0].to_le_bytes();
        digest[i * 8..(i + 1) * 8].copy_from_slice(&block);

        if i != 3 {
            p12(state);
        }
    }

    digest
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
