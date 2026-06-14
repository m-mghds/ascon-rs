use core::convert::TryInto;

use crate::key::Key;
use crate::permutation;
use crate::state::State;

use zeroize::Zeroize;

const IV: u64 = 0x0000_1000_808c_0001;

pub fn initialize(key: &Key, nonce: &[u8; 16]) -> State {
    let mut k = key.words();
    let n = [
        u64::from_le_bytes(nonce[0..8].try_into().unwrap()),
        u64::from_le_bytes(nonce[8..16].try_into().unwrap()),
    ];

    // S = IV || K0 || K1 || N0 || N1
    let mut state = State::from_words(IV, k[0], k[1], n[0], n[1]);
    permutation::p12(&mut state);

    // Final key injection
    // S3 = S3 XOR K0
    // S4 = S4 XOR K1
    let s = state.word_mut();
    s[3] ^= k[0];
    s[4] ^= k[1];

    k.zeroize();

    state
}
