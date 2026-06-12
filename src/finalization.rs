use crate::key::Key;
use crate::permutation;
use crate::state::State;

pub fn finalize(state: &mut State, key: &Key) -> [u8; 16] {
    let k = key.words();

    // First key injection before final permutation:
    // S2 ^= K0
    // S3 ^= K1
    {
        let s = state.word_mut();
        s[2] ^= k[0];
        s[3] ^= k[1];
    }

    permutation::p12(state);

    // Second key injection after final permutation:
    // S3 ^= K0
    // S4 ^= K1
    {
        let s = state.word_mut();
        s[3] ^= k[0];
        s[4] ^= k[1];

        let mut tag = [0u8; 16];

        tag[0..8].copy_from_slice(&s[3].to_le_bytes());
        tag[8..16].copy_from_slice(&s[4].to_le_bytes());

        tag
    }
}
