use crate::state::State;

const ROUND_CONSTANTS: [u8; 16] = [
    0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

pub fn p12(state: &mut State) {
    permute(state, 12);
}

pub fn p8(state: &mut State) {
    permute(state, 8);
}

fn permute(state: &mut State, rounds: usize) {
    assert!(rounds <= 16, "Number of rounds must be between 0 and 16");

    let start = 16 - rounds;

    for &rc in ROUND_CONSTANTS[start..].iter() {
        constant_addition_layer(state, rc);
        substitution_layer(state);
        linear_diffusion_layer(state);
    }
}

// Constant addition layer of the Ascon permutation.
// The round constant is XORed into the third 64-bit word of the state,
// which corresponds to x2 in the Ascon state representation.
// The round constant is originally 8 bits, so it is cast to u64 before
// being XORed with the 64-bit state word.
fn constant_addition_layer(state: &mut State, round_constant: u8) {
    state.word_mut()[2] ^= round_constant as u64;
}

fn substitution_layer(state: &mut State) {
    let x = state.word_mut();

    // Ascon's S-box is applied to the 5 words of the state.
    // The S-box is a 5-bit to 5-bit mapping, so we need to apply it to each bit position across the 5 words.
    // The S-box transformation is defined as follows:
    let x0 = x[0];
    let x1 = x[1];
    let x2 = x[2];
    let x3 = x[3];
    let x4 = x[4];

    let y0 = (x4 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ (x1 & x0) ^ x1 ^ x0;
    let y1 = (x4) ^ (x3 & x2) ^ (x3 & x1) ^ x3 ^ (x2 & x1) ^ x2 ^ x1 ^ x0;
    let y2 = (x4 & x3) ^ x4 ^ x2 ^ x1 ^ !0u64;
    let y3 = (x4 & x0) ^ x4 ^ (x3 & x0) ^ x3 ^ x2 ^ x1 ^ x0;
    let y4 = (x4 & x1) ^ x4 ^ x3 ^ (x1 & x0) ^ x1;

    x[0] = y0;
    x[1] = y1;
    x[2] = y2;
    x[3] = y3;
    x[4] = y4;
}

fn linear_diffusion_layer(state: &mut State) {
    let x = state.word_mut();

    x[0] ^= x[0].rotate_right(19) ^ x[0].rotate_right(28);
    x[1] ^= x[1].rotate_right(61) ^ x[1].rotate_right(39);
    x[2] ^= x[2].rotate_right(1) ^ x[2].rotate_right(6);
    x[3] ^= x[3].rotate_right(10) ^ x[3].rotate_right(17);
    x[4] ^= x[4].rotate_right(7) ^ x[4].rotate_right(41);
}
