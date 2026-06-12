#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    words: [u64; 5],
}

impl State {
    pub const fn from_words(s0: u64, s1: u64, s2: u64, s3: u64, s4: u64) -> Self {
        Self {
            words: [s0, s1, s2, s3, s4],
        }
    }

    pub fn word(&self) -> &[u64; 5] {
        &self.words
    }

    pub fn word_mut(&mut self) -> &mut [u64; 5] {
        &mut self.words
    }
}
