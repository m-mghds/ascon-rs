use core::convert::TryInto;
use core::fmt;

#[derive(Clone, PartialEq, Eq)]
pub struct Key {
    bytes: [u8; 16],
}

impl Key {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    pub fn words(&self) -> [u64; 2] {
        [
            u64::from_le_bytes(self.bytes[0..8].try_into().unwrap()),
            u64::from_le_bytes(self.bytes[8..16].try_into().unwrap()),
        ]
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.bytes
    }
}

// real key should not be printed, this is just for testing purposes
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}
