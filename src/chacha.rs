use core::cmp;

/// An ChaCha-based seekable stream cipher.
#[derive(Clone, Copy)]
pub struct StreamCipher {
    /// The ChaCha state
    st: [u32; 16],
}

impl StreamCipher {
    /// The key length in bytes
    pub const KEY_LENGTH: usize = 32;

    /// The ChaCha constants
    const CONSTANTS: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

    /// Create a new state with the given key and context.
    ///
    /// The key must be 32 bytes long, and must be randomly generated, for example using
    /// `rand::thread_rng().gen::<[u8; 32]>()` or `getrandom::getrandom()`.
    ///
    /// The context identifier is used to improve multi-user security.
    pub fn new(key: &[u8; Self::KEY_LENGTH], id: &[u8; 8]) -> Self {
        let st = [
            Self::CONSTANTS[0],
            Self::CONSTANTS[1],
            Self::CONSTANTS[2],
            Self::CONSTANTS[3],
            u32::from_le_bytes(key[0..4].try_into().unwrap()),
            u32::from_le_bytes(key[4..8].try_into().unwrap()),
            u32::from_le_bytes(key[8..12].try_into().unwrap()),
            u32::from_le_bytes(key[12..16].try_into().unwrap()),
            u32::from_le_bytes(key[16..20].try_into().unwrap()),
            u32::from_le_bytes(key[20..24].try_into().unwrap()),
            u32::from_le_bytes(key[24..28].try_into().unwrap()),
            u32::from_le_bytes(key[28..32].try_into().unwrap()),
            0,
            0,
            u32::from_le_bytes(id[0..4].try_into().unwrap()),
            u32::from_le_bytes(id[4..8].try_into().unwrap()),
        ];
        StreamCipher { st }
    }

    /// Squeeze a 32-byte block, and store it in the given buffer.
    #[inline(always)]
    fn store_rate(mut self, out: &mut [u8], block_offset: u64) {
        self.st[12] = block_offset as _;
        self.st[13] = (block_offset >> 32) as _;
        self.permute();
        for i in 0..16 {
            out[i * 4..][0..4].copy_from_slice(&(self.st[i]).to_le_bytes());
        }
    }

    /// Squeeze a 32-byte block, and add it to the given buffer.
    #[inline(always)]
    fn apply_rate(mut self, out: &mut [u8], block_offset: u64) {
        self.st[12] = block_offset as _;
        self.st[13] = (block_offset >> 32) as _;
        self.permute();

        let out0 = u32::from_le_bytes(out[0 * 4..][0..4].try_into().unwrap());
        let out1 = u32::from_le_bytes(out[1 * 4..][0..4].try_into().unwrap());
        let out2 = u32::from_le_bytes(out[2 * 4..][0..4].try_into().unwrap());
        let out3 = u32::from_le_bytes(out[3 * 4..][0..4].try_into().unwrap());
        let out4 = u32::from_le_bytes(out[4 * 4..][0..4].try_into().unwrap());
        let out5 = u32::from_le_bytes(out[5 * 4..][0..4].try_into().unwrap());
        let out6 = u32::from_le_bytes(out[6 * 4..][0..4].try_into().unwrap());
        let out7 = u32::from_le_bytes(out[7 * 4..][0..4].try_into().unwrap());
        let out8 = u32::from_le_bytes(out[8 * 4..][0..4].try_into().unwrap());
        let out9 = u32::from_le_bytes(out[9 * 4..][0..4].try_into().unwrap());
        let out10 = u32::from_le_bytes(out[10 * 4..][0..4].try_into().unwrap());
        let out11 = u32::from_le_bytes(out[11 * 4..][0..4].try_into().unwrap());
        let out12 = u32::from_le_bytes(out[12 * 4..][0..4].try_into().unwrap());
        let out13 = u32::from_le_bytes(out[13 * 4..][0..4].try_into().unwrap());
        let out14 = u32::from_le_bytes(out[14 * 4..][0..4].try_into().unwrap());
        let out15 = u32::from_le_bytes(out[15 * 4..][0..4].try_into().unwrap());
        out[0 * 4..][0..4].copy_from_slice(&(out0 ^ self.st[0]).to_le_bytes());
        out[1 * 4..][0..4].copy_from_slice(&(out1 ^ self.st[1]).to_le_bytes());
        out[2 * 4..][0..4].copy_from_slice(&(out2 ^ self.st[2]).to_le_bytes());
        out[3 * 4..][0..4].copy_from_slice(&(out3 ^ self.st[3]).to_le_bytes());
        out[4 * 4..][0..4].copy_from_slice(&(out4 ^ self.st[4]).to_le_bytes());
        out[5 * 4..][0..4].copy_from_slice(&(out5 ^ self.st[5]).to_le_bytes());
        out[6 * 4..][0..4].copy_from_slice(&(out6 ^ self.st[6]).to_le_bytes());
        out[7 * 4..][0..4].copy_from_slice(&(out7 ^ self.st[7]).to_le_bytes());
        out[8 * 4..][0..4].copy_from_slice(&(out8 ^ self.st[8]).to_le_bytes());
        out[9 * 4..][0..4].copy_from_slice(&(out9 ^ self.st[9]).to_le_bytes());
        out[10 * 4..][0..4].copy_from_slice(&(out10 ^ self.st[10]).to_le_bytes());
        out[11 * 4..][0..4].copy_from_slice(&(out11 ^ self.st[11]).to_le_bytes());
        out[12 * 4..][0..4].copy_from_slice(&(out12 ^ self.st[12]).to_le_bytes());
        out[13 * 4..][0..4].copy_from_slice(&(out13 ^ self.st[13]).to_le_bytes());
        out[14 * 4..][0..4].copy_from_slice(&(out14 ^ self.st[14]).to_le_bytes());
        out[15 * 4..][0..4].copy_from_slice(&(out15 ^ self.st[15]).to_le_bytes());
    }

    /// Squeeze and return a 64-byte block.
    #[inline(always)]
    fn squeeze_rate(self, block_offset: u64) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.store_rate(&mut out, block_offset);
        out
    }

    /// Fill the given buffer with the keystream starting at the given offset.
    ///
    /// The offset is in bytes.
    ///
    /// The key stream is deterministic: the same key, context and offset will always produce the same output.
    pub fn fill(&self, mut out: &mut [u8], start_offset: u64) -> Result<(), &'static str> {
        if start_offset.checked_add(out.len() as u64).is_none() {
            return Err("offset would overflow");
        }
        let mut block_offset = start_offset / 64;
        let offset_in_first_block = (start_offset % 64) as usize;
        let bytes_to_copy = cmp::min(64 - offset_in_first_block, out.len());
        if bytes_to_copy > 0 {
            let rate = self.squeeze_rate(block_offset);
            out[..bytes_to_copy].copy_from_slice(&rate[offset_in_first_block..][..bytes_to_copy]);
            out = &mut out[bytes_to_copy..];
        }
        while out.len() >= 64 {
            block_offset += 1;
            self.store_rate(&mut out[..64], block_offset);
            out = &mut out[64..];
        }
        if !out.is_empty() {
            block_offset += 1;
            let rate = self.squeeze_rate(block_offset);
            out.copy_from_slice(&rate[..out.len()]);
        }
        Ok(())
    }

    /// Encrypt or decrypt the given buffer in place, given the offset.
    ///
    /// The buffer is modified in place.
    /// The offset is in bytes.
    ///
    /// The key stream is deterministic: the same key, context and offset will always produce the same output.
    /// This function is equivalent to calling `fill` and then XORing the output with the input.
    ///
    /// # Caveats
    ///
    /// * There is no integrity.
    /// * An adversary can flip arbitrary bits in the ciphertext and the corresponding bits in the plaintext will be flipped when decrypted.
    pub fn apply_keystream(
        &self,
        mut out: &mut [u8],
        start_offset: u64,
    ) -> Result<(), &'static str> {
        if start_offset.checked_add(out.len() as u64).is_none() {
            return Err("offset would overflow");
        }
        let mut block_offset = start_offset / 64;
        let offset_in_first_block = (start_offset % 64) as usize;
        let bytes_to_copy = cmp::min(64 - offset_in_first_block, out.len());
        if bytes_to_copy > 0 {
            let rate = self.squeeze_rate(block_offset);
            for i in 0..bytes_to_copy {
                out[i] ^= rate[offset_in_first_block + i];
            }
            out = &mut out[bytes_to_copy..];
        }
        while out.len() >= 64 {
            block_offset += 1;
            self.apply_rate(&mut out[..64], block_offset);
            out = &mut out[64..];
        }
        if !out.is_empty() {
            block_offset += 1;
            let rate = self.squeeze_rate(block_offset);
            for i in 0..out.len() {
                out[i] ^= rate[i];
            }
        }
        Ok(())
    }

    fn permute(&mut self) {
        let mask = self.st;
        let x = &mut self.st;
        for _ in 0..12 / 2 {
            {
                const R: [usize; 4] = [0, 4, 8, 12];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [1, 5, 9, 13];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [2, 6, 10, 14];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [3, 7, 11, 15];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [0, 5, 10, 15];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [1, 6, 11, 12];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [2, 7, 8, 13];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
            {
                const R: [usize; 4] = [3, 4, 9, 14];
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(16);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(12);
                x[R[0]] = x[R[0]].wrapping_add(x[R[1]]);
                x[R[3]] = (x[R[3]] ^ x[R[0]]).rotate_left(8);
                x[R[2]] = x[R[2]].wrapping_add(x[R[3]]);
                x[R[1]] = (x[R[1]] ^ x[R[2]]).rotate_left(7);
            }
        }
        for i in 0..16 {
            x[i] = x[i].wrapping_add(mask[i]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascon() {
        let mut key = [0u8; StreamCipher::KEY_LENGTH];
        getrandom::getrandom(&mut key).unwrap();

        let st = StreamCipher::new(&key, b"testtest");

        let mut out = [0u8; 10000];
        st.apply_keystream(&mut out, 10).unwrap();

        let mut out2 = [0u8; 10000];
        st.fill(&mut out2, 10).unwrap();

        assert_eq!(out, out2);

        st.fill(&mut out2, 11).unwrap();
        assert_eq!(out[1..], out2[0..out2.len() - 1]);
    }
}
