use core::cmp;

/// An Keccak-based seekable stream cipher.
#[derive(Clone, Copy)]
pub struct StreamCipher {
    /// The Keccak state
    st: [u64; 25],
}

impl StreamCipher {
    /// The key length in bytes
    pub const KEY_LENGTH: usize = 32;

    /// Create a new state with the given key and context.
    ///
    /// The key must be 32 bytes long, and must be randomly generated, for example using
    /// `rand::thread_rng().gen::<[u8; 32]>()` or `getrandom::getrandom()`.
    ///
    /// The context is optional can be of any length. It is used to improve multi-user security.
    pub fn new(key: &[u8; Self::KEY_LENGTH], context: impl AsRef<[u8]>) -> Self {
        let context = context.as_ref();
        // PI decimals
        let mut st = [0u64; 25];
        st[0] = 0x20a08c0000000000;
        let mut state = StreamCipher { st };
        state.st[1] ^= u64::from_le_bytes(key[0..8].try_into().unwrap());
        state.st[2] ^= u64::from_le_bytes(key[8..16].try_into().unwrap());
        state.st[3] ^= u64::from_le_bytes(key[16..24].try_into().unwrap());
        state.st[4] ^= u64::from_le_bytes(key[24..32].try_into().unwrap());

        let mut context = context;
        if context.len() > 160 {
            let context_part_len = 160;
            for i in 0..25 - 5 {
                state.st[5 + i] ^= u64::from_le_bytes(context[i * 8..][0..8].try_into().unwrap());
            }
            context = &context[context_part_len..];
            state.permute();

            while context.len() > 160 {
                let context_part_len = 160;
                for i in 0..25 - 5 {
                    state.st[5 + i] ^=
                        u64::from_le_bytes(context[i * 8..][0..8].try_into().unwrap());
                }
                context = &context[context_part_len..];
                state.permute();
            }
        }
        let context_len = context.len();
        let mut buf = [0u8; 160];
        buf[..context_len].copy_from_slice(context);
        for i in 0..25 - 5 {
            state.st[5 + i] ^= u64::from_le_bytes(buf[i * 8..][0..8].try_into().unwrap());
        }
        state.st[0] ^= 0x01;
        state.permute();

        state.st[0] ^= u64::from_le_bytes(key[0..8].try_into().unwrap());
        state.st[1] ^= u64::from_le_bytes(key[8..16].try_into().unwrap());
        state.st[2] ^= u64::from_le_bytes(key[16..24].try_into().unwrap());
        state.st[3] ^= u64::from_le_bytes(key[24..32].try_into().unwrap());

        state
    }

    /// Squeeze a 160-byte block, and store it in the given buffer.
    #[inline(always)]
    fn store_rate(mut self, out: &mut [u8], block_offset: u64) {
        self.st[4] ^= block_offset;
        self.permute();
        for i in 0..25 - 5 {
            out[i * 8..][..8].copy_from_slice(&self.st[5 + i].to_le_bytes());
        }
    }

    /// Squeeze a 160-byte block, and add it to the given buffer.
    #[inline(always)]
    fn apply_rate(mut self, out: &mut [u8], block_offset: u64) {
        self.st[4] ^= block_offset;
        self.permute();
        for i in 0..25 - 5 {
            let x = u64::from_le_bytes(out[i * 8..][..8].try_into().unwrap());
            out[i * 8..][..8].copy_from_slice(&(self.st[5 + i] ^ x).to_le_bytes());
        }
    }

    /// Squeeze and return a 160-byte block.
    #[inline(always)]
    fn squeeze_rate(self, block_offset: u64) -> [u8; 160] {
        let mut out = [0u8; 160];
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
        let mut block_offset = start_offset / 160;
        let offset_in_first_block = (start_offset % 160) as usize;
        let bytes_to_copy = cmp::min(160 - offset_in_first_block, out.len());
        if bytes_to_copy > 0 {
            let rate = self.squeeze_rate(block_offset);
            out[..bytes_to_copy].copy_from_slice(&rate[offset_in_first_block..][..bytes_to_copy]);
            out = &mut out[bytes_to_copy..];
        }
        while out.len() >= 160 {
            block_offset += 1;
            self.store_rate(&mut out[..160], block_offset);
            out = &mut out[160..];
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
        let mut block_offset = start_offset / 160;
        let offset_in_first_block = (start_offset % 160) as usize;
        let bytes_to_copy = cmp::min(160 - offset_in_first_block, out.len());
        if bytes_to_copy > 0 {
            let rate = self.squeeze_rate(block_offset);
            for i in 0..bytes_to_copy {
                out[i] ^= rate[offset_in_first_block + i];
            }
            out = &mut out[bytes_to_copy..];
        }
        while out.len() >= 160 {
            block_offset += 1;
            self.apply_rate(&mut out[..160], block_offset);
            out = &mut out[160..];
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
        keccak::p1600(&mut self.st, 12);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak() {
        let mut key = [0u8; StreamCipher::KEY_LENGTH];
        getrandom::getrandom(&mut key).unwrap();

        let st = StreamCipher::new(&key, b"test");

        let mut out = [0u8; 10000];
        st.apply_keystream(&mut out, 10).unwrap();

        let mut out2 = [0u8; 10000];
        st.fill(&mut out2, 10).unwrap();

        assert_eq!(out, out2);

        st.fill(&mut out2, 11).unwrap();
        assert_eq!(out[1..], out2[0..out2.len() - 1]);
    }

    #[test]
    fn test_large_context() {
        let mut key = [0u8; StreamCipher::KEY_LENGTH];
        getrandom::getrandom(&mut key).unwrap();
        let context = [0u8; 10000];
        let _ = StreamCipher::new(&key, context);
    }
}
