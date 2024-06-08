use core::cmp;

/// An ASCON-based seekable stream cipher.
#[derive(Clone, Copy)]
pub struct StreamCipher {
    /// The ASCON state
    st: [u64; 5],
}

impl StreamCipher {
    /// The key length in bytes
    pub const KEY_LENGTH: usize = 32;

    /// The ASCON constants
    const RKS: [u64; 12] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
    ];

    /// Create a new state with the given key and context.
    ///
    /// The key must be 32 bytes long, and must be randomly generated, for example using
    /// `rand::thread_rng().gen::<[u8; 32]>()` or `getrandom::getrandom()`.
    ///
    /// The context is optional can be of any length. It is used to improve multi-user security.
    pub fn new(key: &[u8; Self::KEY_LENGTH], context: impl AsRef<[u8]>) -> Self {
        let context = context.as_ref();
        let st = [0x010080cc00000000, 0, 0, 0, 0];

        let mut state = StreamCipher { st };
        state.st[1] ^= u64::from_le_bytes(key[0..8].try_into().unwrap());
        state.st[2] ^= u64::from_le_bytes(key[8..16].try_into().unwrap());
        state.st[3] ^= u64::from_le_bytes(key[16..24].try_into().unwrap());
        state.st[4] ^= u64::from_le_bytes(key[24..32].try_into().unwrap());
        state.permute();

        let mut context = context;

        while context.len() > 32 {
            let context_part_len = 32;
            state.st[0] ^= u64::from_le_bytes(context[0..8].try_into().unwrap());
            state.st[1] ^= u64::from_le_bytes(context[8..16].try_into().unwrap());
            state.st[2] ^= u64::from_le_bytes(context[16..24].try_into().unwrap());
            state.st[3] ^= u64::from_le_bytes(context[24..32].try_into().unwrap());
            context = &context[context_part_len..];
            state.permute();
        }

        let context_len = context.len();
        let mut buf = [0u8; 32];
        buf[..context_len].copy_from_slice(context);
        state.st[0] ^= u64::from_le_bytes(buf[0..8].try_into().unwrap());
        state.st[1] ^= u64::from_le_bytes(buf[8..16].try_into().unwrap());
        state.st[2] ^= u64::from_le_bytes(buf[16..24].try_into().unwrap());
        state.st[3] ^= u64::from_le_bytes(buf[24..32].try_into().unwrap());
        state.st[4] ^= 0x01;
        state.permute();

        state.st[0] ^= u64::from_le_bytes(key[0..8].try_into().unwrap());
        state.st[1] ^= u64::from_le_bytes(key[8..16].try_into().unwrap());
        state.st[2] ^= u64::from_le_bytes(key[16..24].try_into().unwrap());
        state.st[3] ^= u64::from_le_bytes(key[24..32].try_into().unwrap());

        state
    }

    /// Squeeze a 40-byte block, and store it in the given buffer.
    #[inline(always)]
    fn store_rate(mut self, out: &mut [u8], block_offset: u64) {
        self.st[4] ^= block_offset;
        let mask = self.st;
        self.permute();
        for (x, mask) in self.st.iter_mut().zip(mask) {
            *x ^= mask;
        }
        for i in 0..5 {
            out[i * 8..][..8].copy_from_slice(&self.st[i].to_le_bytes());
        }
    }

    /// Squeeze a 40-byte block, and add it to the given buffer.
    #[inline(always)]
    fn apply_rate(mut self, out: &mut [u8], block_offset: u64) {
        self.st[4] ^= block_offset;
        let mask = self.st;
        self.permute();
        for (x, mask) in self.st.iter_mut().zip(mask) {
            *x ^= mask;
        }
        for i in 0..5 {
            let x = u64::from_le_bytes(out[i * 8..][..8].try_into().unwrap());
            out[i * 8..][..8].copy_from_slice(&(self.st[i] ^ x).to_le_bytes());
        }
    }

    /// Squeeze and return a 40-byte block.
    #[inline(always)]
    fn squeeze_rate(self, block_offset: u64) -> [u8; 40] {
        let mut out = [0u8; 40];
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
        let mut block_offset = start_offset / 40;
        let offset_in_first_block = (start_offset % 40) as usize;
        let bytes_to_copy = cmp::min(40 - offset_in_first_block, out.len());
        if bytes_to_copy > 0 {
            let rate = self.squeeze_rate(block_offset);
            out[..bytes_to_copy].copy_from_slice(&rate[offset_in_first_block..][..bytes_to_copy]);
            out = &mut out[bytes_to_copy..];
        }
        while out.len() >= 40 {
            block_offset += 1;
            self.store_rate(&mut out[..40], block_offset);
            out = &mut out[40..];
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
        let mut block_offset = start_offset / 40;
        let offset_in_first_block = (start_offset % 40) as usize;
        let bytes_to_copy = cmp::min(40 - offset_in_first_block, out.len());
        if bytes_to_copy > 0 {
            let rate = self.squeeze_rate(block_offset);
            for i in 0..bytes_to_copy {
                out[i] ^= rate[offset_in_first_block + i];
            }
            out = &mut out[bytes_to_copy..];
        }
        while out.len() >= 40 {
            block_offset += 1;
            self.apply_rate(&mut out[..40], block_offset);
            out = &mut out[40..];
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

    #[inline(always)]
    fn round(&mut self, rk: u64) {
        let x = &mut self.st;
        x[2] ^= rk;

        x[0] ^= x[4];
        x[4] ^= x[3];
        x[2] ^= x[1];
        let mut t = [
            x[0] ^ (!x[1] & x[2]),
            x[1] ^ (!x[2] & x[3]),
            x[2] ^ (!x[3] & x[4]),
            x[3] ^ (!x[4] & x[0]),
            x[4] ^ (!x[0] & x[1]),
        ];
        t[1] ^= t[0];
        t[3] ^= t[2];
        t[0] ^= t[4];

        x[2] = t[2] ^ t[2].rotate_right(6 - 1);
        x[3] = t[3] ^ t[3].rotate_right(17 - 10);
        x[4] = t[4] ^ t[4].rotate_right(41 - 7);
        x[0] = t[0] ^ t[0].rotate_right(28 - 19);
        x[1] = t[1] ^ t[1].rotate_right(61 - 39);
        x[2] = t[2] ^ x[2].rotate_right(1);
        x[3] = t[3] ^ x[3].rotate_right(10);
        x[4] = t[4] ^ x[4].rotate_right(7);
        x[0] = t[0] ^ x[0].rotate_right(19);
        x[1] = t[1] ^ x[1].rotate_right(39);
        x[2] = !x[2];
    }

    fn permute(&mut self) {
        for &rk in &Self::RKS {
            self.round(rk);
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
