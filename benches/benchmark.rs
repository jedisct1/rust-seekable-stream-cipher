use benchmark_simple::*;

fn main() {
    let bench = Bench::new();
    let options = &Options {
        iterations: 250_000,
        warmup_iterations: 25_000,
        min_samples: 5,
        max_samples: 10,
        max_rsd: 1.0,
        ..Default::default()
    };

    {
        use seekable_stream_cipher::chacha::StreamCipher;

        let key = [0u8; StreamCipher::KEY_LENGTH];
        let st = StreamCipher::new(&key, b"testtest");
        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.apply_keystream(&mut out, 0).ok();
            out
        });
        println!("ChaCha     : {}", res.throughput(out.len() as _));
    }

    {
        use seekable_stream_cipher::keccak::StreamCipher;

        let key = [0u8; StreamCipher::KEY_LENGTH];
        let st = StreamCipher::new(&key, b"test");
        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.apply_keystream(&mut out, 0).ok();
            out
        });
        println!("Keccak     : {}", res.throughput(out.len() as _));
    }

    {
        use seekable_stream_cipher::ascon::StreamCipher;

        let key = [0u8; StreamCipher::KEY_LENGTH];
        let st = StreamCipher::new(&key, b"test");
        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.apply_keystream(&mut out, 0).ok();
            out
        });
        println!("Ascon      : {}", res.throughput(out.len() as _));
    }

    {
        use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        type Aes128Ctr64LE = ctr::Ctr64LE<aes::Aes128>;

        let key = [0x42; 16];
        let iv = [0x24; 16];
        let mut st = Aes128Ctr64LE::new(&key.into(), &iv.into());

        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.seek(0);
            st.apply_keystream(&mut out);
            out
        });
        println!("AES-128    : {}", res.throughput(out.len() as _));
    }
}
