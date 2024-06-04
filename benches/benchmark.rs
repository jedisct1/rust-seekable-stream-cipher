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
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::ChaCha20 as ChaCha;

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut st = ChaCha::new(&key.into(), &nonce.into());
        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.seek(0);
            st.apply_keystream(&mut out);
            out
        });
        println!("ChaCha20/20: {}", res.throughput(out.len() as _));
    }

    {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::ChaCha12 as ChaCha;

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut st = ChaCha::new(&key.into(), &nonce.into());
        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.seek(0);
            st.apply_keystream(&mut out);
            out
        });
        println!("ChaCha20/12: {}", res.throughput(out.len() as _));
    }

    {
        use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
        use chacha20::ChaCha8 as ChaCha;

        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut st = ChaCha::new(&key.into(), &nonce.into());
        let mut out = [0u8; 10000];
        let res = bench.run(options, || {
            st.seek(0);
            st.apply_keystream(&mut out);
            out
        });
        println!("ChaCha20/8 : {}", res.throughput(out.len() as _));
    }
}
