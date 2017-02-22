use std::u64;
use rust_sodium::randombytes::randombytes;
//use rustc_serialize::hex::{ToHex};

pub fn randommod(n: u64) -> u64 {
    let mut result:u64 = 0;
    if n > 1 {
        let r = randombytes(32);
        for j in 0..32 {
            result = (result * 256 + (r[j] as u64)) % n;
        }
    }
    result
}

pub fn nameparse(source: &str) -> Vec<u8> {
    let src = String::from(source).into_bytes();
    let mut dst: Vec<u8> = vec![];
    let mut s = 0;
    while s < src.len() {
        let mut j = s;
        while j < src.len() && src[j] != '.' as u8 {
            j += 1;
        }
        dst.push((j - s) as u8);
        // println!("nameparse: count {}", j - s);
        while s < src.len() && src[s] != '.' as u8 {
            dst.push(src[s]);
            s += 1;
        }
        if s < src.len() && src[s] == '.' as u8 {
            s += 1;
        }
    }
    // println!("nameparse: str {}", String::from_utf8(dst.clone()).unwrap());
    // println!("nameparse: hex {}", dst.to_hex());
    return dst;
}
