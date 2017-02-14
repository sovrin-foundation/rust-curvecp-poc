#[macro_use]
extern crate arrayref;
extern crate rustc_serialize;
extern crate rust_sodium_sys;
extern crate rust_sodium;

use std::mem;
use std::u64;
use std::slice;
use std::str;
use std::net::UdpSocket;
use rust_sodium_sys::*;
use rust_sodium::randombytes::randombytes;
use rustc_serialize::hex::{ToHex};

const SECRETKEY:[u8; 32] = [
    0x70, 0x2d, 0x76, 0x4d, 0xe0, 0x54, 0x7c, 0x94,
    0x86, 0x4c, 0x28, 0x97, 0x39, 0xc8, 0xaa, 0xd4,
    0x80, 0x08, 0x08, 0xd9, 0x1f, 0xdf, 0x70, 0xf6,
    0xe4, 0x37, 0x7b, 0x13, 0x7d, 0x0c, 0x13, 0x8d
];
const PUBLICKEY:[u8; 32] = [
    0x0a, 0x02, 0x94, 0xb7, 0x69, 0x86, 0x30, 0x42,
    0x28, 0xa3, 0x34, 0x11, 0x23, 0x92, 0x70, 0x95,
    0x88, 0xf2, 0xe0, 0x04, 0xf3, 0xd8, 0xe0, 0xdd,
    0x13, 0x9b, 0x90, 0x95, 0x96, 0xe4, 0xf9, 0x48
];
const SERVER_EXT:[u8; 16] = [
    0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93,
    0x23, 0x84, 0x62, 0x64, 0x33, 0x83, 0x27, 0x95
];

#[repr(packed)]
struct ClientHello {
    signature: [u8; 8],
    server_ext: [u8; 16],
    client_ext: [u8; 16],
    client_sterm_pk: [u8; 32],
    pad: [u8; 64],
    nonce: [u8; 8],
    cbox: [u8; 80]
}

#[repr(packed)]
struct ServerCookie {
    signature: [u8; 8],
    client_ext: [u8; 16],
    server_ext: [u8; 16],
    nonce: [u8; 16],
    cbox: [u8; 144]
}

fn randommod(n: u64) -> u64 {
    let mut result:u64 = 0;
    if n > 1
    {
        let r = randombytes(32);
        for j in 0..32
        {
            result = (result * 256 + (r[j] as u64)) % n;
        }
    }
    result
}


fn main() {
    let mut clientlongtermpk: [u8; 32] = PUBLICKEY;
    let mut serverlongtermpk: [u8; 32] = PUBLICKEY;
    let mut clientlongtermsk: [u8; 32] = SECRETKEY;
    let mut clientshorttermpk: [u8; 32] = [0; 32];
    let mut clientshorttermsk: [u8; 32] = [0; 32];
    let mut clientshorttermnonce: u64 = randommod(281474976710656);
    let mut clientshortserverlong: [u8; 32] = [0; 32];
    let mut clientlongserverlong: [u8; 32] = [0; 32];
    let socket = UdpSocket::bind("0.0.0.0:0").expect("err");

    /*
     * Send Client Hello
     */

    clientshorttermnonce += 1;

    // keys
    unsafe {
        crypto_box_keypair(&mut clientshorttermpk[0], &mut clientshorttermsk[0]);
        crypto_box_beforenm(&mut clientshortserverlong[0],
                            &mut serverlongtermpk[0],
                            &mut clientshorttermsk[0]);
        crypto_box_beforenm(&mut clientlongserverlong[0],
                            &mut serverlongtermpk[0],
                            &mut clientlongtermsk[0]);
    }

    // signature
    let signature = String::from("QvnQ5XlH").into_bytes();

    // nonce
    let x = String::from("CurveCP-client-H________").into_bytes();
    let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
    for i in 0..8 {
        nonce[16+i] = ((clientshorttermnonce >> i*8) & 0xFF) as u8;
    }

    // cbox
    let mut ctext: [u8; 96] = [0; 96];
    unsafe {
        let zeros = [0; 96];
        crypto_box_afternm(&mut ctext[0], &zeros[0], 96, &nonce[0], &clientshortserverlong[0]);
    }

    // complete ClientHello packet
    let mut packet = ClientHello {
        signature: *array_ref![signature.as_slice(), 0, 8],
        server_ext: SERVER_EXT,
        client_ext: [0; 16],
        client_sterm_pk: clientshorttermpk,
        pad: [0; 64],
        nonce: *array_ref![nonce[16..], 0, 8],
        cbox: *array_ref![ctext[16..], 0, 80]
    };

    // dump ClientHello
    println!("sending");
    println!("signature {}", packet.signature.to_hex());
    println!("server_ext {}", packet.server_ext.to_hex());
    println!("client_ext {}", packet.client_ext.to_hex());
    println!("client_sterm_pk {}", packet.client_sterm_pk.to_hex());
    println!("pad {}", packet.pad.to_hex());
    println!("nonce {}", packet.nonce.to_hex());
    println!("cbox {}", packet.cbox.to_hex());
    println!("clientshortserverlong {}", clientshortserverlong.to_hex());

    // send
    let p: *const ClientHello = &packet;
    let p: *const u8 = p as *const u8;
    socket.send_to(unsafe{slice::from_raw_parts(p, mem::size_of::<ClientHello>())}, "127.0.0.1:12345");

    // recv ServerCookie
    let mut buf: [u8; 1024] = [0; 1024];
    println!("receiving");
    let (len, src) = socket.recv_from(&mut buf).unwrap();
    println!("received {} bytes from {}", len, src);
    let scookie: &ServerCookie = unsafe { mem::transmute(&buf) };

    // dump ServerCookie
    println!("signature {}", scookie.signature.to_hex());
    println!("client_ext {}", scookie.client_ext.to_hex());
    println!("server_ext {}", scookie.server_ext.to_hex());
    println!("nonce {}", scookie.nonce.to_hex());
    println!("cbox {}", scookie.cbox.to_hex());
}
