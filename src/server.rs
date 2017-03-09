#[macro_use]
extern crate arrayref;
extern crate rustc_serialize;
extern crate rust_sodium_sys;
extern crate rust_sodium;

use std::net::UdpSocket;
mod libcurvecp;
use libcurvecp::*;

#[cfg(test)]
mod tests;

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

const SERVER_ADDR:&'static str = "127.0.0.1:12345";
const SERVER_NAME:&'static str = "machine.example.com";

fn main() {
    let socket = UdpSocket::bind(SERVER_ADDR).expect("err");
    let mut ctx: CCPContext = CCPContext::new();

    let mut buf: [u8; CCP_MAX_PACKET_SIZE] = [0; CCP_MAX_PACKET_SIZE];

    // recv ClientHello
    println!("receiving ClientHello");
    let (len, client_ip) = socket.recv_from(&mut buf).unwrap();
    println!("received {} bytes from {}", len, client_ip);
    if ctx.parse_client_hello(&buf, len, PUBLICKEY, SECRETKEY, SERVER_EXT) < 0 {
        println!("client hello parsing failed");
        return;
    }

    // send ServerCookie
    println!("send mk_server_cookie");
    let ret = ctx.mk_server_cookie(&mut buf);
    if ret < 0 {
        println!("mk_server_cookie failure!");
        return;
    }
    socket.send_to(&buf[0..(ret as usize)], client_ip).expect("err");

    // recv ClientInitiate
    println!("receiving ClientInitiate");
    let (len, src) = socket.recv_from(&mut buf).unwrap();
    println!("received {} bytes from {}", len, src);
    if ctx.parse_client_initiate(&buf, len) < 0 {
        println!("client initiate parsing failed");
        return;
    }

    // send ServerMessage
    println!("send mk_server_message");
    let ret = ctx.mk_server_message(&mut buf,
                                    String::from("TESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTESTTEST").into_bytes().as_slice());
    if ret < 0 {
        println!("mk_server_message failure!");
        return;
    }
    socket.send_to(&buf[0..(ret as usize)], client_ip).expect("err");

    // recv ClientMessage
    println!("receiving ClientMessage");
    let (len, src) = socket.recv_from(&mut buf).unwrap();
    println!("received {} bytes from {}", len, src);
    if ctx.parse_client_message(&buf, len) < 0 {
        println!("client message parsing failed");
        return;
    }
}
