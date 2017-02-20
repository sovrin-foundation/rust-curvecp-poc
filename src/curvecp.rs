use std::mem;
use std::u64;
use rust_sodium_sys::*;
use rust_sodium::randombytes::randombytes;

pub const CCP_MAX_PACKET_SIZE:usize = 1024;

#[repr(packed)]
pub struct ClientHello {
    signature: [u8; 8],
    server_ext: [u8; 16],
    client_ext: [u8; 16],
    client_sterm_pk: [u8; 32],
    pad: [u8; 64],
    nonce: [u8; 8],
    cbox: [u8; 80]
}

#[repr(packed)]
pub struct ServerCookie {
    signature: [u8; 8],
    client_ext: [u8; 16],
    server_ext: [u8; 16],
    nonce: [u8; 16],
    cbox: [u8; 144]
}

pub struct CCPContext {
    clientlongtermpk: [u8; 32],
    clientlongtermsk: [u8; 32],
    clientshorttermpk: [u8; 32],
    clientshorttermsk: [u8; 32],
    serverlongtermpk: [u8; 32],
    clientshortserverlong: [u8; 32],
    clientlongserverlong: [u8; 32],
    clientshorttermnonce: u64,
    clientext: [u8; 16],
    serverext: [u8; 16]
}

impl CCPContext {
    pub fn new() -> CCPContext {
        CCPContext {
            clientlongtermpk: [0; 32],
            clientlongtermsk: [0; 32],
            clientshorttermpk: [0; 32],
            clientshorttermsk: [0; 32],
            serverlongtermpk: [0; 32],
            clientshortserverlong: [0; 32],
            clientlongserverlong: [0; 32],
            clientshorttermnonce: 0,
            clientext: [0; 16],
            serverext: [0; 16]
        }
    }

    pub fn mk_client_hello(&mut self,
                       buf: &mut [u8; CCP_MAX_PACKET_SIZE],
                       clientlongtermpk: [u8; 32],
                       clientlongtermsk: [u8; 32],
                       serverlongtermpk: [u8; 32],
                       clientext: [u8; 16],
                       serverext: [u8; 16]) -> isize {
        // init
        self.clientext = clientext;
        self.serverext = serverext;
        self.clientlongtermpk = clientlongtermpk;
        self.serverlongtermpk = serverlongtermpk;
        self.clientlongtermsk = clientlongtermsk;
        self.clientshorttermpk = [0; 32];
        self.clientshorttermsk = [0; 32];
        self.clientshorttermnonce = randommod(281474976710656);
        self.clientshortserverlong = [0; 32];
        self.clientlongserverlong = [0; 32];
        self.clientshorttermnonce += 1;

        // keys
        unsafe {
            crypto_box_keypair(&mut self.clientshorttermpk[0],
                               &mut self.clientshorttermsk[0]);
            crypto_box_beforenm(&mut self.clientshortserverlong[0],
                                &mut self.serverlongtermpk[0],
                                &mut self.clientshorttermsk[0]);
            crypto_box_beforenm(&mut self.clientlongserverlong[0],
                                &mut self.serverlongtermpk[0],
                                &mut self.clientlongtermsk[0]);
        }

        // signature
        let signature = String::from("QvnQ5XlH").into_bytes();

        // nonce
        let x = String::from("CurveCP-client-H________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = ((self.clientshorttermnonce >> i*8) & 0xFF) as u8;
        }

        // cbox
        let mut ctext: [u8; 96] = [0; 96];
        unsafe {
            let zeros = [0; 96];
            crypto_box_afternm(&mut ctext[0], &zeros[0], 96, &nonce[0], &self.clientshortserverlong[0]);
        }

        // complete ClientHello packet
        let packet: &mut ClientHello = unsafe { mem::transmute(buf) };
        packet.signature = *array_ref![signature.as_slice(), 0, 8];
        packet.server_ext = self.serverext;
        packet.client_ext = self.clientext;
        packet.client_sterm_pk = self.clientshorttermpk;
        packet.pad = [0; 64];
        packet.nonce = *array_ref![nonce[16..], 0, 8];
        packet.cbox = *array_ref![ctext[16..], 0, 80];

        // dump ClientHello
        /*
        println!("ClientHello");
        println!("signature {}", packet.signature.to_hex());
        println!("server_ext {}", packet.server_ext.to_hex());
        println!("client_ext {}", packet.client_ext.to_hex());
        println!("client_sterm_pk {}", packet.client_sterm_pk.to_hex());
        println!("pad {}", packet.pad.to_hex());
        println!("nonce {}", packet.nonce.to_hex());
        println!("cbox {}", packet.cbox.to_hex());
         */

        // return
        return mem::size_of::<ClientHello>() as isize;
    }
}


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