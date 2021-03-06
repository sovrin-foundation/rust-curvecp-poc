// TODO: implement safenonce

use std::mem;
use std::u64;
use std::str;
use rust_sodium_sys::*;
use rust_sodium::randombytes::randombytes;
//use rustc_serialize::hex::{ToHex};

pub const CCP_MAX_PACKET_SIZE:usize = 1152;
pub const CCP_MAX_CLIENT_INIT_PAYLOAD_SIZE:usize = 640;
pub const CCP_MAX_CLIENT_INIT_CBOX_SIZE:usize = 640 + 368;
pub const CCP_MAX_MESSAGE_SIZE:usize = 1104;

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

#[repr(packed)]
pub struct ClientInitiate {
    signature: [u8; 8],
    server_ext: [u8; 16],
    client_ext: [u8; 16],
    client_sterm_pk: [u8; 32],
    servercookie: [u8; 96],
    nonce: [u8; 8],
    cbox: [u8; CCP_MAX_CLIENT_INIT_CBOX_SIZE]
}

#[repr(packed)]
pub struct ServerMessage {
    signature: [u8; 8],
    client_ext: [u8; 16],
    server_ext: [u8; 16],
    nonce: [u8; 8],
    cbox: [u8; CCP_MAX_MESSAGE_SIZE + 16]
}

#[repr(packed)]
pub struct ClientMessage {
    signature: [u8; 8],
    server_ext: [u8; 16],
    client_ext: [u8; 16],
    client_sterm_pk: [u8; 32],
    nonce: [u8; 8],
    cbox: [u8; CCP_MAX_MESSAGE_SIZE + 16]
}

pub struct CCPContext {
    clientlongtermpk: [u8; 32],
    clientlongtermsk: [u8; 32],
    clientshorttermpk: [u8; 32],
    clientshorttermsk: [u8; 32],
    servershorttermpk: [u8; 32],
    servershorttermsk: [u8; 32],
    serverlongtermpk: [u8; 32],
    serverlongtermsk: [u8; 32],
    clientshortserverlong: [u8; 32],
    clientshortservershort: [u8; 32],
    clientlongserverlong: [u8; 32],
    clientshorttermnonce: u64,
    clientext: [u8; 16],
    serverext: [u8; 16],
    servercookie: [u8; 96]
}

impl CCPContext {
    pub fn new() -> CCPContext {
        CCPContext {
            clientlongtermpk: [0; 32],
            clientlongtermsk: [0; 32],
            clientshorttermpk: [0; 32],
            clientshorttermsk: [0; 32],
            servershorttermpk: [0; 32],
            servershorttermsk: [0; 32],
            serverlongtermpk: [0; 32],
            serverlongtermsk: [0; 32],
            clientshortserverlong: [0; 32],
            clientshortservershort: [0; 32],
            clientlongserverlong: [0; 32],
            clientshorttermnonce: 0,
            clientext: [0; 16],
            serverext: [0; 16],
            servercookie: [0; 96]
        }
    }

    /*
     * Make client hello packet
     */
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

        return mem::size_of::<ClientHello>() as isize;
    }

    /*
     * Parse server cookie packet
     */
    pub fn parse_server_cookie(&mut self, buf: &[u8; CCP_MAX_PACKET_SIZE], size: usize) -> isize {
        let packet: &ServerCookie = unsafe { mem::transmute(buf) };
        if str::from_utf8(&packet.signature).unwrap() != "RL3aNMXK" {
            return -1;
        }
        if (packet.client_ext != self.clientext) ||
           (packet.server_ext != self.serverext) {
            return -2;
        }

        let x = String::from("CurveCPK________________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..16 {
            nonce[8+i] = packet.nonce[i];
        }

        let mut text: [u8; 160] = [0; 160];
        for i in 0..144 {
            text[16+i] = packet.cbox[i];
        }
        unsafe {
            if crypto_box_open_afternm(&mut text[0],
                                       &text[0], 160,
                                       &nonce[0],
                                       &self.clientshortserverlong[0]) != 0 {
                return -3;
            }
        }
        self.servershorttermpk = *array_ref![text[32..], 0, 32];
        self.servercookie = *array_ref![text[64..], 0, 96];

        return size as isize;
    }


    /*
     * Make client initiate packet
     */
    pub fn mk_client_initiate(&mut self,
                              buf: &mut [u8; CCP_MAX_PACKET_SIZE],
                              servername: &str,
                              msg: &[u8]) -> isize {
        if msg.len() < 16 || msg.len() > CCP_MAX_CLIENT_INIT_PAYLOAD_SIZE {
            return -1;
        }
        if servername.len() > 256 {
            return -2;
        }

        // signature
        let signature = String::from("QvnQ5XlI").into_bytes();

        let packet: &mut ClientInitiate = unsafe { mem::transmute(buf) };
        packet.signature = *array_ref![signature.as_slice(), 0, 8];
        packet.server_ext = self.serverext;
        packet.client_ext = self.clientext;
        packet.client_sterm_pk = self.clientshorttermpk;
        packet.servercookie = self.servercookie;

        // vouch
        let x = String::from("CurveCPV________________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        let r = randombytes(16);
        for i in 0..16 {
            nonce[8+i] = r[i];
        }
        let mut text: [u8; 64] = [0; 64];
        for i in 0..32 {
            text[32+i] = self.clientshorttermpk[i];
        }
        unsafe {
            crypto_box_afternm(&mut text[0],
                               &text[0], 64,
                               &nonce[0],
                               &self.clientlongserverlong[0]);
        }
        let mut vouch: [u8; 64] = [0; 64];
        for i in 0..16 {
            vouch[i] = nonce[8+i];
        }
        for i in 0..48 {
            vouch[16+i] = text[16+i];
        }

        // nonce
        self.clientshorttermnonce += 1;
        let x = String::from("CurveCP-client-I________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = ((self.clientshorttermnonce >> i*8) & 0xFF) as u8;
        }
        packet.nonce = *array_ref![nonce[16..], 0, 8];

        // cbox
        let mut text: [u8; 16 + CCP_MAX_CLIENT_INIT_CBOX_SIZE] = [0; 16 + CCP_MAX_CLIENT_INIT_CBOX_SIZE];
        for i in 0..32 {
            text[32+i] = self.clientlongtermpk[i];
        }
        for i in 0..64 {
            text[64+i] = vouch[i];
        }
        let x = nameparse(servername);
        for i in 0..x.len() {
            text[128+i] = x[i];
        }
        for i in 0..msg.len() {
            text[384+i] = msg[i];
        }
        unsafe {
            crypto_box_beforenm(&mut self.clientshortservershort[0],
                                &self.servershorttermpk[0],
                                &self.clientshorttermsk[0]);
            crypto_box_afternm(&mut text[0],
                               &text[0], (msg.len() + 384) as u64,
                               &nonce[0],
                               &self.clientshortservershort[0]);
        }
        packet.cbox = *array_ref![text[16..], 0, CCP_MAX_CLIENT_INIT_CBOX_SIZE];

        return 544 + msg.len() as isize;
    }

    /*
     * Parse server message
     */
    pub fn parse_server_message(&mut self, buf: &[u8; CCP_MAX_PACKET_SIZE], size: usize) -> isize {
        let packet: &ServerMessage = unsafe { mem::transmute(buf) };
        if str::from_utf8(&packet.signature).unwrap() != "RL3aNMXM" {
            return -1;
        }
        if (packet.client_ext != self.clientext) ||
           (packet.server_ext != self.serverext) {
            return -2;
        }

        let x = String::from("CurveCP-server-M________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = packet.nonce[i];
        }

        let mut text: [u8; CCP_MAX_MESSAGE_SIZE + 16] = [0; CCP_MAX_MESSAGE_SIZE + 16];
        for i in 0..size-48 {
            text[16+i] = packet.cbox[i];
        }
        unsafe {
            if crypto_box_open_afternm(&mut text[0],
                                       &text[0], (size-48+16) as u64,
                                       &nonce[0],
                                       &self.clientshortservershort[0]) != 0 {
                return -3;
            }
        }

        println!("ServerMessage: {}", str::from_utf8(&text).unwrap());

        return size as isize;
    }

    /*
     * Make client message packet
     */
    pub fn mk_client_message(&mut self,
                             buf: &mut [u8; CCP_MAX_PACKET_SIZE],
                             msg: &[u8]) -> isize {
        if msg.len() < 16 || msg.len() > CCP_MAX_MESSAGE_SIZE {
            return -1;
        }

        // signature
        let signature = String::from("QvnQ5XlM").into_bytes();

        let packet: &mut ClientMessage = unsafe { mem::transmute(buf) };
        packet.signature = *array_ref![signature.as_slice(), 0, 8];
        packet.server_ext = self.serverext;
        packet.client_ext = self.clientext;
        packet.client_sterm_pk = self.clientshorttermpk;

        // nonce
        self.clientshorttermnonce += 1;
        let x = String::from("CurveCP-client-M________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = ((self.clientshorttermnonce >> i*8) & 0xFF) as u8;
        }
        packet.nonce = *array_ref![nonce[16..], 0, 8];

        // cbox
        let mut text: [u8; 32 + CCP_MAX_MESSAGE_SIZE] = [0; 32 + CCP_MAX_MESSAGE_SIZE];
        for i in 0..msg.len() {
            text[32+i] = msg[i];
        }
        unsafe {
            crypto_box_afternm(&mut text[0],
                               &text[0], (msg.len() + 32) as u64,
                               &nonce[0],
                               &self.clientshortservershort[0]);
        }
        packet.cbox = *array_ref![text[16..], 0, CCP_MAX_MESSAGE_SIZE + 16];

        return 96 + msg.len() as isize;
    }


    /*
     * Parse client hello
     */
    pub fn parse_client_hello(&mut self,
                              buf: &[u8; CCP_MAX_PACKET_SIZE], size: usize,
                              serverlongtermpk: [u8; 32],
                              serverlongtermsk: [u8; 32],
                              serverext: [u8; 16]) -> isize {
        // init
        self.serverext = serverext;
        self.serverlongtermpk = serverlongtermpk;
        self.serverlongtermsk = serverlongtermsk;

        // parse
        let packet: &ClientHello = unsafe { mem::transmute(buf) };
        if str::from_utf8(&packet.signature).unwrap() != "QvnQ5XlH" {
            return -1;
        }
        if packet.server_ext != self.serverext {
            return -2;
        }

        // nonce
        let x = String::from("CurveCP-client-H________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = packet.nonce[i];
        }

        // client_sterm_pk
        self.clientshorttermpk = packet.client_sterm_pk;
        unsafe {
            crypto_box_beforenm(&mut self.clientshortserverlong[0],
                                &self.clientshorttermpk[0],
                                &serverlongtermsk[0]);
        }

        self.clientext = packet.client_ext;

        // cbox
        let mut text: [u8; 96] = [0; 96];
        for i in 0..80 {
            text[16+i] = packet.cbox[i];
        }
        unsafe {
            if crypto_box_open_afternm(&mut text[0],
                                       &text[0], 96,
                                       &nonce[0],
                                       &self.clientshortserverlong[0]) != 0 {
                return -3;
            }
        }

        // ignore content, it is client_sterm_pk + [0; 64]

        return size as isize;
    }


    /*
     * Make server cookie packet
     */
    pub fn mk_server_cookie(&mut self,
                            buf: &mut [u8; CCP_MAX_PACKET_SIZE]) -> isize {
        // signature
        let signature = String::from("RL3aNMXK").into_bytes();

        let packet: &mut ServerCookie = unsafe { mem::transmute(buf) };
        packet.signature = *array_ref![signature.as_slice(), 0, 8];
        packet.server_ext = self.serverext;
        packet.client_ext = self.clientext;

        // nonce
        self.clientshorttermnonce += 1;
        let x = String::from("CurveCPKminute-k________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        let r = randombytes(8); // FIXME: ???
        for i in 0..8 {
            nonce[16+i] = r[i];
        }
        packet.nonce = *array_ref![nonce[8..], 0, 16];

        unsafe {
            crypto_box_keypair(&mut self.servershorttermpk[0],
                               &mut self.servershorttermsk[0]);
        }

        // cbox
        let mut text: [u8; 160] = [0; 160];
        for i in 0..32 {
            text[32+i] = self.servershorttermpk[i];
        }
        for i in 0..16 {
            text[64+i] = nonce[8+i];
        }
        unsafe {
            crypto_box_afternm(&mut text[0],
                               &text[0], 160,
                               &nonce[0],
                               &self.clientshortserverlong[0]);
        }
        packet.cbox = *array_ref![text[16..], 0, 144];
        return mem::size_of::<ServerCookie>() as isize;
    }


    /*
     * Parse client initiate
     */
    pub fn parse_client_initiate(&mut self, buf: &[u8; CCP_MAX_PACKET_SIZE], size: usize) -> isize {
        let packet: &ClientInitiate = unsafe { mem::transmute(buf) };
        if str::from_utf8(&packet.signature).unwrap() != "QvnQ5XlI" {
            return -1;
        }
        if packet.server_ext != self.serverext {
            return -2;
        }

        // nonce
        let x = String::from("CurveCP-client-I________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = packet.nonce[i];
        }

        unsafe {
            crypto_box_beforenm(&mut self.clientshortservershort[0],
                                &self.clientshorttermpk[0],
                                &self.servershorttermsk[0]);
        }

        // cbox
        let mut text: [u8; 16 + CCP_MAX_CLIENT_INIT_CBOX_SIZE] = [0; 16 + CCP_MAX_CLIENT_INIT_CBOX_SIZE];
        for i in 0..(size - 160) {
            text[16+i] = packet.cbox[i];
        }
        unsafe {
            if crypto_box_open_afternm(&mut text[0],
                                       &text[0], (size - 160) as u64,
                                       &nonce[0],
                                       &self.clientshortservershort[0]) != 0 {
                return -3;
            }
        }
        for i in 0..32 {
            self.clientlongtermpk[i] = text[32+i];
        }

        // TODO: check server name

        unsafe {
            crypto_box_beforenm(&mut self.clientlongserverlong[0],
                                &self.clientlongtermpk[0],
                                &self.serverlongtermsk[0]);
        }

        return size as isize;
    }


    /*
     * Parse client message
     */
    pub fn parse_client_message(&mut self, buf: &[u8; CCP_MAX_PACKET_SIZE], size: usize) -> isize {
        let packet: &ClientMessage = unsafe { mem::transmute(buf) };
        if str::from_utf8(&packet.signature).unwrap() != "QvnQ5XlM" {
            return -1;
        }
        if packet.server_ext != self.serverext {
            return -2;
        }

        // nonce
        let x = String::from("CurveCP-client-M________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = packet.nonce[i];
        }

        // cbox
        let mut text: [u8; CCP_MAX_MESSAGE_SIZE + 16] = [0; CCP_MAX_MESSAGE_SIZE + 16];
        for i in 0..size-80 {
            text[16+i] = packet.cbox[i];
        }
        unsafe {
            if crypto_box_open_afternm(&mut text[0],
                                       &text[0], (size-80+16) as u64,
                                       &nonce[0],
                                       &self.clientshortservershort[0]) != 0 {
                return -3;
            }
        }

        println!("ClientMessage: {}", str::from_utf8(&text).unwrap());

        return size as isize;
    }


    /*
     * Make server message packet
     */
    pub fn mk_server_message(&mut self,
                             buf: &mut [u8; CCP_MAX_PACKET_SIZE],
                             msg: &[u8]) -> isize {
        if msg.len() < 16 || msg.len() > CCP_MAX_MESSAGE_SIZE {
            return -1;
        }

        // signature
        let signature = String::from("RL3aNMXM").into_bytes();

        let packet: &mut ServerMessage = unsafe { mem::transmute(buf) };
        packet.signature = *array_ref![signature.as_slice(), 0, 8];
        packet.server_ext = self.serverext;
        packet.client_ext = self.clientext;

        // nonce
        self.clientshorttermnonce += 1;
        let x = String::from("CurveCP-server-M________").into_bytes();
        let mut nonce: [u8; 24]  = *array_ref![x.as_slice(), 0, 24];
        for i in 0..8 {
            nonce[16+i] = ((self.clientshorttermnonce >> i*8) & 0xFF) as u8;
        }
        packet.nonce = *array_ref![nonce[16..], 0, 8];

        // cbox
        let mut text: [u8; 32 + CCP_MAX_MESSAGE_SIZE] = [0; 32 + CCP_MAX_MESSAGE_SIZE];
        for i in 0..msg.len() {
            text[32+i] = msg[i];
        }
        unsafe {
            crypto_box_afternm(&mut text[0],
                               &text[0], (msg.len() + 32) as u64,
                               &nonce[0],
                               &self.clientshortservershort[0]);
        }
        packet.cbox = *array_ref![text[16..], 0, CCP_MAX_MESSAGE_SIZE + 16];

        return 64 + msg.len() as isize;
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
        while s < src.len() && src[s] != '.' as u8 {
            dst.push(src[s]);
            s += 1;
        }
        if s < src.len() && src[s] == '.' as u8 {
            s += 1;
        }
    }
    return dst;
}
