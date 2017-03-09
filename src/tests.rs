#[cfg(test)]

pub mod tests {

    use std::mem;
    use libcurvecp::*;

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
    const SERVER_NAME:&'static str = "machine.example.com";

    #[test]
    fn test_client_hello() {
        let mut ctx: CCPContext = CCPContext::new();
        let mut buf: [u8; CCP_MAX_PACKET_SIZE] = [0; CCP_MAX_PACKET_SIZE];
        let mut ret = ctx.mk_client_hello(&mut buf,
                                          PUBLICKEY, SECRETKEY,
                                          PUBLICKEY,
                                          [0; 16], SERVER_EXT);
        if ret > 0 {
            ret = ctx.parse_client_hello(&buf, ret as usize, PUBLICKEY, SECRETKEY, SERVER_EXT);
        }
        assert!(ret == 224)
    }

    #[test]
    fn test_client_initiate() {
        let mut ctx: CCPContext = CCPContext::new();
        let mut buf: [u8; CCP_MAX_PACKET_SIZE] = [0; CCP_MAX_PACKET_SIZE];
        let msg = String::from("TESTTESTTESTTEST").into_bytes();
        let msg = msg.as_slice();
        let mut ret = ctx.mk_client_initiate(&mut buf,
                                             SERVER_NAME,
                                             msg);
        if ret > 0 {
            ret = ctx.parse_client_initiate(&buf, ret as usize);
        }
        assert!(ret == 544 + msg.len() as isize);
    }

    #[test]
    fn test_client_message() {
        let mut ctx: CCPContext = CCPContext::new();
        let mut buf: [u8; CCP_MAX_PACKET_SIZE] = [0; CCP_MAX_PACKET_SIZE];
        let msg = String::from("TESTTESTTESTTEST").into_bytes();
        let msg = msg.as_slice();
        let mut ret = ctx.mk_client_message(&mut buf,
                                            msg);
        if ret > 0 {
            ret = ctx.parse_client_message(&buf, ret as usize);
        }
        assert!(ret == 96 + msg.len() as isize);
    }

    #[test]
    fn test_server_cookie() {
        let mut ctx: CCPContext = CCPContext::new();
        let mut buf: [u8; CCP_MAX_PACKET_SIZE] = [0; CCP_MAX_PACKET_SIZE];
        let mut ret = ctx.mk_server_cookie(&mut buf);
        if ret > 0 {
            ret = ctx.parse_server_cookie(&buf, ret as usize);
        }
        assert!(ret == mem::size_of::<ServerCookie>() as isize);
    }

    #[test]
    fn test_server_message() {
        let mut ctx: CCPContext = CCPContext::new();
        let mut buf: [u8; CCP_MAX_PACKET_SIZE] = [0; CCP_MAX_PACKET_SIZE];
        let msg = String::from("TESTTESTTESTTEST").into_bytes();
        let msg = msg.as_slice();
        let mut ret = ctx.mk_server_message(&mut buf,
                                            msg);
        if ret > 0 {
            ret = ctx.parse_server_message(&buf, ret as usize);
        }
        assert!(ret == 64 + msg.len() as isize);
    }
}
