use std::net::UdpSocket;
use std::time::Duration;

mod proto;
mod proto_enc;

fn main() -> std::io::Result<()> {
    let t = vec![
        107, 46, 97, 96, 96, 96, 44, 103, 202, 47, 40, 231, 46, 207, 200, 143, 79, 44, 74, 141,
        175, 204, 47, 5, 0,
    ];

    let msg = proto_enc::parse_nodeproto(&t);
    println!("{:?}", msg);

    let t1 = vec![
        65, 77, 65, 1, 1, 1, 1, 172, 110, 236, 111, 108, 227, 99, 105, 252, 127, 190, 173, 99, 15,
        70, 239, 27, 128, 145, 149, 193, 212, 241, 138, 252, 195, 207, 147, 190, 164, 48, 91, 11,
        219, 116, 10, 73, 48, 222, 64, 213, 184, 15, 55, 219, 86, 44, 6, 138, 5, 26, 198, 109, 117,
        101, 164, 141, 22, 109, 150, 221, 111, 56, 237, 199, 123, 203, 191, 119, 140, 29, 35, 162,
        144, 202, 14, 33, 76, 43, 67, 251, 91, 32, 138, 68, 245, 9, 115, 56, 210, 61, 192, 116,
        209, 2, 168, 4, 150, 164, 213, 216, 220, 14, 199, 139, 87, 203, 77, 38, 50, 0, 114, 7, 249,
        67, 28, 106, 134, 65, 106, 123, 125, 176, 77, 179, 233, 153, 38, 100, 165, 118, 119, 188,
        59, 216, 199, 247, 75, 183, 234, 45, 154, 43, 136, 0, 0, 0, 1, 24, 89, 159, 74, 21, 38,
        169, 23, 0, 0, 0, 25, 107, 46, 97, 96, 96, 96, 44, 103, 202, 47, 40, 231, 46, 207, 200,
        143, 79, 44, 74, 141, 175, 204, 47, 5, 0,
    ];
    let msg = proto_enc::unpack_message_v2(&t1);
    println!("{:?}", msg);

    // Target UDP address of an Amadeus node.
    let addr = std::env::var("UDP_ADDR").unwrap_or_else(|_| "127.0.0.1:36969".to_string());
    // Bind a local UDP socket on an ephemeral port.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Send a simple ping message to the node.
    socket.send_to(b"ping", &addr)?;

    println!("sent");

    // Wait for a response from the node.
    let mut buf = [0u8; 65535];
    let (len, src) = socket.recv_from(&mut buf)?;
    println!("received {} bytes from {}", len, src);
    Ok(())
}
