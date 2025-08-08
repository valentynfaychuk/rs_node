use std::net::UdpSocket;
use std::time::Duration;

mod genesis;
mod proto;
mod proto_enc;
mod test_data; // refers to folder `src/test_data`
use test_data::ping::PING; // import specific items

fn main() -> std::io::Result<()> {
    let t = vec![
        107, 46, 97, 96, 96, 96, 44, 103, 202, 47, 40, 231, 46, 207, 200, 143, 79, 44, 74, 141,
        175, 204, 47, 5, 0,
    ];

    let msg = proto_enc::parse_nodeproto(&t);
    println!("{:?}", msg);

    let ping = proto::MessageV2 {
        version: "1.1.1".to_string(),
        pk: vec![
            172, 110, 236, 111, 108, 227, 99, 105, 252, 127, 190, 173, 99, 15, 70, 239, 27, 128,
            145, 149, 193, 212, 241, 138, 252, 195, 207, 147, 190, 164, 48, 91, 11, 219, 116, 10,
            73, 48, 222, 64, 213, 184, 15, 55, 219, 86, 44, 6,
        ],
        signature: vec![
            143, 92, 174, 21, 75, 133, 77, 52, 173, 66, 53, 190, 66, 1, 90, 49, 159, 23, 155, 179,
            169, 184, 70, 206, 60, 221, 190, 234, 240, 126, 145, 133, 135, 190, 147, 30, 126, 98,
            110, 161, 193, 10, 215, 184, 100, 203, 116, 83, 22, 121, 76, 229, 49, 57, 240, 246,
            229, 20, 28, 68, 104, 70, 165, 188, 163, 8, 174, 94, 24, 100, 218, 128, 73, 161, 176,
            43, 167, 156, 210, 117, 58, 38, 46, 67, 231, 247, 2, 239, 212, 59, 255, 105, 143, 30,
            22, 222,
        ],
        shard_index: 0,
        shard_total: 1,
        ts_nano: 1754616311234332055,
        original_size: 57,
        payload: vec![
            107, 46, 97, 96, 96, 96, 41, 103, 202, 47, 40, 103, 41, 200, 204, 75, 47, 103, 43, 202,
            207, 47, 73, 77, 41, 103, 206, 203, 204, 41, 231, 40, 73, 205, 45, 200, 47, 74, 204,
            129, 112, 89, 74, 138, 227, 115, 243, 216, 24, 148, 220, 220, 219, 103, 48, 2, 0,
        ],
    };

    let t1 = proto_enc::encode_message_v2(&ping).expect("should encode");
    //println!("{:?}", msg);
    println!("{:?}", t1);

    // Target UDP address of an Amadeus node.
    let addr = std::env::var("UDP_ADDR").unwrap_or_else(|_| "127.0.0.1:36969".to_string());
    // Bind a local UDP socket on an ephemeral port.
    let socket = UdpSocket::bind("0.0.0.0:36969")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Send a simple ping message to the node.
    socket.send_to(&t1, &addr)?;

    println!("sent");

    for _ in 1..1000 {
        // Wait for a response from the node.
        let mut buf = [0u8; 65535];
        let (len, src) = socket.recv_from(&mut buf)?;
        println!("received {} bytes from {}", len, src);

        let data = &buf[..len];
        // println!("{:?}", data);
        let unpacked = proto_enc::unpack_message_v2(&data).map(|m| {
            let x = proto_enc::parse_nodeproto(&m.payload);

            match x {
                Ok(proto::NodeProto::Ping(_)) => {}
                Ok(a) => {
                    println!("{:?}", a);
                }
                _ => {}
            }
        });
    }
    Ok(())
}
