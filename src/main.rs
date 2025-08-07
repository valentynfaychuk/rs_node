use std::net::UdpSocket;
use std::time::Duration;

fn main() -> std::io::Result<()> {
    // Target UDP address of an Amadeus node.
    let addr = std::env::var("UDP_ADDR").unwrap_or_else(|_| "127.0.0.1:36969".to_string());
    // Bind a local UDP socket on an ephemeral port.
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(5)))?;

    // Send a simple ping message to the node.
    socket.send_to(b"ping", &addr)?;

    // Wait for a response from the node.
    let mut buf = [0u8; 65535];
    let (len, src) = socket.recv_from(&mut buf)?;
    println!("received {} bytes from {}", len, src);
    Ok(())
}
