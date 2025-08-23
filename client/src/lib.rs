#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct UdpLoggedDatagram {
    src: std::net::SocketAddr,
    data: Vec<u8>,
}

impl UdpLoggedDatagram {
    pub fn new(src: std::net::SocketAddr, data: Vec<u8>) -> Self {
        Self { src, data }
    }
}

impl TryFrom<UdpLoggedDatagram> for Vec<u8> {
    type Error = bincode::error::EncodeError;

    fn try_from(dgram: UdpLoggedDatagram) -> Result<Self, Self::Error> {
        bincode::encode_to_vec(&dgram, bincode::config::standard())
    }
}

impl TryFrom<&[u8]> for UdpLoggedDatagram {
    type Error = bincode::error::DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (dgram, _): (UdpLoggedDatagram, usize) = bincode::decode_from_slice(bytes, bincode::config::standard())?;
        Ok(dgram)
    }
}

pub fn init_tracing() {
    // Minimal, dependency-light logging initialization.
    // Prefer not to fail if a subscriber is already set elsewhere.
    let _ = tracing_subscriber::fmt::try_init();

    // Install a panic hook that reports to stderr without requiring tracing macros.
    std::panic::set_hook(Box::new(|pi| {
        eprintln!("panic: {}", pi);
    }));
}

// use std::fmt;
// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
// use std::str::FromStr;
//
// #[derive(Copy, Clone, Eq, PartialEq, Hash, Default, Ord, PartialOrd, bincode::Encode, bincode::Decode)]
// pub struct Ip46(pub u128);
//
// impl Ip46 {
//     #[inline]
//     pub fn as_u128(self) -> u128 {
//         self.0
//     }
//
//     #[inline]
//     pub fn is_v4(self) -> bool {
//         let b = self.0.to_be_bytes();
//         b[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
//     }
//
//     #[inline]
//     pub fn is_v6(self) -> bool {
//         !self.is_v4()
//     }
//
//     #[inline]
//     pub fn to_std(self) -> IpAddr {
//         let b = self.0.to_be_bytes();
//         if self.is_v4() { IpAddr::V4(Ipv4Addr::new(b[12], b[13], b[14], b[15])) } else { IpAddr::V6(Ipv6Addr::from(b)) }
//     }
// }
//
// impl From<Ipv6Addr> for Ip46 {
//     #[inline]
//     fn from(v6: Ipv6Addr) -> Self {
//         Ip46(u128::from_be_bytes(v6.octets()))
//     }
// }
//
// impl From<Ipv4Addr> for Ip46 {
//     #[inline]
//     fn from(v4: Ipv4Addr) -> Self {
//         let o = v4.octets();
//         let b = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, o[0], o[1], o[2], o[3]];
//         Ip46(u128::from_be_bytes(b))
//     }
// }
//
// impl From<IpAddr> for Ip46 {
//     #[inline]
//     fn from(ip: IpAddr) -> Self {
//         match ip {
//             IpAddr::V4(v4) => v4.into(),
//             IpAddr::V6(v6) => v6.into(),
//         }
//     }
// }
//
// impl fmt::Display for Ip46 {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         let b = self.0.to_be_bytes();
//         if self.is_v4() {
//             write!(f, "{}.{}.{}.{}", b[12], b[13], b[14], b[15])
//         } else {
//             write!(f, "{}", Ipv6Addr::from(b))
//         }
//     }
// }
//
// impl FromStr for Ip46 {
//     type Err = std::net::AddrParseError;
//     fn from_str(s: &str) -> Result<Self, Self::Err> {
//         let ip: IpAddr = s.parse()?;
//         Ok(ip.into())
//     }
// }
