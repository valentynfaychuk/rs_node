use bincode::error::{DecodeError, EncodeError};
use bincode::{config::standard, decode_from_slice, encode_to_vec};
use std::fs::{File, OpenOptions};
use std::io;
use std::io::{BufReader, Write};
use std::net::SocketAddr;
use std::sync::{Mutex, OnceLock};
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep};

#[async_trait::async_trait]
pub trait DumpReplaySocket: Send + Sync {
    async fn dump_replay_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

#[async_trait::async_trait]
impl DumpReplaySocket for UdpSocket {
    async fn dump_replay_recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let recv_res = if let Some(reader_mutex) = udp_replay().as_ref() {
            // use the replay file instead of the real socket
            recv_from_replay(reader_mutex, buf).await
        } else {
            // fallback to real UDP socket when no replay file
            self.recv_from(buf).await
        };

        let (len, src) = recv_res?;

        // optionally dump the received datagram
        maybe_dump_datagram(src, &buf[..len]);

        Ok((len, src))
    }
}

fn udp_replay() -> &'static Option<Mutex<BufReader<File>>> {
    static UDP_REPLAY: OnceLock<Option<Mutex<BufReader<File>>>> = OnceLock::new();
    UDP_REPLAY.get_or_init(|| match std::env::var("UDP_REPLAY") {
        Ok(path) => match File::open(&path) {
            Ok(file) => {
                println!("replaying UDP packets from {path}");
                Some(Mutex::new(BufReader::new(file)))
            }
            Err(e) => {
                eprintln!("failed to open UDP_REPLAY file: {e}");
                None
            }
        },
        Err(_) => None,
    })
}

async fn recv_from_replay(reader_mutex: &Mutex<BufReader<File>>, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    // loop is needed to implement artificial blocking behavior on EOF
    // until somebody appends more data to the capture
    loop {
        use std::io::{Read, Seek, SeekFrom};
        enum ReplayAttempt {
            Data(usize, SocketAddr),
            Eof,
        }
        // file I/O while holding the lock only synchronously, drop lock before any .await
        let attempt = {
            let mut reader = reader_mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut data = Vec::new();
            let bytes_read = reader.read_to_end(&mut data)?;
            if bytes_read == 0 {
                ReplayAttempt::Eof
            } else {
                let (dgram, consumed) = decode_from_slice::<UdpLoggedDatagram, _>(&data, standard())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                let current_pos = reader.stream_position()?;
                reader.seek(SeekFrom::Start(current_pos - (bytes_read as u64) + (consumed as u64)))?;

                let payload = dgram.data();
                let copy_len = std::cmp::min(payload.len(), buf.len());
                buf[..copy_len].copy_from_slice(&payload[..copy_len]);

                ReplayAttempt::Data(copy_len, dgram.src())
            }
        };

        match attempt {
            ReplayAttempt::Eof => {
                sleep(Duration::from_secs(10)).await;
                continue;
            }
            ReplayAttempt::Data(copy_len, src) => {
                // re-dump what we 'received' if dumping is enabled
                maybe_dump_datagram(src, &buf[..copy_len]);
                return Ok((copy_len, src));
            }
        }
    }
}

fn maybe_dump_datagram(src: SocketAddr, payload: &[u8]) {
    if let Some(file_mutex) = udp_dump().as_ref() {
        if let Ok(mut f) = file_mutex.lock() {
            let dgram = UdpLoggedDatagram::new(src, payload.to_vec());
            if let Ok(bytes) = Vec::<u8>::try_from(dgram) {
                let _ = f.write_all(&bytes);
            }
        }
    }
}

fn udp_dump() -> &'static Option<Mutex<File>> {
    static UDP_DUMP: OnceLock<Option<Mutex<File>>> = OnceLock::new();
    UDP_DUMP.get_or_init(|| match std::env::var("UDP_DUMP") {
        Ok(path) => match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                println!("dumping UDP packets to {path}");
                Some(Mutex::new(file))
            }
            Err(e) => {
                eprintln!("failed to open UDP_DUMP file: {e}");
                None
            }
        },
        Err(_) => None,
    })
}

#[derive(Clone, bincode::Encode, bincode::Decode)]
pub struct UdpLoggedDatagram {
    src: SocketAddr,
    data: Vec<u8>,
}

impl UdpLoggedDatagram {
    pub fn new(src: SocketAddr, data: Vec<u8>) -> Self {
        Self { src, data }
    }

    pub fn src(&self) -> SocketAddr {
        self.src
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

impl TryFrom<UdpLoggedDatagram> for Vec<u8> {
    type Error = EncodeError;

    fn try_from(dgram: UdpLoggedDatagram) -> Result<Self, Self::Error> {
        encode_to_vec(&dgram, standard())
    }
}

impl TryFrom<&[u8]> for UdpLoggedDatagram {
    type Error = DecodeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(decode_from_slice(bytes, standard())?.0)
    }
}
