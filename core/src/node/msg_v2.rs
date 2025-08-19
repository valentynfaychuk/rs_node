#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("message v2 is only {0} bytes")]
    WrongLength(usize),
    #[error("version format is invalid")]
    VersionFormat,
    #[error("version is out of range, expected 0..=255")]
    VersionOutOfRange,
    #[error("bad public key length, expected 48 bytes, got {0}")]
    BadPkLen(usize),
    #[error("bad signature length, expected 96 bytes, got {0}")]
    BadSigLen(usize),
    #[error("invalid magic, expected 'AMA'")]
    InvalidMagic,
    #[error("invalid flags, expected 0b00000001, got {0}")]
    InvalidFlags(u8),
    #[error("message not signed")]
    NotSigned,
    #[error("invalid shard index, expected 0..=65535, got {0}")]
    InvalidShardIndex(u16),
    #[error("invalid shard total, expected 0..=65535, got {0}")]
    InvalidShardTotal(u16),
    #[error("invalid timestamp, expected 0..=18446744073709551615, got {0}")]
    InvalidTimestamp(u64),
    #[error("invalid original size, expected 0..=4294967295, got {0}")]
    InvalidOriginalSize(u32),
    #[error("version is not supported")]
    VersionNotSupported,
}

/// Signed Message Format (BLS Signature)
///
/// <<"AMA", version_3byte::3-binary, 0::7, 1::1, pk::48-binary, signature::96-binary,
///   shard_index::16, shard_total::16, ts_n::64, original_size::32,
///   msg_compressed_or_shard::binary>>
///
/// Offset  Length  Field               Description
/// ──────────────────────────────────────────────────────────────────
/// 0-2     3       Magic               "AMA" (0x414D41)
/// 3-5     3       Version             3-byte version (e.g., 1.1.2)
/// 6       1       Flags               Bits: 0000000[signed=1]
/// 7-54    48      Public Key          BLS12-381 public key (48 bytes)
/// 55-150  96      Signature           BLS12-381 signature (96 bytes)
/// 151-152 2       Shard Index         Current shard number (big-endian)
/// 153-154 2       Shard Total         Total shards * 2 (big-endian)
/// 155-162 8       Timestamp           Nanosecond timestamp (big-endian)
/// 163-166 4       Original Size       Size of original message (big-endian)
/// 167+    N       Payload/Shard       Message data or Reed-Solomon shard
#[derive(Debug)]
pub struct MessageV2 {
    pub version: String,
    pub pk: Vec<u8>,
    pub signature: Vec<u8>,
    pub shard_index: u16,
    pub shard_total: u16,
    pub ts_nano: u64,
    pub original_size: u32,
    pub payload: Vec<u8>,
}

impl TryFrom<&[u8]> for MessageV2 {
    type Error = Error;
    fn try_from(bin: &[u8]) -> Result<Self, Self::Error> {
        crate::metrics::inc_v2udp_packets();
        Self::try_from_inner(bin).map_err(|e| {
            crate::metrics::inc_v2_parsing_errors();
            e
        })
    }
}

impl TryInto<Vec<u8>> for MessageV2 {
    type Error = Error;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        if self.pk.len() != 48 {
            return Err(Error::BadPkLen(self.pk.len()));
        }
        if self.signature.len() != 96 {
            return Err(Error::BadSigLen(self.signature.len()));
        }
        let ver = Self::ver_to_bytes(&self.version)?;

        // 3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + payload
        let mut out = Vec::with_capacity(3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 + self.payload.len());

        // "AMA"
        out.extend_from_slice(b"AMA");

        // version_3byte
        out.extend_from_slice(&ver);

        // 0::7, 1::1 → one byte with LSB set
        out.push(0b0000_0001);

        // pk (48), signature (96)
        out.extend_from_slice(&self.pk);
        out.extend_from_slice(&self.signature);

        // shard_index::16, shard_total::16 (big-endian)
        out.extend_from_slice(&self.shard_index.to_be_bytes());
        out.extend_from_slice(&self.shard_total.to_be_bytes());

        // ts_n::64 (big-endian)
        out.extend_from_slice(&self.ts_nano.to_be_bytes());

        // original_size::32 (big-endian)
        out.extend_from_slice(&self.original_size.to_be_bytes());

        // msg_compressed_or_shard::binary (rest)
        out.extend_from_slice(&self.payload);

        Ok(out)
    }
}

impl MessageV2 {
    fn try_from_inner(bin: &[u8]) -> Result<Self, Error> {
        // Must be at least header length
        if bin.len() < 3 + 3 + 1 + 48 + 96 + 2 + 2 + 8 + 4 {
            crate::metrics::inc_v2_parsing_errors();
            return Err(Error::WrongLength(bin.len()));
        }

        // Magic
        if &bin[0..3] != b"AMA" {
            crate::metrics::inc_v2_parsing_errors();
            return Err(Error::InvalidMagic);
        }

        let version_bytes = &bin[3..6];
        let version = format!("{}.{}.{}", version_bytes[0], version_bytes[1], version_bytes[2]);

        // Next is 7 zero bits and 1 flag bit, total 1 byte
        let flag_byte = bin[6];
        if flag_byte & 0b11111110 != 0 {
            crate::metrics::inc_v2_parsing_errors();
            return Err(Error::InvalidFlags(flag_byte));
        }

        if flag_byte & 0b00000001 == 0 {
            return Err(Error::NotSigned);
        }

        let pk_start = 7;
        let pk_end = pk_start + 48;
        let pk = bin[pk_start..pk_end].to_vec();

        let sig_start = pk_end;
        let sig_end = sig_start + 96;
        let signature = bin[sig_start..sig_end].to_vec();

        let shard_index = u16::from_be_bytes(bin[sig_end..sig_end + 2].try_into().unwrap());
        let shard_total = u16::from_be_bytes(bin[sig_end + 2..sig_end + 4].try_into().unwrap());

        let ts_nano = u64::from_be_bytes(bin[sig_end + 4..sig_end + 12].try_into().unwrap());
        let original_size = u32::from_be_bytes(bin[sig_end + 12..sig_end + 16].try_into().unwrap());

        let payload = bin[sig_end + 16..].to_vec();

        Ok(Self { version, pk, signature, shard_index, shard_total, ts_nano, original_size, payload })
    }

    fn ver_to_bytes(v: &str) -> Result<[u8; 3], Error> {
        let parts: Vec<&str> = v.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::VersionFormat);
        }
        let mut out = [0u8; 3];
        for (i, p) in parts.iter().enumerate() {
            let n: i64 = p.parse().map_err(|_| Error::VersionFormat)?;
            if !(0..=255).contains(&n) {
                return Err(Error::VersionOutOfRange);
            }
            out[i] = n as u8;
        }
        Ok(out)
    }
}
