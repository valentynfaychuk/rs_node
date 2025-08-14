/// Translated from https://github.com/amadeus-robot/reedsolomon_ex
use anyhow::{Error, anyhow};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use std::sync::Mutex;

pub const SHARD_SIZE: usize = 1024;

pub struct ReedSolomonResource {
    pub p_encoder: Mutex<ReedSolomonEncoder>,
    pub p_decoder: Mutex<ReedSolomonDecoder>,
}

pub fn create_resource(
    data_shards: usize,
    recovery_shards: usize,
) -> Result<ReedSolomonResource, Error> {
    let size_shard = SHARD_SIZE;

    let encoder = ReedSolomonEncoder::new(data_shards, recovery_shards, size_shard)
        .map_err(|_| anyhow!("can't create encoder"))?;
    let decoder = ReedSolomonDecoder::new(data_shards, recovery_shards, size_shard)
        .map_err(|_| anyhow!("can't create decoder"))?;
    let resource = ReedSolomonResource {
        p_encoder: Mutex::new(encoder),
        p_decoder: Mutex::new(decoder),
    };
    Ok(resource)
}

pub fn encode_shards(
    resource: ReedSolomonResource,
    data: &[u8],
) -> Result<Vec<(usize, Vec<u8>)>, Error> {
    let chunk_size = SHARD_SIZE;

    let mut encoder_lock = resource
        .p_encoder
        .lock()
        .map_err(|_| anyhow!("poisoned mutex"))?;

    let chunk_count = (data.len() + 1023) / SHARD_SIZE;
    let mut encoded_shards = Vec::with_capacity(chunk_count * 2);
    let mut itr = 0;

    // Step through `data` in increments of `chunk_size`.
    for chunk_start in (0..data.len()).step_by(chunk_size) {
        let chunk_end = (chunk_start + chunk_size).min(data.len());
        let chunk = &data[chunk_start..chunk_end];

        // Create a 1024-byte buffer initialized to 0.
        let mut buffer = [0u8; SHARD_SIZE];
        buffer[..chunk.len()].copy_from_slice(chunk);

        encoder_lock
            .add_original_shard(&buffer)
            .map_err(|_| anyhow!("can't add shard"))?;

        let bin = buffer.to_vec();
        encoded_shards.push((itr, bin));
        itr += 1;
    }

    let result = encoder_lock.encode().map_err(|_| anyhow!("can't encode"))?;
    let recovery: Vec<_> = result.recovery_iter().collect();
    for recovered_shard in recovery {
        let bin = recovered_shard.to_vec();
        encoded_shards.push((itr, bin));
        itr += 1;
    }

    Ok(encoded_shards)
}

pub fn decode_shards(
    resource: ReedSolomonResource,
    shards: Vec<(usize, Vec<u8>)>,
    total_shards: usize,
    original_size: usize,
) -> Result<Vec<u8>, Error> {
    let mut decoder_lock = resource
        .p_decoder
        .lock()
        .map_err(|_| anyhow!("poisoned mutex"))?;

    let mut combined = vec![0u8; original_size];

    let half = total_shards / 2;
    for (index, bin) in shards {
        let idx_usize = index as usize;
        if idx_usize < half {
            let shard_data = bin.as_slice();

            let offset = idx_usize * SHARD_SIZE;
            // Protect against going past original_size
            let end = (offset + shard_data.len()).min(original_size);
            combined[offset..end].copy_from_slice(&shard_data[..(end - offset)]);

            decoder_lock
                .add_original_shard(index, shard_data)
                .map_err(|_| anyhow!("can't add shard"))?;
        } else {
            decoder_lock
                .add_recovery_shard(index - half, bin.as_slice())
                .map_err(|_| anyhow!("can't add shard"))?;
        }
    }
    let result = decoder_lock.decode().map_err(|_| anyhow!("can't decode"))?;

    for idx in 0..half {
        if let Some(shard_data) = result.restored_original(idx) {
            let offset = idx * SHARD_SIZE;
            let end = (offset + shard_data.len()).min(original_size);
            combined[offset..end].copy_from_slice(&shard_data[..(end - offset)]);
        }
    }

    Ok(combined)
}
