#[inline]
pub fn bcat(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut v = Vec::with_capacity(total);
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}
