//! Bounded, streaming inspection of retained packet artifacts. No packet payload is decoded.
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Default)]
pub struct PacketCounts {
    pub packets: u64,
    pub truncated: bool,
    pub dropped_packets: Option<u64>,
}

pub fn pcapng_counts(path: &Path, limit: u64) -> io::Result<PacketCounts> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid or truncated PCAPNG");
    if size > limit || size < 28 {
        return Err(invalid());
    }
    let mut counts = PacketCounts::default();
    let mut offset = 0;
    let mut little = true;
    while offset < size {
        let mut header = [0u8; 12];
        file.read_exact(&mut header)?;
        let section = header[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
        if offset == 0 && !section {
            return Err(invalid());
        }
        if section {
            little = match &header[8..12] {
                [0x4d, 0x3c, 0x2b, 0x1a] => true,
                [0x1a, 0x2b, 0x3c, 0x4d] => false,
                _ => return Err(invalid()),
            };
        }
        let u32_at = |bytes: &[u8]| {
            let bytes: [u8; 4] = bytes.try_into().unwrap();
            if little {
                u32::from_le_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            }
        };
        let kind = u32_at(&header[..4]);
        let length = u32_at(&header[4..8]) as u64;
        if length < 12 || !length.is_multiple_of(4) || length > size - offset {
            return Err(invalid());
        }
        if section && length < 28 {
            return Err(invalid());
        }
        if kind == 6 || kind == 2 {
            if length < 32 {
                return Err(invalid());
            }
            let mut rest = [0u8; 16];
            file.read_exact(&mut rest)?;
            let captured = u32_at(&rest[8..12]) as u64;
            let original = u32_at(&rest[12..16]) as u64;
            if captured > original || captured.div_ceil(4) * 4 > length - 32 {
                return Err(invalid());
            }
            counts.packets += 1;
            counts.truncated |= captured < original;
        } else if kind == 3 {
            if length < 16 {
                return Err(invalid());
            }
            counts.packets += 1;
            counts.truncated |= u32_at(&header[8..12]) as u64 > length - 16;
        }
        file.seek(SeekFrom::Start(offset + length - 4))?;
        let mut trailer = [0u8; 4];
        file.read_exact(&mut trailer)?;
        if u32_at(&trailer) as u64 != length {
            return Err(invalid());
        }
        offset += length;
    }
    Ok(counts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_packet_count_and_malformed_capture() {
        let path =
            std::env::temp_dir().join(format!("foxhole-pcap-test-{}.pcapng", std::process::id()));
        let bytes = include_bytes!("../tests/fixtures/detection/network.pcapng");
        std::fs::write(&path, bytes).unwrap();
        assert!(pcapng_counts(&path, bytes.len() as u64).unwrap().packets > 0);
        assert!(pcapng_counts(&path, 1).is_err());
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(pcapng_counts(&path, bytes.len() as u64).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
