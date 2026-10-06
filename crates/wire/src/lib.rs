//! Redoubt serial framing: `COBS([ver] ++ payload ++ crc32_le) ++ 0x00`.
//!
//! CRC-32/ISO-HDLC (zlib) over `[ver] ++ payload`. The CRC detects corruption
//! only; it is NOT a security control (a hostile host can forge it). Any
//! anomaly yields a `DropReason`; nothing is ever partially processed.
#![no_std]
#![forbid(unsafe_code)]

pub const WIRE_VER: u8 = 0x01;
/// Largest inner payload (matches `abi::MAX_REQ`; responses are smaller).
pub const MAX_PAYLOAD: usize = 512;
const PRE_MAX: usize = 1 + MAX_PAYLOAD + 4;
/// Worst-case COBS output for n bytes is n + ceil(n/254); +1 delimiter.
/// PRE_MAX=517 -> 517 + 3 + 1 = 521.
pub const MAX_FRAME: usize = PRE_MAX + PRE_MAX.div_ceil(254) + 1;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DropReason {
    Cobs,
    Crc,
    Version,
    TooLong,
    Empty,
}

/// CRC-32/ISO-HDLC, bitwise (reflected poly 0xEDB88320).
pub fn crc32(parts: &[&[u8]]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for p in parts {
        for &b in *p {
            c ^= b as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
            }
        }
    }
    !c
}

/// COBS-encode `input` into `out` (no delimiter). Returns bytes written.
pub fn cobs_encode(input: &[u8], out: &mut [u8]) -> Result<usize, DropReason> {
    let mut w = 1usize; // slot 0 is the first code byte
    let mut code_at = 0usize;
    let mut code = 1u8;
    if out.is_empty() {
        return Err(DropReason::TooLong);
    }
    for &b in input {
        if b == 0 {
            out[code_at] = code;
            code = 1;
            code_at = w;
            *out.get_mut(w).ok_or(DropReason::TooLong)? = 0;
            w += 1;
        } else {
            *out.get_mut(w).ok_or(DropReason::TooLong)? = b;
            w += 1;
            code += 1;
            if code == 0xFF {
                out[code_at] = code;
                code = 1;
                code_at = w;
                *out.get_mut(w).ok_or(DropReason::TooLong)? = 0;
                w += 1;
            }
        }
    }
    out[code_at] = code;
    Ok(w)
}

/// COBS-decode `input` (no delimiter, must contain no 0x00) into `out`.
pub fn cobs_decode(input: &[u8], out: &mut [u8]) -> Result<usize, DropReason> {
    let mut i = 0usize;
    let mut w = 0usize;
    while i < input.len() {
        let code = input[i] as usize;
        if code == 0 {
            return Err(DropReason::Cobs);
        }
        i += 1;
        let end = i + code - 1;
        if end > input.len() {
            return Err(DropReason::Cobs);
        }
        let n = code - 1;
        let dst = out.get_mut(w..w + n).ok_or(DropReason::TooLong)?;
        dst.copy_from_slice(&input[i..end]);
        w += n;
        i = end;
        if code != 0xFF && i < input.len() {
            *out.get_mut(w).ok_or(DropReason::TooLong)? = 0;
            w += 1;
        }
    }
    Ok(w)
}

/// Frame `payload` into `out`; returns bytes written incl. the 0x00 delimiter.
pub fn frame(payload: &[u8], out: &mut [u8]) -> Result<usize, DropReason> {
    if payload.len() > MAX_PAYLOAD {
        return Err(DropReason::TooLong);
    }
    let mut pre = [0u8; PRE_MAX];
    pre[0] = WIRE_VER;
    pre[1..1 + payload.len()].copy_from_slice(payload);
    let crc = crc32(&[&pre[..1 + payload.len()]]);
    let n = 1 + payload.len();
    pre[n..n + 4].copy_from_slice(&crc.to_le_bytes());
    let w = cobs_encode(&pre[..n + 4], out)?;
    *out.get_mut(w).ok_or(DropReason::TooLong)? = 0;
    Ok(w + 1)
}

/// Deframe one complete frame (including its trailing 0x00) into `scratch`.
pub fn deframe<'a>(frame: &[u8], scratch: &'a mut [u8]) -> Result<&'a [u8], DropReason> {
    if frame.is_empty() {
        return Err(DropReason::Empty);
    }
    if frame.len() > MAX_FRAME {
        return Err(DropReason::TooLong);
    }
    let (&last, body) = frame.split_last().ok_or(DropReason::Empty)?;
    if last != 0 {
        return Err(DropReason::Cobs); // truncated: no delimiter
    }
    if body.is_empty() {
        return Err(DropReason::Empty);
    }
    let n = cobs_decode(body, scratch)?;
    if n < 1 + 4 {
        return Err(DropReason::Crc);
    }
    let dec = &scratch[..n];
    let (signed, crc_b) = dec.split_at(n - 4);
    let want = u32::from_le_bytes([crc_b[0], crc_b[1], crc_b[2], crc_b[3]]);
    if crc32(&[signed]) != want {
        return Err(DropReason::Crc);
    }
    if signed[0] != WIRE_VER {
        return Err(DropReason::Version);
    }
    Ok(&scratch[1..n - 4])
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn rt(p: &[u8]) {
        let mut enc = [0u8; 1024];
        let n = cobs_encode(p, &mut enc).unwrap();
        assert!(!enc[..n].contains(&0));
        let mut dec = [0u8; 1024];
        let m = cobs_decode(&enc[..n], &mut dec).unwrap();
        assert_eq!(&dec[..m], p);
    }

    #[test]
    fn crc_check_value() {
        assert_eq!(crc32(&[b"123456789"]), 0xCBF4_3926);
        assert_eq!(crc32(&[b"1234", b"56789"]), 0xCBF4_3926);
    }

    #[test]
    fn cobs_roundtrips() {
        rt(&[]);
        rt(&[0; 300]);
        rt(&[0]);
        rt(&[7; 253]);
        rt(&[7; 254]);
        rt(&[7; 255]);
        rt(&[7; 508]);
        rt(&[7; 517]);
        let v: Vec<u8> = (0..517u32).map(|i| (i % 3) as u8).collect();
        rt(&v);
    }

    #[test]
    fn cobs_known_vectors() {
        let mut o = [0u8; 8];
        let n = cobs_encode(&[0x11, 0x22, 0x00, 0x33], &mut o).unwrap();
        assert_eq!(&o[..n], &[3, 0x11, 0x22, 2, 0x33]);
    }

    #[test]
    fn cobs_bad_inputs() {
        let mut o = [0u8; 16];
        assert_eq!(cobs_decode(&[3, 1, 0, 2], &mut o), Err(DropReason::Cobs)); // interior zero
        assert_eq!(cobs_decode(&[5, 1, 2], &mut o), Err(DropReason::Cobs)); // bad length
    }

    #[test]
    fn frame_roundtrip_and_max() {
        for p in [&[][..], &[0u8; 512][..], &[9u8; 512][..], b"hello\x00world"] {
            let mut f = [0u8; MAX_FRAME];
            let n = frame(p, &mut f).unwrap();
            assert!(n <= MAX_FRAME);
            assert_eq!(f[..n].iter().filter(|&&b| b == 0).count(), 1);
            assert_eq!(f[n - 1], 0);
            let mut s = [0u8; MAX_FRAME];
            assert_eq!(deframe(&f[..n], &mut s).unwrap(), p);
        }
    }

    #[test]
    fn bit_flips_are_dropped() {
        let mut f = [0u8; MAX_FRAME];
        let n = frame(b"some payload \x00 bytes", &mut f).unwrap();
        let mut crc = 0;
        for i in 0..n {
            for b in 0..8 {
                let mut g = f;
                g[i] ^= 1 << b;
                let mut s = [0u8; MAX_FRAME];
                match deframe(&g[..n], &mut s) {
                    Err(DropReason::Crc) => crc += 1,
                    Err(_) => {} // flip made a zero / bad COBS length
                    Ok(_) => panic!("accepted corrupted frame"),
                }
            }
        }
        assert!(crc > 0);
    }

    #[test]
    fn truncated_oversized_empty_dropped() {
        let mut f = [0u8; MAX_FRAME];
        let n = frame(b"abcdef", &mut f).unwrap();
        let mut s = [0u8; MAX_FRAME];
        assert!(deframe(&f[..n - 1], &mut s).is_err());
        assert!(deframe(&f[..n / 2], &mut s).is_err());
        assert_eq!(deframe(&[], &mut s), Err(DropReason::Empty));
        assert_eq!(deframe(&[0], &mut s), Err(DropReason::Empty));
        let big = [1u8; MAX_FRAME + 1];
        assert_eq!(deframe(&big, &mut s), Err(DropReason::TooLong));
        assert_eq!(frame(&[0u8; 513], &mut f), Err(DropReason::TooLong));
        let mut tiny = [0u8; 4];
        assert!(frame(b"abcdef", &mut tiny).is_err());
        let mut small = [0u8; 3];
        assert!(deframe(&f[..n], &mut small).is_err());
    }

    #[test]
    fn wrong_version_dropped() {
        let pre = [0x02u8, 1, 2, 3];
        let crc = crc32(&[&pre]);
        let mut full = [0u8; 8];
        full[..4].copy_from_slice(&pre);
        full[4..].copy_from_slice(&crc.to_le_bytes());
        let mut f = [0u8; 32];
        let n = cobs_encode(&full, &mut f).unwrap();
        f[n] = 0;
        let mut s = [0u8; 32];
        assert_eq!(deframe(&f[..n + 1], &mut s), Err(DropReason::Version));
    }
}
