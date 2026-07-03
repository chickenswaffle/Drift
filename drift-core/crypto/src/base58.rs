//! Base58 (Bitcoin alphabet), byte-for-byte compatible with `drift.crypto`'s
//! `b58encode` / `b58decode`. No checksum — DRIFT adds its own framing.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Encode bytes as a base58 string. Leading zero bytes map to leading '1's,
/// matching the reference implementation.
pub fn encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|&&b| b == 0).count();

    // Big-endian base conversion via repeated division on a byte-vector.
    let mut digits: Vec<u8> = Vec::new();
    for &byte in data {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }

    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for &d in digits.iter().rev() {
        out.push(ALPHABET[d as usize] as char);
    }
    // The all-zero input yields no digits; the leading '1's already cover it.
    if out.is_empty() {
        // Empty input → empty string (matches the reference).
    }
    out
}

/// Decode a base58 string back to bytes. Returns `None` on an invalid character.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text.chars().take_while(|&c| c == '1').count();

    let mut bytes: Vec<u8> = Vec::new();
    for c in text.chars() {
        let val = ALPHABET.iter().position(|&a| a as char == c)? as u32;
        let mut carry = val;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for case in [&b""[..], b"\x00", b"\x00\x00\x01", b"hello world"] {
            assert_eq!(decode(&encode(case)).unwrap(), case);
        }
    }
}
