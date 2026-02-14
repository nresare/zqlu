use bytes::{BufMut, BytesMut};
use codeckit::Base62;
use crc::{CRC_16_IBM_SDLC, Crc};
use ssh_key::public::KeyData;
use ssh_key::{EcdsaCurve, PublicKey};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZqluError {
    #[error("Failed to parse the provided input as a key")]
    InvalidInput,
    #[error("Zqlu does not yet support the supplied key type")]
    UnsupportedKeyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ZuluKeyType {
    Ed25519 = b'A',
    Rsa = b'B',
    P256Odd = b'C',
    P256Even = b'D',
    P384Odd = b'E',
    P384Even = b'F',
    P521Odd = b'G',
    P521Even = b'H',
    EXT = b'X',
}

type Zqlu = String;

pub fn from_public_key(input: &PublicKey) -> Result<Zqlu, ZqluError> {
    let mut buf = BytesMut::new();
    let key_type = match input.key_data() {
        KeyData::Ecdsa(key) => {
            let bytes = key.as_ref();

            if bytes.is_empty() {
                return Err(ZqluError::InvalidInput);
            }
            if bytes[0] != 0x04 {
                return Err(ZqluError::InvalidInput);
            }
            // skip the first byte, split in two equal parts and write the first one
            let x_size = (bytes.len() - 1) / 2;
            buf.put_slice(&bytes[1..x_size + 1]);

            let even = bytes[bytes.len() - 1] % 2 == 0;

            match key.curve() {
                EcdsaCurve::NistP256 => {
                    if even {
                        ZuluKeyType::P256Even
                    } else {
                        ZuluKeyType::P256Odd
                    }
                }
                EcdsaCurve::NistP384 => {
                    if even {
                        ZuluKeyType::P384Even
                    } else {
                        ZuluKeyType::P384Odd
                    }
                }
                EcdsaCurve::NistP521 => {
                    if even {
                        ZuluKeyType::P521Even
                    } else {
                        ZuluKeyType::P521Odd
                    }
                }
            }
        }
        KeyData::Ed25519(key) => {
            buf.put_slice(key.as_ref());
            ZuluKeyType::Ed25519
        }
        KeyData::Rsa(_) => {
            return Err(ZqluError::UnsupportedKeyType);
        }
        &_ => return Err(ZqluError::UnsupportedKeyType),
    };
    let crc = Crc::<u16>::new(&CRC_16_IBM_SDLC);
    let mut crc = crc.digest();
    crc.update(b"zq.lu");
    crc.update(&[key_type as u8]);
    crc.update(&buf);
    buf.put_u16(crc.finalize());

    Ok(format!(
        "zq.lu{}{}",
        char::from(key_type as u8),
        Base62::encode(&buf)
    ))
}

#[cfg(test)]
mod tests {
    use crate::from_public_key;
    use anyhow::Result;
    use ssh_key::PublicKey;

    #[test]
    fn test_from_public_key_ed25519() -> Result<()> {
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKQQ9RtF1SCEl296sQ6A7un2s1MWdtxcPqNC7SiLRM0h";
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(
            "zq.luAAhI0TjjRFd5K5vfy4hig23m7bppmotzOLVIkwFnPMfVWDp",
            from_public_key(&key)?
        );
        Ok(())
    }

    #[test]
    fn test_from_public_key_p256() -> Result<()> {
        let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLwTgyd3Co4r9dyFqA6uK+6B1o77KIjvcusce1QEYhxNwwhC6XyIoXtqmw93Jw3eOh7RRtP0YiYaVM4Lvxgd4NA=";
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(
            "zq.luDCGME4UXnRi5W6z3rr8tUTR8dINmiDFB3Y32Jb9ivQ3wC4S",
            from_public_key(&key)?
        );
        Ok(())
    }
}
