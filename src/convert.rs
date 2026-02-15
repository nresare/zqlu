use crate::{Zqlu, ZqluError, ZqluKeyType, bail_ii};
use bytes::{BufMut, BytesMut};
use codeckit::Base62;
use crc::{CRC_16_IBM_SDLC, Crc};
use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData};

fn serialise_ecdsa(key: &EcdsaPublicKey, buf: &mut BytesMut) -> Result<ZqluKeyType, ZqluError> {
    let bytes = key.as_ref();

    if bytes.is_empty() {
        bail_ii!("Raw key data can not be empty");
    }
    if bytes[0] != 0x04 {
        bail_ii!("Raw key has the wrong key marker, expected 0x04");
    }
    // skip the first byte, split in two equal parts and write the first one
    let x_size = (bytes.len() - 1) / 2;
    buf.put_slice(&bytes[1..x_size + 1]);

    let even = bytes[bytes.len() - 1] % 2 == 0;

    Ok(ZqluKeyType::from_curve_and_compressed_y(key.curve(), even))
}

fn serialise_key(key: &PublicKey, buf: &mut BytesMut) -> Result<ZqluKeyType, ZqluError> {
    Ok(match key.key_data() {
        KeyData::Ecdsa(key) => serialise_ecdsa(key, buf)?,
        KeyData::Ed25519(key) => {
            buf.put_slice(key.as_ref());
            ZqluKeyType::Ed25519
        }
        KeyData::Rsa(_) => {
            return Err(ZqluError::UnsupportedKeyType);
        }
        &_ => return Err(ZqluError::UnsupportedKeyType),
    })
}

pub fn from_public_key(input: &PublicKey) -> Result<Zqlu, ZqluError> {
    let mut buf = BytesMut::new();
    let key_type = serialise_key(input, &mut buf)?;
    let crc = Crc::<u16>::new(&CRC_16_IBM_SDLC);
    let mut crc = crc.digest();
    crc.update(b"zq.lu");
    crc.update(&[key_type as u8]);
    crc.update(&buf);
    buf.put_u16(crc.finalize());

    Zqlu::new(format!(
        "zq.lu{}{}",
        char::from(key_type as u8),
        Base62::encode(&buf)
    ))
}

#[cfg(test)]
mod tests {
    use crate::convert::from_public_key;
    use crate::test::str;
    use anyhow::Result;
    use ssh_key::PublicKey;

    #[test]
    fn test_from_public_key_ed25519() -> Result<()> {
        let key = str!("ed25519.openssh");
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(from_public_key(&key)?, str!("ed25519.zq"),);
        Ok(())
    }

    #[test]
    fn test_from_public_key_p256() -> Result<()> {
        let key = str!("p256.openssh");
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(from_public_key(&key)?, str!("p256.zq"),);
        Ok(())
    }

    #[test]
    fn test_from_public_key_p384() -> Result<()> {
        let key = str!("p384.openssh");
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(from_public_key(&key)?, str!("p384.zq"),);
        Ok(())
    }

    #[test]
    fn test_from_public_key_p521() -> Result<()> {
        let key = str!("p521.openssh");
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(from_public_key(&key)?, str!("p521.zq"),);
        Ok(())
    }
}
