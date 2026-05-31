// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 The zqlu project contributors

use crate::{Zqlu, ZqluError, ZqluKeyType, bail_ii, base62};
use bytes::{BufMut, BytesMut};
use crc::{CRC_16_IBM_SDLC, Crc};
use ssh_key::PublicKey;
use ssh_key::public::{EcdsaPublicKey, KeyData, RsaPublicKey};

const RSA_F4: &[u8] = &[0x01, 0x00, 0x01];

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

fn serialise_rsa(key: &RsaPublicKey, buf: &mut BytesMut) -> Result<ZqluKeyType, ZqluError> {
    let exponent = key
        .e
        .as_positive_bytes()
        .ok_or_else(|| ZqluError::InvalidInput("RSA exponent must be positive".into()))?;
    let modulus = key
        .n
        .as_positive_bytes()
        .ok_or_else(|| ZqluError::InvalidInput("RSA modulus must be positive".into()))?;

    if exponent == RSA_F4 {
        let key_type = match modulus.len() {
            256 => Some(ZqluKeyType::Rsa2048),
            384 => Some(ZqluKeyType::Rsa3072),
            512 => Some(ZqluKeyType::Rsa4096),
            _ => None,
        };

        if let Some(key_type) = key_type {
            buf.put_slice(modulus);
            return Ok(key_type);
        }
    }

    put_length_value(exponent, buf);
    put_length_value(modulus, buf);
    Ok(ZqluKeyType::RsaExotic)
}

fn put_length_value(value: &[u8], buf: &mut BytesMut) {
    put_varint(value.len(), buf);
    buf.put_slice(value);
}

fn put_varint(mut value: usize, buf: &mut BytesMut) {
    while value >= 0x80 {
        buf.put_u8((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    buf.put_u8(value as u8);
}

fn serialise_key(key: &PublicKey, buf: &mut BytesMut) -> Result<ZqluKeyType, ZqluError> {
    Ok(match key.key_data() {
        KeyData::Ecdsa(key) => serialise_ecdsa(key, buf)?,
        KeyData::Ed25519(key) => {
            buf.put_slice(key.as_ref());
            ZqluKeyType::Ed25519
        }
        KeyData::Rsa(key) => serialise_rsa(key, buf)?,
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
        base62::encode(&buf)
    ))
}

#[cfg(test)]
mod tests {
    use crate::convert::from_public_key;
    use crate::test::str;
    use crate::{Zqlu, ZqluKeyType};
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
    fn test_from_public_key_p256_leading_zero() -> Result<()> {
        let key = str!("p256-leading-zero.openssh");
        let key = PublicKey::from_openssh(key)?;
        assert_eq!(from_public_key(&key)?, str!("p256-leading-zero.zq"),);
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

    #[test]
    fn test_from_public_key_rsa_2048() -> Result<()> {
        let key = PublicKey::from_openssh(str!("rsa2048.openssh"))?;
        let zqlu = from_public_key(&key)?;
        assert_eq!(zqlu, str!("rsa2048.zq"));
        assert_eq!(zqlu.get_key_type(), ZqluKeyType::Rsa2048);
        assert_eq!(
            Zqlu::new(str!("rsa2048.zq"))?.public_key().key_data(),
            key.key_data()
        );
        Ok(())
    }

    #[test]
    fn test_from_public_key_rsa_3072() -> Result<()> {
        let key = PublicKey::from_openssh(str!("rsa3072.openssh"))?;
        let zqlu = from_public_key(&key)?;
        assert_eq!(zqlu, str!("rsa3072.zq"));
        assert_eq!(zqlu.get_key_type(), ZqluKeyType::Rsa3072);
        assert_eq!(
            Zqlu::new(str!("rsa3072.zq"))?.public_key().key_data(),
            key.key_data()
        );
        Ok(())
    }

    #[test]
    fn test_from_public_key_rsa_4096() -> Result<()> {
        let key = PublicKey::from_openssh(str!("rsa4096.openssh"))?;
        let zqlu = from_public_key(&key)?;
        assert_eq!(zqlu, str!("rsa4096.zq"));
        assert_eq!(zqlu.get_key_type(), ZqluKeyType::Rsa4096);
        assert_eq!(
            Zqlu::new(str!("rsa4096.zq"))?.public_key().key_data(),
            key.key_data()
        );
        Ok(())
    }

    #[test]
    fn test_from_public_key_rsa_exotic() -> Result<()> {
        let key = PublicKey::from_openssh(str!("rsa2048-e3.openssh"))?;
        let zqlu = from_public_key(&key)?;
        assert_eq!(zqlu, str!("rsa2048-e3.zq"));
        assert_eq!(zqlu.get_key_type(), ZqluKeyType::RsaExotic);
        assert_eq!(
            Zqlu::new(str!("rsa2048-e3.zq"))?.public_key().key_data(),
            key.key_data()
        );
        Ok(())
    }
}
