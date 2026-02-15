mod convert;
#[cfg(test)]
mod test;

use codeckit::Base62;
use crc::{CRC_16_IBM_SDLC, Crc};
use num_enum::TryFromPrimitive;
use p256::NistP256;
use p256::elliptic_curve::point::DecompressPoint;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::elliptic_curve::subtle::Choice;
use p384::NistP384;
use p521::NistP521;
use primeorder::elliptic_curve::sec1::{EncodedPoint, ModulusSize};
use primeorder::elliptic_curve::{CurveArithmetic, FieldBytesSize};
use primeorder::generic_array::GenericArray;
use primeorder::{AffinePoint, PrimeCurveParams};
use ssh_key::public::EcdsaPublicKey;
use ssh_key::{EcdsaCurve, PublicKey};
use std::fmt::{Display, Formatter};
use std::ops::Not;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZqluError {
    #[error("Failed to parse the provided input as a key: {0}")]
    InvalidInput(String),
    #[error("Zqlu does not yet support the supplied key type")]
    UnsupportedKeyType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum ZqluKeyType {
    Ed25519 = b'A',
    //    Rsa = b'B',
    P256Odd = b'C',
    P256Even = b'D',
    P384Odd = b'E',
    P384Even = b'F',
    P521Odd = b'G',
    P521Even = b'H',
    EXT = b'X',
}

impl ZqluKeyType {
    fn from_curve_and_compressed_y(ecdsa_curve: EcdsaCurve, even: bool) -> Self {
        if even {
            match ecdsa_curve {
                EcdsaCurve::NistP256 => ZqluKeyType::P256Even,
                EcdsaCurve::NistP384 => ZqluKeyType::P384Even,
                EcdsaCurve::NistP521 => ZqluKeyType::P521Even,
            }
        } else {
            match ecdsa_curve {
                EcdsaCurve::NistP256 => ZqluKeyType::P256Odd,
                EcdsaCurve::NistP384 => ZqluKeyType::P384Odd,
                EcdsaCurve::NistP521 => ZqluKeyType::P521Odd,
            }
        }
    }

    fn even(&self) -> bool {
        matches!(
            self,
            ZqluKeyType::P256Even | ZqluKeyType::P384Even | ZqluKeyType::P521Even
        )
    }
}

#[derive(Debug)]
pub struct Zqlu(String, PublicKey);

impl Zqlu {}

macro_rules! bail_ii {
    ($msg:expr) => {
        return Err(ZqluError::InvalidInput($msg.into()))
    };
}
use ZqluError::UnsupportedKeyType;
pub(crate) use bail_ii;

impl Zqlu {
    pub fn new(input: impl AsRef<str>) -> Result<Self, ZqluError> {
        let input = input.as_ref();

        if !input.starts_with("zq.lu") {
            bail_ii!("Input must start with 'zq.lu'")
        }

        let key_type = try_get_type(input)?;
        for c in input.chars().skip(6) {
            if !c.is_ascii_alphanumeric() && !c.is_ascii_whitespace() {
                bail_ii!("Invalid character in Zqlu key")
            }
        }
        let key_and_checksum = Base62::decode(&input[6..]);

        validate_crc(key_type, &key_and_checksum)?;

        let key = &key_and_checksum[..key_and_checksum.len() - 2];

        Ok(Zqlu(input.to_string(), to_public_key(key, key_type)?))
    }

    pub fn get_key_type(&self) -> ZqluKeyType {
        try_get_type(&self.0).expect("not possible to create an instance with an invalid key type")
    }

    pub fn from_public_key(public_key: &PublicKey) -> Result<Zqlu, ZqluError> {
        convert::from_public_key(public_key)
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.1
    }
}

fn to_public_key(key: &[u8], key_type: ZqluKeyType) -> Result<PublicKey, ZqluError> {
    let even = key_type.even();
    Ok(match key_type {
        ZqluKeyType::Ed25519 => {
            if key.len() != 32 {
                bail_ii!("Invalid Ed25519 key length")
            }
            let Ok(key) = ssh_key::public::Ed25519PublicKey::try_from(key) else {
                bail_ii!("Invalid Ed25519 key")
            };
            PublicKey::from(key)
        }
        ZqluKeyType::P256Odd | ZqluKeyType::P256Even => {
            if key.len() != 32 {
                bail_ii!("Invalid P256 key length")
            }
            let encoded = decompress::<NistP256>(key, even)?;
            PublicKey::from(EcdsaPublicKey::NistP256(encoded))
        }
        ZqluKeyType::P384Odd | ZqluKeyType::P384Even => {
            if key.len() != 48 {
                bail_ii!("Invalid P384 key length")
            }
            let encoded = decompress::<NistP384>(key, even)?;
            PublicKey::from(EcdsaPublicKey::NistP384(encoded))
        }
        ZqluKeyType::P521Odd | ZqluKeyType::P521Even => {
            if key.len() != 66 {
                bail_ii!("Invalid P521 key length")
            }
            let encoded = decompress::<NistP521>(key, even)?;
            PublicKey::from(EcdsaPublicKey::NistP521(encoded))
        }
        _ => return Err(UnsupportedKeyType),
    })
}

fn decompress<C>(x: &[u8], y_is_even: bool) -> Result<EncodedPoint<C>, ZqluError>
where
    C: PrimeCurveParams + CurveArithmetic,
    AffinePoint<C>: DecompressPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let y_is_odd = Choice::from(y_is_even as u8).not();
    let x_bytes = GenericArray::from_slice(x);
    let point: AffinePoint<C> = AffinePoint::decompress(x_bytes, y_is_odd)
        .into_option()
        .ok_or(ZqluError::InvalidInput("Invalid key data".into()))?;
    Ok(point.to_encoded_point(false))
}

fn validate_crc(zqlu_key_type: ZqluKeyType, key_and_checksum: &[u8]) -> Result<(), ZqluError> {
    let crc = Crc::<u16>::new(&CRC_16_IBM_SDLC);
    let mut crc = crc.digest();
    crc.update(b"zq.lu");
    crc.update(&[zqlu_key_type as u8]);
    crc.update(&key_and_checksum[..key_and_checksum.len() - 2]);

    let checksum: [u8; 2] = key_and_checksum[key_and_checksum.len() - 2..]
        .try_into()
        .unwrap();
    if crc.finalize() != u16::from_be_bytes(checksum) {
        bail_ii!("Invalid CRC")
    }
    Ok(())
}

fn try_get_type(input: &str) -> Result<ZqluKeyType, ZqluError> {
    let Some(key_type) = input.chars().nth(5) else {
        bail_ii!("Input is too short to contain a key type")
    };
    ZqluKeyType::try_from_primitive(key_type as u8).map_err(|_| UnsupportedKeyType)
}

impl Display for Zqlu {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl PartialEq<&str> for Zqlu {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
mod tests {
    use crate::test::str;
    use crate::{Zqlu, ZqluError};
    use anyhow::Result;

    #[test]
    fn test_zqlu_new() -> Result<()> {
        // happy case
        Zqlu::new("zq.luDCGME4UXnRi5W6z3rr8tUTR8dINmiDFB3Y32Jb9ivQ3wC4S")?;
        assert!(matches!(Zqlu::new("test"), Err(ZqluError::InvalidInput(_))));
        assert!(matches!(
            Zqlu::new("zq.lu"),
            Err(ZqluError::InvalidInput(_))
        ));
        assert!(matches!(
            Zqlu::new("zq.luYwhatever"),
            Err(ZqluError::UnsupportedKeyType)
        ));
        assert!(matches!(
            Zqlu::new("zq.luA??"),
            Err(ZqluError::InvalidInput(_))
        ));
        assert!(matches!(
            Zqlu::new("zq.luYdeadbeef"),
            Err(ZqluError::UnsupportedKeyType)
        ));
        // happy case but with checksum modified
        assert!(matches!(
            Zqlu::new("zq.luDCGME4UXnRi5W6z3rr8tUTR8dINmiDFB3Y32Jb9ivQ3wC4Y"),
            Err(ZqluError::InvalidInput(_))
        ));
        Ok(())
    }

    #[test]
    fn test_zqlu_to_public_key_ed25519() -> Result<()> {
        let zqlu = Zqlu::new(str!("ed25519.zq"))?;
        let public_key = zqlu.public_key();
        assert_eq!(public_key.to_openssh()?, str!("ed25519.openssh"));
        Ok(())
    }

    #[test]
    fn test_zqlu_to_public_key_p256() -> Result<()> {
        let zqlu = Zqlu::new(str!("p256.zq"))?;
        let public_key = zqlu.public_key();
        assert_eq!(public_key.to_openssh()?, str!("p256.openssh"));
        Ok(())
    }

    #[test]
    fn test_zqlu_to_public_key_p384() -> Result<()> {
        let zqlu = Zqlu::new(str!("p384.zq"))?;
        let public_key = zqlu.public_key();
        assert_eq!(public_key.to_openssh()?, str!("p384.openssh"));
        Ok(())
    }

    #[test]
    fn test_zqlu_to_public_key_p521() -> Result<()> {
        let zqlu = Zqlu::new(str!("p521.zq"))?;
        let public_key = zqlu.public_key();
        assert_eq!(public_key.to_openssh()?, str!("p521.openssh"));
        Ok(())
    }
}
