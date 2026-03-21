// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 The zqlu project contributors

mod convert;
#[cfg(test)]
mod test;

use codeckit::Base62;
use crc::{CRC_16_IBM_SDLC, Crc};
use num_enum::TryFromPrimitive;
use p256::NistP256;
use p256::elliptic_curve::pkcs8::der::Document;
use p256::elliptic_curve::pkcs8::{DecodePublicKey, SubjectPublicKeyInfoRef};
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

#[derive(Error, Debug)]
pub enum ParsePublicKeyError {
    #[error("Failed to parse the provided input as OpenSSH, zqlu, or PEM/SPKI public key text")]
    InvalidInput {
        openssh: ssh_key::Error,
        zqlu: ZqluError,
        pem: ZqluError,
    },
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

pub(crate) fn encode_base62(input: &[u8]) -> String {
    let leading_zeroes = input.iter().take_while(|&&byte| byte == 0).count();
    let encoded = Base62::encode(input);

    if leading_zeroes == 0 {
        encoded
    } else {
        format!(
            "{}{}",
            "0".repeat(leading_zeroes),
            &encoded[leading_zeroes..]
        )
    }
}

pub(crate) fn decode_base62(input: &str) -> Vec<u8> {
    Base62::decode(input)
}

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
        let key_and_checksum = decode_base62(&input[6..]);

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

pub fn parse(input: impl AsRef<str>) -> Result<PublicKey, ParsePublicKeyError> {
    let input = input.as_ref().trim();

    match PublicKey::from_openssh(input) {
        Ok(key) => Ok(key),
        Err(openssh) => match Zqlu::new(input) {
            Ok(zqlu) => Ok(zqlu.public_key().clone()),
            Err(zqlu) => match parse_pem_public_key(input) {
                Ok(key) => Ok(key),
                Err(pem) => Err(ParsePublicKeyError::InvalidInput { openssh, zqlu, pem }),
            },
        },
    }
}

fn parse_pem_public_key(input: &str) -> Result<PublicKey, ZqluError> {
    if !input.starts_with("-----BEGIN PUBLIC KEY-----") {
        bail_ii!("Input is not a PEM public key")
    }

    let pem = if input.ends_with('\n') {
        input.to_owned()
    } else {
        format!("{input}\n")
    };

    let ed25519 = parse_ed25519_pem_public_key(&pem);
    if let Ok(key) = ed25519 {
        return Ok(key);
    }

    let p256 = parse_p256_pem_public_key(&pem);
    if let Ok(key) = p256 {
        return Ok(key);
    }

    let p384 = parse_p384_pem_public_key(&pem);
    if let Ok(key) = p384 {
        return Ok(key);
    }

    let p521 = parse_p521_pem_public_key(&pem);
    if let Ok(key) = p521 {
        return Ok(key);
    }

    Err(ZqluError::InvalidInput(format!(
        "Failed to parse PEM public key as Ed25519 ({}) P-256 ({}) P-384 ({}) or P-521 ({})",
        match ed25519 {
            Err(err) => err,
            Ok(_) => unreachable!(),
        },
        match p256 {
            Err(err) => err,
            Ok(_) => unreachable!(),
        },
        match p384 {
            Err(err) => err,
            Ok(_) => unreachable!(),
        },
        match p521 {
            Err(err) => err,
            Ok(_) => unreachable!(),
        }
    )))
}

fn parse_ed25519_pem_public_key(input: &str) -> Result<PublicKey, ZqluError> {
    let (_label, doc) = Document::from_pem(input)
        .map_err(|err| ZqluError::InvalidInput(format!("Failed to parse PEM public key: {err}")))?;
    let spki = SubjectPublicKeyInfoRef::try_from(doc.as_bytes()).map_err(|err| {
        ZqluError::InvalidInput(format!("Failed to parse SPKI public key: {err}"))
    })?;

    if spki.algorithm.oid
        != p256::elliptic_curve::pkcs8::ObjectIdentifier::new_unwrap("1.3.101.112")
    {
        bail_ii!("PEM public key is not Ed25519")
    }

    if spki.algorithm.parameters.is_some() {
        bail_ii!("Ed25519 PEM public key must not have algorithm parameters")
    }

    let key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
        ZqluError::InvalidInput("Ed25519 PEM public key contains an invalid bit string".into())
    })?;
    let key = ssh_key::public::Ed25519PublicKey::try_from(key_bytes).map_err(|err| {
        ZqluError::InvalidInput(format!("Failed to parse Ed25519 public key: {err}"))
    })?;

    Ok(PublicKey::from(key))
}

fn parse_p256_pem_public_key(input: &str) -> Result<PublicKey, ZqluError> {
    let key = p256::PublicKey::from_public_key_pem(input)
        .map_err(|err| ZqluError::InvalidInput(format!("Failed to parse PEM public key: {err}")))?;
    let encoded = key.to_encoded_point(false);
    let key = EcdsaPublicKey::from_sec1_bytes(encoded.as_bytes()).map_err(|err| {
        ZqluError::InvalidInput(format!("Failed to parse SEC1 public key: {err}"))
    })?;
    Ok(PublicKey::from(key))
}

fn parse_p384_pem_public_key(input: &str) -> Result<PublicKey, ZqluError> {
    let key = p384::PublicKey::from_public_key_pem(input)
        .map_err(|err| ZqluError::InvalidInput(format!("Failed to parse PEM public key: {err}")))?;
    let encoded = key.to_encoded_point(false);
    let key = EcdsaPublicKey::from_sec1_bytes(encoded.as_bytes()).map_err(|err| {
        ZqluError::InvalidInput(format!("Failed to parse SEC1 public key: {err}"))
    })?;
    Ok(PublicKey::from(key))
}

fn parse_p521_pem_public_key(input: &str) -> Result<PublicKey, ZqluError> {
    let key = p521::PublicKey::from_public_key_pem(input)
        .map_err(|err| ZqluError::InvalidInput(format!("Failed to parse PEM public key: {err}")))?;
    let encoded = key.to_encoded_point(false);
    let key = EcdsaPublicKey::from_sec1_bytes(encoded.as_bytes()).map_err(|err| {
        ZqluError::InvalidInput(format!("Failed to parse SEC1 public key: {err}"))
    })?;
    Ok(PublicKey::from(key))
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
    use crate::{ParsePublicKeyError, Zqlu, ZqluError, parse};
    use anyhow::Result;

    fn assert_pem_roundtrip(input: &str, openssh_prefix: &str) -> Result<()> {
        let key = parse(input)?;
        let openssh = key.to_openssh()?;
        assert!(openssh.starts_with(openssh_prefix));

        let zqlu = Zqlu::from_public_key(&key)?;
        assert_eq!(zqlu.public_key().to_openssh()?, openssh);
        Ok(())
    }

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
    fn test_parse_openssh() -> Result<()> {
        let key = parse(str!("ed25519.openssh"))?;
        assert_eq!(key.to_openssh()?, str!("ed25519.openssh"));
        Ok(())
    }

    #[test]
    fn test_parse_zqlu() -> Result<()> {
        let key = parse(str!("ed25519.zq"))?;
        assert_eq!(key.to_openssh()?, str!("ed25519.openssh"));
        Ok(())
    }

    #[test]
    fn test_parse_ed25519_pem() -> Result<()> {
        assert_pem_roundtrip(str!("ed25519.pem"), "ssh-ed25519 ")
    }

    #[test]
    fn test_parse_p256_pem() -> Result<()> {
        assert_pem_roundtrip(str!("p256.pem"), "ecdsa-sha2-nistp256 ")
    }

    #[test]
    fn test_parse_p384_pem() -> Result<()> {
        assert_pem_roundtrip(str!("p384.pem"), "ecdsa-sha2-nistp384 ")
    }

    #[test]
    fn test_parse_p521_pem() -> Result<()> {
        assert_pem_roundtrip(str!("p521.pem"), "ecdsa-sha2-nistp521 ")
    }

    #[test]
    fn test_parse_trimmed() -> Result<()> {
        let key = parse(format!("\n  {}\n", str!("ed25519.zq")))?;
        assert_eq!(key.to_openssh()?, str!("ed25519.openssh"));
        Ok(())
    }

    #[test]
    fn test_parse_invalid() {
        assert!(matches!(
            parse("not a key"),
            Err(ParsePublicKeyError::InvalidInput { .. })
        ));
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
