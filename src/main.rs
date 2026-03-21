use anyhow::Result;
use clap::Parser;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;
use zqlu::{Zqlu, parse};

/// This tool converts between the openssh and zqlu public key formats
#[derive(Parser)]
struct Cli {
    #[clap(short, long, value_name = "FILE")]
    input: Option<PathBuf>,
    #[clap(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    #[clap(short, long, conflicts_with = "fingerprint")]
    decode: bool,
    #[clap(short, long, conflicts_with = "decode")]
    fingerprint: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let input = read_input(cli.input)?;
    let result = transform(&input, cli.decode, cli.fingerprint)?;
    if let Some(output) = cli.output {
        // we want a newline at the end of the file
        let key = format!("{}\n", result);
        File::create(output)?.write_all(key.as_bytes())?;
    } else {
        println!("{}", result);
    }
    Ok(())
}

fn transform(input: &str, decode: bool, fingerprint: bool) -> Result<String> {
    if fingerprint {
        let key = parse(input)?;
        return Ok(key.fingerprint(Default::default()).to_string());
    }

    match decode {
        true => {
            let zqlu = Zqlu::new(input)?;
            let key = zqlu.public_key();
            Ok(key.to_openssh()?)
        }
        false => {
            let key = parse(input)?;
            Ok(Zqlu::from_public_key(&key)?.to_string())
        }
    }
}

fn read_input(maybe_file: Option<PathBuf>) -> Result<String> {
    Ok(match maybe_file {
        Some(input) => {
            let mut file = File::open(input)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            String::from_utf8(buf)?
        }
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            String::from_utf8(buf)?
        }
    })
}

#[cfg(test)]
mod tests {
    use super::transform;
    use anyhow::Result;
    use ssh_key::PublicKey;

    #[test]
    fn test_fingerprint_from_openssh() -> Result<()> {
        let input = include_str!("../tests/ed25519.openssh");
        let expected = PublicKey::from_openssh(input)?
            .fingerprint(Default::default())
            .to_string();

        assert_eq!(transform(input, false, true)?, expected);
        Ok(())
    }

    #[test]
    fn test_fingerprint_from_zqlu() -> Result<()> {
        let openssh = include_str!("../tests/ed25519.openssh");
        let zqlu = include_str!("../tests/ed25519.zq");
        let expected = PublicKey::from_openssh(openssh)?
            .fingerprint(Default::default())
            .to_string();

        assert_eq!(transform(zqlu, false, true)?, expected);
        Ok(())
    }
}
