use anyhow::Result;
use clap::Parser;
use ssh_key::PublicKey;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::path::PathBuf;
use zqlu::Zqlu;

/// This tool converts between the openssh and zqlu public key formats
#[derive(Parser)]
struct Cli {
    #[clap(short, long, value_name = "FILE")]
    input: Option<PathBuf>,
    #[clap(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
    #[clap(short, long)]
    decode: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let input = read_input(cli.input)?;
    let result = transform(&input, cli.decode)?;
    if let Some(output) = cli.output {
        // we want a newline at the end of the file
        let key = format!("{}\n", result);
        File::create(output)?.write_all(key.as_bytes())?;
    } else {
        println!("{}", result);
    }
    Ok(())
}

fn transform(input: &str, decode: bool) -> Result<String> {
    match decode {
        true => {
            let zqlu = Zqlu::new(input)?;
            let key = zqlu.public_key();
            Ok(key.to_openssh()?)
        }
        false => {
            let key = PublicKey::from_openssh(input)?;
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
