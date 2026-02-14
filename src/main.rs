use anyhow::Result;
use clap::Parser;
use ssh_key::PublicKey;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use zqlu::from_public_key;

/// This tool converts an openssh key to
#[derive(Parser)]
struct Cli {
    #[clap(short, long, value_name = "FILE")]
    input: Option<PathBuf>,
    #[clap(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let input = read_input(cli.input)?;

    let key = PublicKey::from_openssh(&input)?;
    println!("{}", from_public_key(&key)?);
    Ok(())
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
