use std::path::PathBuf;

use clap::Parser;
use clap_verbosity_flag::Verbosity;

use file_cipher::cipher::Cipher;
use log;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::time::Instant;

use anyhow::{anyhow, Result};
use file_cipher;

#[derive(Parser)]
#[command(version = "1.0.0")]
#[command(about = "Simply use xor to encrypt and decrypt files", long_about = None)]
struct Cli {
    #[arg(long, short, help = "input file path or input directory")]
    input: PathBuf,

    #[arg(long, short, help = "output directory")]
    output: PathBuf,

    #[arg(
        long,
        short,
        conflicts_with = "decrypt",
        help = "encrypt the input file"
    )]
    encrypt: bool,

    #[arg(
        long,
        short,
        conflicts_with = "encrypt",
        help = "decrypt the input file"
    )]
    decrypt: bool,

    #[arg(
        long,
        short,
        help = "each byte of the input file is xor evaluated against this value, and it can't be zero"
    )]
    xor: u8,

    #[command(flatten)]
    verbose: Verbosity,
}

fn processing_file<P: AsRef<std::path::Path>>(
    input: P,
    output: P,
    encrypt: bool,
    xor: u8,
) -> Result<()> {
    let input = input.as_ref();
    let output = output.as_ref();
    let in_file = File::open(input)?;

    let mut br = BufReader::new(in_file);
    let mut bw: BufWriter<File>;

    log::info!("input file: {}", input.to_str().unwrap());
    log::info!("output file: {}", output.to_str().unwrap());
    let begin_time = Instant::now();
    let cipher = file_cipher::xor::XorCipher::new(xor);
    if encrypt {
        let out_file = OpenOptions::new().create(true).write(true).open(output)?;
        bw = BufWriter::new(out_file);
        cipher.encrypt(&mut br, &mut bw)?;
    } else {
        let out_file = OpenOptions::new().create(true).write(true).open(output)?;
        bw = BufWriter::new(out_file);
        cipher.decrypt(&mut br, &mut bw)?;
    }

    let end_time = Instant::now();
    log::trace!("elapsed time: {:?}", end_time.duration_since(begin_time));
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    if !cli.output.exists() {
        let copied = cli.output.clone();
        log::info!("Create output directory: {}", copied.to_str().unwrap());
        std::fs::create_dir_all(copied)?;
        // return Err(anyhow!("The output dir does not exist"));
    }

    if cli.xor == 0 {
        log::error!("The xor parameter cannot be zero");
        return Err(anyhow!("The xor parameter cannot be zero"));
    }

    if cli.input.is_dir() {
        for entry in std::fs::read_dir(cli.input)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                continue;
            }

            let filename = path.file_name().unwrap();
            let mut output = cli.output.clone();
            output.push(filename);
            let _ = processing_file(path, output, cli.encrypt, cli.xor);
        }
    } else {
        let filename = cli.input.file_name().unwrap();
        let mut output = cli.output.clone();
        output.push(filename);
        processing_file(cli.input, output, cli.encrypt, cli.xor)?;
    }

    Ok(())
}
