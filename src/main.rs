use std::path::PathBuf;

use clap::Parser;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
// use std::time::Instant;

use anyhow::{anyhow, Result};

#[derive(Parser)]
#[command(version = "1.0.0")]
#[command(about = "Simply use xor to encrypt and decrypt files", long_about = None)]
struct Cli {
    #[arg(long, short, help = "input file path")]
    input: PathBuf,

    #[arg(
        long,
        short,
        help = "output file, if it is a directory, the final output file path is OUTPUT/INPUT.filename"
    )]
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
}

const MAGIC_BYTES: &[u8] = b"rs_file_cipher";
const MAGIC_BYTES_LEN: usize = 14;

fn main() -> Result<()> {
    let cli = Cli::parse();
    let out_path: PathBuf = if cli.output.is_dir() {
        let mut output = cli.output.clone();
        output.push(cli.input.file_name().unwrap());
        output
    } else {
        cli.output
    };

    if cli.xor == 0 {
        return Err(anyhow!("The xor parameter cannot be zero"));
    }

    let in_file = File::open(cli.input)?;
    let out_file = OpenOptions::new().create(true).write(true).open(out_path)?;
    let mut br = BufReader::new(in_file);
    let mut bw = BufWriter::new(out_file);

    let mut buffer = vec![0u8; 1024];

    // let begin_time = Instant::now();
    if cli.encrypt {
        bw.write_all(MAGIC_BYTES)?;
    } else {
        let mut buffer = [0u8; MAGIC_BYTES_LEN];
        br.read_exact(&mut buffer)?;
        let index = MAGIC_BYTES
            .iter()
            .zip(buffer.iter())
            .position(|(a, b)| a != b);
        if let Some(_) = index {
            return Err(anyhow!(
                "The input file is not a file encrypted by file_cipher"
            ));
        }
    }

    loop {
        let read_len = br.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        let out: Vec<u8> = buffer[0..read_len].iter().map(|v| v ^ cli.xor).collect();
        bw.write_all(&out)?;
    }

    bw.flush()?;

    // let end_time = Instant::now();
    // println!("elapsed time: {:?}", end_time.duration_since(begin_time));
    Ok(())
}
