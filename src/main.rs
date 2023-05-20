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
}

const MAGIC_BYTES: &[u8] = b"rs_file_cipher";
const MAGIC_BYTES_LEN: usize = 14;
const FORMAT_VERSION: u16 = 0x0001;
const HEADER_LEN: usize = MAGIC_BYTES_LEN + 2;

fn processing_file<P: AsRef<std::path::Path>>(
    input: P,
    output: P,
    encrypt: bool,
    xor: u8,
) -> Result<()> {
    let in_file = File::open(input)?;

    let mut br = BufReader::new(in_file);
    let mut bw: BufWriter<File>;

    let mut buffer = vec![0u8; 1024];

    // let begin_time = Instant::now();
    if encrypt {
        let out_file = OpenOptions::new().create(true).write(true).open(output)?;
        bw = BufWriter::new(out_file);
        bw.write_all(MAGIC_BYTES)?;
        let version = FORMAT_VERSION.to_be_bytes();
        bw.write_all(&version)?;
    } else {
        let mut buffer = [0u8; HEADER_LEN];
        br.read_exact(&mut buffer)?;
        let index = MAGIC_BYTES
            .iter()
            .zip(buffer[0..MAGIC_BYTES_LEN].iter())
            .position(|(a, b)| a != b);

        if let Some(_) = index {
            return Err(anyhow!(
                "The input file is not a file encrypted by file_cipher"
            ));
        }
        let mut bytes = [0u8; 2];
        bytes[0] = buffer[MAGIC_BYTES_LEN];
        bytes[1] = buffer[MAGIC_BYTES_LEN + 1];
        let version = u16::from_be_bytes(bytes);
        let out_file = OpenOptions::new().create(true).write(true).open(output)?;
        bw = BufWriter::new(out_file);
    }

    loop {
        let read_len = br.read(&mut buffer)?;
        if read_len == 0 {
            break;
        }
        let out: Vec<u8> = buffer[0..read_len].iter().map(|v| v ^ xor).collect();
        bw.write_all(&out)?;
    }

    bw.flush()?;

    // let end_time = Instant::now();
    // println!("elapsed time: {:?}", end_time.duration_since(begin_time));
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if !cli.output.exists() {
        let copied = cli.output.clone();
        std::fs::create_dir_all(copied)?;
        // return Err(anyhow!("The output dir does not exist"));
    }

    if cli.xor == 0 {
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
