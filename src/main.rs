use std::path::PathBuf;

use clap::Parser;
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::time::Instant;

use anyhow::{anyhow, Result};

#[derive(Parser)]
#[command(version = "1.0.0")]
#[command(about = "Image encryption", long_about = None)]
struct Cli {
    #[arg(long, short, help = "input image file path")]
    input: PathBuf,

    #[arg(long, short, help = "output image file path")]
    output: PathBuf,

    #[arg(
        long,
        short,
        conflicts_with = "decrypt",
        help = "encrypt the input image"
    )]
    encrypt: bool,

    #[arg(
        long,
        short,
        conflicts_with = "encrypt",
        help = "decrypt the input image"
    )]
    decrypt: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let out_path: PathBuf = if cli.output.is_dir() {
        let mut output = cli.output.clone();
        output.push(cli.input.file_name().unwrap());
        output
    } else {
        cli.output
    };

    let in_file = File::open(cli.input)?;
    let out_file = OpenOptions::new().create(true).write(true).open(out_path)?;
    let mut br = BufReader::new(in_file);
    let mut bw = BufWriter::new(out_file);

    let mut buffer = vec![0u8; 1024];

    let magic_bytes = "rs_img_cipher".as_bytes();
    let xor: u8;

    let begin_time = Instant::now();
    if cli.encrypt {
        let mut rng = rand::thread_rng();
        xor = rng.gen_range(1..u8::MAX);
        let mut magic_buf = Vec::<u8>::with_capacity(magic_bytes.len() + 1);
        magic_buf.extend_from_slice(&magic_bytes[0..]);
        magic_buf.push(xor);

        bw.write_all(&magic_buf)?;
    } else {
        let mut buffer = [0u8; 14];
        br.read_exact(&mut buffer)?;
        let b = &buffer[0..13];
        let index = magic_bytes.iter().zip(b.iter()).position(|(a, b)| a != b);
        if let Some(_) = index {
            return Err(anyhow!(
                "The input file is not a file encrypted by img_cipher"
            ));
        }
        xor = buffer[13];
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

    let end_time = Instant::now();
    println!("elapsed time: {:?}", end_time.duration_since(begin_time));
    Ok(())
}
