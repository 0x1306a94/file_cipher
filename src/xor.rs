use std::io::{Read, Write};

use byte_struct::*;

use crate::cipher::Cipher;
use crate::header;
use crate::version;

pub struct XorCipher {
    xor: u8,
}

impl XorCipher {
    pub fn new(xor: u8) -> Self {
        XorCipher { xor: xor }
    }
}

impl Cipher for XorCipher {
    fn encrypt<R, W>(&self, src: &mut R, dst: &mut W) -> anyhow::Result<()>
    where
        R: Read,
        W: Write,
    {
        let header = header::XorHeader::new();
        let mut header_bytes = [0u8; header::XorHeader::BYTE_LEN];
        header.write_bytes(&mut header_bytes);
        dst.write(&header_bytes)?;

        let mut buffer = vec![0u8; 1024];
        loop {
            let read_len = src.read(&mut buffer)?;
            if read_len == 0 {
                break;
            }
            let out: Vec<u8> = buffer[0..read_len].iter().map(|v| v ^ self.xor).collect();
            dst.write_all(&out)?;
        }

        dst.flush()?;

        Ok(())
    }

    fn decrypt<R, W>(&self, src: &mut R, dst: &mut W) -> anyhow::Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut header_bytes = [0u8; header::XorHeader::BYTE_LEN];
        src.read_exact(&mut header_bytes)?;
        let header = header::XorHeader::try_from(&header_bytes[0..])?;
        let version =
            version::Version::try_from(header.format()).map_err(|err| anyhow::anyhow!(err))?;
        if version != version::Version::V1 {
            return anyhow::Result::Err(anyhow::anyhow!("Only v1 is supported"));
        }
        let mut buffer = vec![0u8; 1024];
        loop {
            let read_len = src.read(&mut buffer)?;
            if read_len == 0 {
                break;
            }
            let out: Vec<u8> = buffer[0..read_len].iter().map(|v| v ^ self.xor).collect();
            dst.write_all(&out)?;
        }

        dst.flush()?;

        Ok(())
    }
}
