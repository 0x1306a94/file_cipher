use byte_struct::*;

use crate::error::FileCipherError;
use crate::utils;
use crate::version::Version;

pub(crate) const MAGIC_BYTES: &[u8] = b"rs_file_cipher";
pub(crate) const MAGIC_BYTES_LEN: usize = MAGIC_BYTES.len();
pub(crate) const HEADER_LEN: usize = MAGIC_BYTES_LEN + 2;

pub(crate) const ECC_PUBLIC_KEY_LEN: usize = 64;
pub(crate) const ECC_PRIVATE_KEY_LEN: usize = 32;

#[derive(ByteStruct, PartialEq, Debug)]
#[byte_struct_be]
pub(crate) struct XorHeader {
    magic: [u8; MAGIC_BYTES_LEN],
    format: u16,
}

impl XorHeader {
    pub(crate) fn new() -> Self {
        let mut h = XorHeader {
            magic: [0u8; MAGIC_BYTES_LEN],
            format: Version::V1.into(),
        };
        h.magic.copy_from_slice(MAGIC_BYTES);
        h
    }

    pub(crate) fn format(&self) -> u16 {
        self.format
    }
}

impl TryFrom<&[u8]> for XorHeader {
    type Error = FileCipherError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != XorHeader::BYTE_LEN {
            return Err(FileCipherError::NotLongEnough(XorHeader::BYTE_LEN));
        }

        let index = MAGIC_BYTES
            .iter()
            .zip(bytes[0..MAGIC_BYTES_LEN].iter())
            .position(|(a, b)| a != b);

        if let Some(_) = index {
            return Err(FileCipherError::Other(
                "The input file is not a file encrypted by file_cipher".to_owned(),
            ));
        }

        let header = XorHeader::read_bytes(bytes);
        if let Err(msg) = Version::try_from(header.format) {
            return Err(FileCipherError::Other(msg.to_string()));
        }
        Ok(header)
    }
}

#[derive(ByteStruct, PartialEq, Debug)]
#[byte_struct_be]
pub(crate) struct AesECCHeader {
    magic: [u8; MAGIC_BYTES_LEN],
    format: u16,
    key: [u8; ECC_PUBLIC_KEY_LEN],
    iv: [u8; 16],
}

impl AesECCHeader {
    pub(crate) fn new(publickey: &str, iv: &[u8; 16]) -> Self {
        let mut h = AesECCHeader {
            magic: [0u8; MAGIC_BYTES_LEN],
            format: Version::V2.into(),
            key: [0u8; ECC_PUBLIC_KEY_LEN],
            iv: [0u8; 16],
        };
        h.magic.copy_from_slice(MAGIC_BYTES);
        let key_bytes = utils::decode_hex(publickey).unwrap();
        h.key.copy_from_slice(&key_bytes);
        h.iv.copy_from_slice(iv);
        h
    }

    pub(crate) fn format(&self) -> u16 {
        self.format
    }

    pub(crate) fn key_bytes(&self) -> &[u8; ECC_PUBLIC_KEY_LEN] {
        &self.key
    }

    pub(crate) fn iv_bytes(&self) -> &[u8; 16] {
        &self.iv
    }
}

impl TryFrom<&[u8]> for AesECCHeader {
    type Error = FileCipherError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != AesECCHeader::BYTE_LEN {
            return Err(FileCipherError::NotLongEnough(AesECCHeader::BYTE_LEN));
        }

        let index = MAGIC_BYTES
            .iter()
            .zip(bytes[0..MAGIC_BYTES_LEN].iter())
            .position(|(a, b)| a != b);

        if let Some(_) = index {
            return Err(FileCipherError::Other(
                "The input file is not a file encrypted by file_cipher".to_owned(),
            ));
        }

        let header = AesECCHeader::read_bytes(bytes);
        if let Err(msg) = Version::try_from(header.format) {
            return Err(FileCipherError::Other(msg.to_string()));
        }

        Ok(header)
    }
}
