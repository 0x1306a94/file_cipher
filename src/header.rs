use byte_struct::*;

use crate::error::FileCipherError;
use crate::version::Version;

pub(crate) const MAGIC_BYTES: &[u8] = b"rs_file_cipher";
pub(crate) const MAGIC_BYTES_LEN: usize = MAGIC_BYTES.len();
pub(crate) const HEADER_LEN: usize = MAGIC_BYTES_LEN + 2;

#[derive(ByteStruct, PartialEq, Debug)]
#[byte_struct_be]
pub(crate) struct Header {
    magic: [u8; MAGIC_BYTES_LEN],
    format: u16,
}

impl Header {
    pub(crate) fn new(version: Version) -> Self {
        let mut h = Header {
            magic: [0u8; MAGIC_BYTES_LEN],
            format: version.into(),
        };
        h.magic.copy_from_slice(MAGIC_BYTES);
        h
    }

    pub(crate) fn format(&self) -> u16 {
        self.format
    }
}

impl TryFrom<&[u8]> for Header {
    type Error = FileCipherError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != Header::BYTE_LEN {
            return Err(FileCipherError::NotLongEnough);
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

        let header = Header::read_bytes(bytes);
        if let Err(msg) = Version::try_from(header.format) {
            return Err(FileCipherError::Other(msg.to_string()));
        }
        Ok(header)
    }
}
