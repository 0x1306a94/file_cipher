#[derive(Debug, PartialEq, Eq)]
pub enum Version {
    V1,
    // V2,
}

impl From<Version> for u16 {
    fn from(value: Version) -> Self {
        match value {
            Version::V1 => 0x0001,
            // Version::V2 => 0x0002,
        }
    }
}

impl TryFrom<u16> for Version {
    type Error = &'static str;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Version::V1),
            // 0x0002 => Ok(Version::V2),
            _ => Err("Unsupported format"),
        }
    }
}
