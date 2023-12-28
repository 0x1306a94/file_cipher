use std::fmt;

#[derive(Debug)]
pub enum FileCipherError {
    // 长度不够
    NotLongEnough(usize),
    Other(String),
}

impl fmt::Display for FileCipherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileCipherError::NotLongEnough(len) => {
                write!(f, "The length must be at least {}", len)
            }
            FileCipherError::Other(message) => write!(f, "Other error: {}", message),
        }
    }
}

impl std::error::Error for FileCipherError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}
