use std::io::{Read, Write};
pub trait Cipher {
    fn encrypt<R, W>(&self, src: &mut R, dst: &mut W) -> anyhow::Result<()>
    where
        R: Read,
        W: Write;

    fn decrypt<R, W>(&self, src: &mut R, dst: &mut W) -> anyhow::Result<()>
    where
        R: Read,
        W: Write;
}
