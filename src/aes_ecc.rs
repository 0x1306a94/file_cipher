use byte_struct::*;

use openssl::symm::{Cipher as AesCipher, Crypter, Mode};

use std::io::{Read, Write};

use crate::cipher::Cipher;
use crate::header;
use crate::utils;
use crate::version;

use micro_uecc_safe;

const BUFFER_SIZE: usize = 4096;

pub struct AesECCCipher {
    key: String,
}

impl AesECCCipher {
    pub fn new(key: &str) -> Self {
        AesECCCipher {
            key: key.to_string(),
        }
    }
}

impl Cipher for AesECCCipher {
    fn encrypt<R, W>(&self, src: &mut R, dst: &mut W) -> anyhow::Result<()>
    where
        R: Read,
        W: Write,
    {
        if self.key.len() != header::ECC_PUBLIC_KEY_LEN * 2 {
            return Err(anyhow::anyhow!("illegal public key"));
        }
        let key_pair = micro_uecc_safe::uecc_mkae_key_with_secp256k1()?;

        let mut secret_key_buf = [0u8; 32];
        let mut server_public_key = utils::decode_hex(&self.key)?;
        let mut client_private_key = utils::decode_hex(&key_pair.private_key)?;

        micro_uecc_safe::ucc_shared_secret_whith_secp256k1(
            &mut server_public_key,
            &mut client_private_key,
            &mut secret_key_buf,
        )?;

        let iv = utils::generate_random_iv();
        let secret_key = utils::encode_hex(&secret_key_buf);
        log::trace!("server_public_key: {}", self.key);
        log::trace!("client_public_key: {}", key_pair.public_key);
        log::trace!("client_private_key: {}", key_pair.private_key);
        log::trace!("secret_key: {}", secret_key);
        log::trace!("iv: {}", utils::encode_hex(&iv));

        let header = header::AesECCHeader::new(&key_pair.public_key, &iv);

        let mut header_bytes = [0u8; header::AesECCHeader::BYTE_LEN];
        header.write_bytes(&mut header_bytes);
        dst.write(&header_bytes)?;

        let cipher = AesCipher::aes_256_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Encrypt, &secret_key_buf, Some(&iv))?;
        crypter.pad(true);

        let block_size = cipher.block_size();
        log::trace!("block_size: {}", block_size);
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut output_buffer = vec![0u8; BUFFER_SIZE + block_size];
        let mut total_origin_len = 0;
        let mut total_encrypt_len = 0;
        loop {
            let bytes_read = src.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            total_origin_len += bytes_read;
            let result = crypter.update(&buffer[..bytes_read], &mut output_buffer[0..])?;
            total_encrypt_len += result;
            dst.write_all(&output_buffer[..result])?;
        }

        let result = crypter.finalize(&mut output_buffer[0..])?;
        total_encrypt_len += result;
        dst.write_all(&output_buffer[..result])?;
        log::trace!("total_origin_len: {}", total_origin_len);
        log::trace!("total_encrypt_len: {}", total_encrypt_len);

        dst.flush()?;

        Ok(())
    }

    fn decrypt<R, W>(&self, src: &mut R, dst: &mut W) -> anyhow::Result<()>
    where
        R: Read,
        W: Write,
    {
        if self.key.len() != header::ECC_PRIVATE_KEY_LEN * 2 {
            return Err(anyhow::anyhow!("illegal private key"));
        }

        let mut header_bytes = [0u8; header::AesECCHeader::BYTE_LEN];
        src.read_exact(&mut header_bytes)?;
        let header = header::AesECCHeader::try_from(&header_bytes[0..])?;
        let version =
            version::Version::try_from(header.format()).map_err(|err| anyhow::anyhow!(err))?;
        if version != version::Version::V2 {
            return anyhow::Result::Err(anyhow::anyhow!("Only v2 is supported"));
        }

        let mut secret_key_buf = [0u8; 32];
        let mut client_public_key = [0u8; header::ECC_PUBLIC_KEY_LEN];
        client_public_key.copy_from_slice(header.key_bytes());
        let mut server_private_key = utils::decode_hex(&self.key)?;

        micro_uecc_safe::ucc_shared_secret_whith_secp256k1(
            &mut client_public_key,
            &mut server_private_key,
            &mut secret_key_buf,
        )?;

        let iv_buf = header.iv_bytes();
        let secret_key = utils::encode_hex(&secret_key_buf);
        log::trace!("server_private_key: {}", self.key);
        log::trace!(
            "client_public_key: {}",
            utils::encode_hex(&client_public_key)
        );
        log::trace!("secret_key: {}", secret_key);
        log::trace!("iv: {}", utils::encode_hex(iv_buf));

        let cipher = AesCipher::aes_256_ecb();
        let mut crypter = Crypter::new(cipher, Mode::Decrypt, &secret_key_buf, Some(iv_buf))?;
        crypter.pad(true);

        let block_size = cipher.block_size();
        log::trace!("block_size: {}", block_size);
        let mut buffer = [0u8; BUFFER_SIZE];
        let mut output_buffer = vec![0u8; BUFFER_SIZE + block_size];
        let mut total_origin_len = 0;
        let mut total_decrypt_len = 0;
        loop {
            let bytes_read = src.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            total_origin_len += bytes_read;
            let result = crypter.update(&buffer[..bytes_read], &mut output_buffer[0..])?;
            total_decrypt_len += result;
            dst.write_all(&output_buffer[..result])?;
        }

        let result = crypter.finalize(&mut output_buffer[0..])?;
        total_decrypt_len += result;
        dst.write_all(&output_buffer[..result])?;
        log::trace!("total_origin_len: {}", total_origin_len);
        log::trace!("total_decrypt_len: {}", total_decrypt_len);
        dst.flush()?;

        Ok(())
    }
}
