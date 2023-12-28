use micro_uecc_sys;

use anyhow::anyhow;

pub struct UEcckeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn uecc_mkae_key_with_secp256k1() -> anyhow::Result<UEcckeyPair> {
    if micro_uecc_sys::uECC_SUPPORTS_secp256k1 != 1 {
        return Err(anyhow::anyhow!("secp256k1 is not supported"));
    }
    unsafe {
        let curve = micro_uecc_sys::uECC_secp256k1();
        let prlen = micro_uecc_sys::uECC_curve_private_key_size(curve) as usize;
        let plen = micro_uecc_sys::uECC_curve_public_key_size(curve) as usize;
        // println!("prlen: {} plen: {}", prlen, plen);
        let mut private_key_buf = vec![0; prlen];
        let mut public_key_buf = vec![0; plen];
        let ret =
            micro_uecc_sys::uECC_make_key(&mut public_key_buf[0], &mut private_key_buf[0], curve);
        if ret != 1 {
            return anyhow::Result::Err(anyhow::anyhow!(
                "Failed to generate a key pair. Procedure"
            ));
        }
        let private_key = private_key_buf
            .iter()
            .map(|v| format!("{:02x}", *v))
            .reduce(|cur, next| cur + &next)
            .ok_or_else(|| anyhow!("Failed to generate a key pair. Procedure"))?;

        let public_key = public_key_buf
            .iter()
            .map(|v| format!("{:02x}", *v))
            .reduce(|cur, next| cur + &next)
            .ok_or_else(|| anyhow!("Failed to generate a key pair. Procedure"))?;

        Ok(UEcckeyPair {
            private_key,
            public_key,
        })
    }
}

pub fn ucc_shared_secret_whith_secp256k1(
    pub_key_buf: &mut [u8],
    priv_key_buf: &mut [u8],
    secret_buf: &mut [u8],
) -> anyhow::Result<()> {
    if micro_uecc_sys::uECC_SUPPORTS_secp256k1 != 1 {
        return Err(anyhow::anyhow!("secp256k1 is not supported"));
    }
    unsafe {
        let curve = micro_uecc_sys::uECC_secp256k1();
        let ret = micro_uecc_sys::uECC_shared_secret(
            &mut pub_key_buf[0],
            &mut priv_key_buf[0],
            &mut secret_buf[0],
            curve,
        );
        if ret == 1 {
            Ok(())
        } else {
            Err(anyhow!("uECC_shared_secret fail"))
        }
    }
}

pub fn uecc_mkae_key_with_secp256r1() -> anyhow::Result<UEcckeyPair> {
    if micro_uecc_sys::uECC_SUPPORTS_secp256r1 != 1 {
        return Err(anyhow::anyhow!("secp256r1 is not supported"));
    }
    unsafe {
        let curve = micro_uecc_sys::uECC_secp256r1();
        let prlen = micro_uecc_sys::uECC_curve_private_key_size(curve) as usize;
        let plen = micro_uecc_sys::uECC_curve_public_key_size(curve) as usize;
        // println!("prlen: {} plen: {}", prlen, plen);
        let mut private_key_buf = vec![0; prlen];
        let mut public_key_buf = vec![0; plen];
        let ret =
            micro_uecc_sys::uECC_make_key(&mut public_key_buf[0], &mut private_key_buf[0], curve);
        if ret != 1 {
            return anyhow::Result::Err(anyhow::anyhow!(
                "Failed to generate a key pair. Procedure"
            ));
        }
        let private_key = private_key_buf
            .iter()
            .map(|v| format!("{:02x}", *v))
            .reduce(|cur, next| cur + &next)
            .ok_or_else(|| anyhow!("Failed to generate a key pair. Procedure"))?;

        let public_key = public_key_buf
            .iter()
            .map(|v| format!("{:02x}", *v))
            .reduce(|cur, next| cur + &next)
            .ok_or_else(|| anyhow!("Failed to generate a key pair. Procedure"))?;

        Ok(UEcckeyPair {
            private_key,
            public_key,
        })
    }
}

pub fn ucc_shared_secret_whith_secp256r1(
    pub_key_buf: &mut [u8],
    priv_key_buf: &mut [u8],
    secret_buf: &mut [u8],
) -> anyhow::Result<()> {
    if micro_uecc_sys::uECC_SUPPORTS_secp256r1 != 1 {
        return Err(anyhow::anyhow!("secp256r1 is not supported"));
    }
    unsafe {
        let curve = micro_uecc_sys::uECC_secp256r1();
        let ret = micro_uecc_sys::uECC_shared_secret(
            &mut pub_key_buf[0],
            &mut priv_key_buf[0],
            &mut secret_buf[0],
            curve,
        );
        if ret == 1 {
            Ok(())
        } else {
            Err(anyhow!("uECC_shared_secret fail"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gen_secp256k1_key_pair() {
        match uecc_mkae_key_with_secp256k1() {
            Err(ref err) => println!("{:?}", err),
            Ok(pair) => {
                println!("private_key: {}", pair.private_key);
                println!("public_key: {}", pair.public_key);
            }
        };
    }

    #[test]
    fn gen_secp256r1_key_pair() {
        match uecc_mkae_key_with_secp256r1() {
            Err(ref err) => println!("{:?}", err),
            Ok(pair) => {
                println!("private_key: {}", pair.private_key);
                println!("public_key: {}", pair.public_key);
            }
        };
    }
}
