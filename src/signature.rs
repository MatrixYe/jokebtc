/// @Name signer
///
/// @Date 2025/5/6 下午4:47
///
/// @Author Matrix.Ye
///
/// @Description:

use secp256k1::{rand, Secp256k1, SecretKey};


// 签名对象
pub struct Signer {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

//
impl Signer {
    pub fn new() -> Self {
        let sep = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = secret_key.public_key(&sep);
        Signer{
            private_key: PrivateKey(secret_key),
            public_key: PublicKey(vec![]),
        }
    }
}

pub struct PrivateKey(SecretKey);
pub struct PublicKey(Vec<u8>);