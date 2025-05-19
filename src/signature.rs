/// @Name signer
///
/// @Date 2025/5/6 下午4:47
///
/// @Author Matrix.Ye
///
/// @Description:
///
use anyhow::{anyhow, Context, Result};
use base58::{FromBase58, ToBase58};
use hmac::Hmac;
use ripemd::Ripemd160;
use secp256k1::{rand, Message, PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256, Sha512};


type HmacSha512 = Hmac<Sha512>;

const VERSION_BYTE: u8 = 0x00;

#[derive(Debug)]
pub struct Signer {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Signer {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Signer { secret_key, public_key }
    }

    pub fn create_by_wif(wif: &str) -> Result<Self> {
        // WIF格式解码
        // let decoded = wif.from_base58().context("Base58解码失败")?;
        let decoded = wif.from_base58().map_err(|e| anyhow!("Base58解码失败: {:?}", e))?;  // 手动转换错误
        // let decoded = wif.from_base58().map_err(|e| anyhow!("Base58解码错误{:?}",e))?;  // 手动转换错误


        // 验证校验
        let (data, checksum) = decoded.split_at(decoded.len() - 4);
        let hash = Sha256::digest(&Sha256::digest(data));

        if &hash[..4] != checksum {
            return Err(anyhow!("校验码不匹配"));
        }

        // 提取私钥（跳过版本字节）
        let secret_key_bytes = &data[1..33].try_into().context("私钥长度必需为32字节")?;

        let secret_key = SecretKey::from_byte_array(&secret_key_bytes).context("无效的私钥格式")?;


        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        Ok(Signer {
            secret_key,
            public_key,
        })
    }
    /// 导出私钥为WIF格式字符串（Base58Check编码）
    pub fn to_private_key(&self) -> Result<String> {
        // 添加版本字节（主网私钥为0x80）
        let mut data = vec![0x80u8];
        data.extend_from_slice(&self.secret_key.secret_bytes());

        // 添加压缩标志
        data.push(0x01);

        // 计算双重SHA256校验
        let checksum = Sha256::digest(&Sha256::digest(&data));
        data.extend_from_slice(&checksum[..4]);

        // Base58编码
        Ok(data.to_base58())
    }

    pub fn to_address(&self) -> Result<String> {
        // 压缩公钥生成（
        let pub_key = self.public_key.serialize();

        // SHA-256 + RIPEMD-160
        let sha_hash = Sha256::digest(&pub_key);
        let mut ripemd = Ripemd160::new();
        ripemd.update(sha_hash);
        let hash160 = ripemd.finalize();

        // 构建地址载荷（
        let mut payload = vec![VERSION_BYTE];
        payload.extend_from_slice(&hash160);

        // 双重SHA-256校验和
        let checksum = Sha256::digest(&Sha256::digest(&payload));
        payload.extend_from_slice(&checksum[..4]);

        Ok(payload.to_base58())
    }
    /// 对消息进行ECDSA签名（SHA256哈希预处理）
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        let secp = Secp256k1::new();
        let message_hash = Sha256::digest(message);
        let signature = secp.sign_ecdsa(
            &Message::from_digest_slice(&message_hash)?, &self.secret_key);
        Ok(signature.serialize_compact())
    }

    /// 验证ECDSA签名有效性
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let secp = Secp256k1::new();
        let message_hash = Sha256::digest(message);
        let sig = secp256k1::ecdsa::Signature::from_compact(signature)?;

        Ok(secp.verify_ecdsa(
            &Message::from_digest_slice(&message_hash)?,
            &sig,
            &self.public_key,
        ).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_wif_export() {
        // 已知私钥测试用例
        let signer = Signer::create_by_wif("KyohL2RAhP3uoPpJujgqSv1uQYR6Cx9ooxCJvnxQ3P524D6XTsSm").unwrap();
        assert_eq!(signer.to_private_key().unwrap(), "KyohL2RAhP3uoPpJujgqSv1uQYR6Cx9ooxCJvnxQ3P524D6XTsSm");
    }

    #[test]
    fn test_new_key_validity() {
        let signer = Signer::new();
        let wif = signer.to_private_key().unwrap();
        // KyohL2RAhP3uoPpJujgqSv1uQYR6Cx9ooxCJvnxQ3P524D6XTsSm
        // 验证格式特征
        assert!(wif.starts_with('L') || wif.starts_with('K'));
        assert_eq!(wif.len(), 52);
    }
    #[test]
    fn test_address_generation() {
        let wif = "KyohL2RAhP3uoPpJujgqSv1uQYR6Cx9ooxCJvnxQ3P524D6XTsSm";
        let signer = Signer::create_by_wif(wif).unwrap();
        let address = signer.to_address().unwrap();
        assert_eq!(address, "1EmJB4MeFgPU1wME7zvX12X5SaTkYcttEt");
    }

    #[test]
    fn test_invalid_wif() {
        // 测试错误WIF格式
        let invalid_wif = "11111KyohL2RAhP3uoPpJujgqSv1uQYR6Cx9ooxCJvnxQ3P524D6XTsSm";
        assert!(Signer::create_by_wif(invalid_wif).is_err());
    }

    #[test]
    fn test_new_address_valid() {
        // 验证新生成地址的格式
        let signer = Signer::new();
        let address = signer.to_address().unwrap();

        // 验证Base58编码特征
        assert!(address.starts_with('1'));
    }

    #[test]
    fn test_signature_flow() -> Result<()> {
        let signer = Signer::new();
        let message = b"this is tx data";

        // 正常签名验证
        let sig = signer.sign(message)?;
        assert!(signer.verify(message, &sig)?);

        // 篡改数据验证失败
        let mut tampered = message.to_vec();
        tampered[0] ^= 0xFF;  // 修改首字节
        assert!(!signer.verify(&tampered, &sig)?);

        // 错误签名验证失败
        let mut bad_sig = sig;
        bad_sig[10] = bad_sig[10].wrapping_add(1);
        assert!(!signer.verify(message, &bad_sig)?);

        Ok(())
    }
}