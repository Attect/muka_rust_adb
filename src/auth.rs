use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rand::rngs::OsRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use signature::SignatureEncoding;
use signature::hazmat::PrehashSigner;

use crate::error::{AdbError, Result};

#[derive(Debug, Clone)]
pub struct AuthKey {
    private_key: RsaPrivateKey,
    public_key: Option<String>,
    path: PathBuf,
}

impl AuthKey {
    #[cfg(test)]
    pub(crate) fn from_private_key(private_key: RsaPrivateKey, public_key: Option<String>) -> Self {
        Self {
            private_key,
            public_key,
            path: PathBuf::from("adbkey"),
        }
    }

    pub fn load_all() -> Result<Vec<Self>> {
        let mut keys = Vec::new();
        keys.push(Self::load_default()?);
        keys.extend(load_vendor_keys());
        Ok(keys)
    }

    pub fn load_default() -> Result<Self> {
        let path = user_key_path()?;
        if !path.exists() {
            static KEYGEN_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let _guard = KEYGEN_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
            if !path.exists() {
                generate_user_key(&path)?;
            }
        }
        Self::load(path)
    }

    pub fn load(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let pem = fs::read_to_string(&path)?;
        let private_key = parse_private_key_pem(&pem).map_err(|err| {
            AdbError::Protocol(format!("无法解析 adb 私钥 {}: {err}", path.display()))
        })?;
        let public_key = fs::read_to_string(public_key_path(&path))
            .ok()
            .map(|value| value.trim_end_matches(['\r', '\n']).to_string())
            .filter(|value| !value.is_empty())
            .or_else(|| calculate_android_public_key(&private_key).ok());

        Ok(Self {
            private_key,
            public_key,
            path,
        })
    }

    pub fn sign_token(&self, token: &[u8]) -> Result<Vec<u8>> {
        if token.len() != 20 {
            return Err(AdbError::Protocol(format!(
                "AUTH TOKEN 长度应为 20 字节，实际为 {}",
                token.len()
            )));
        }

        let signing_key = SigningKey::<Sha1>::new(self.private_key.clone());
        let signature: Signature = signing_key
            .sign_prehash(token)
            .map_err(|err| AdbError::Protocol(format!("ADB TOKEN 签名失败: {err}")))?;
        Ok(signature.to_vec())
    }

    pub fn public_key_payload(&self) -> Option<Vec<u8>> {
        self.public_key.as_ref().map(|public_key| {
            let mut payload = public_key.as_bytes().to_vec();
            payload.push(0);
            payload
        })
    }

    pub(crate) fn public_key_text(&self) -> Result<String> {
        self.public_key
            .clone()
            .ok_or_else(|| AdbError::Protocol("无法生成 adb 公钥".to_string()))
    }

    pub(crate) fn private_key_pkcs8_der(&self) -> Result<Vec<u8>> {
        self.private_key
            .to_pkcs8_der()
            .map(|document| document.as_bytes().to_vec())
            .map_err(|err| AdbError::Protocol(format!("编码 adb 私钥失败: {err}")))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

pub fn generate_user_key(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let private_key = RsaPrivateKey::new(&mut OsRng, 2048)
        .map_err(|err| AdbError::Protocol(format!("生成 RSA2048 adbkey 失败: {err}")))?;
    let public_key = calculate_android_public_key(&private_key)?;
    let pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|err| AdbError::Protocol(format!("编码 adb 私钥失败: {err}")))?;

    write_private_key(path, pem.as_bytes())?;
    fs::write(public_key_path(path), public_key)?;
    Ok(())
}

pub fn public_key_from_private_key(path: &Path) -> Result<String> {
    let pem = fs::read_to_string(path)?;
    let private_key = parse_private_key_pem(&pem).map_err(|err| {
        AdbError::Protocol(format!("无法解析 adb 私钥 {}: {err}", path.display()))
    })?;
    calculate_android_public_key(&private_key)
}

fn load_vendor_keys() -> Vec<AuthKey> {
    let Some(paths) = std::env::var_os("ADB_VENDOR_KEYS") else {
        return Vec::new();
    };

    std::env::split_paths(&paths)
        .flat_map(|path| load_vendor_key_path(&path))
        .collect()
}

fn load_vendor_key_path(path: &Path) -> Vec<AuthKey> {
    if path.is_file() {
        return AuthKey::load(path).into_iter().collect();
    }
    if !path.is_dir() {
        return Vec::new();
    }

    let Ok(entries) = fs::read_dir(path) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".adb_key"))
        })
        .filter_map(|path| AuthKey::load(path).ok())
        .collect()
}

fn calculate_android_public_key(private_key: &RsaPrivateKey) -> Result<String> {
    let public_key = RsaPublicKey::from(private_key);
    let encoded = encode_android_public_key_binary(&public_key)?;
    Ok(format!(
        "{} {}",
        BASE64_STANDARD.encode(encoded),
        public_key_comment()
    ))
}

fn encode_android_public_key_binary(public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    const MODULUS_SIZE: usize = 2048 / 8;
    const MODULUS_WORDS: u32 = (MODULUS_SIZE / 4) as u32;

    let modulus = public_key.n();
    let exponent = bigint_to_u32(public_key.e())?;
    let mut modulus_le = fixed_le_bytes(modulus, MODULUS_SIZE)?;
    let n0 = u32::from_le_bytes(modulus_le[0..4].try_into().expect("slice has 4 bytes"));
    let n0inv = n0_inverse(n0)?;
    let r = BigUint::from(1_u32) << (MODULUS_SIZE * 8);
    let rr = (&r * &r) % modulus;
    let mut rr_le = fixed_le_bytes(&rr, MODULUS_SIZE)?;

    let mut out = Vec::with_capacity(3 * 4 + 2 * MODULUS_SIZE);
    out.extend_from_slice(&MODULUS_WORDS.to_le_bytes());
    out.extend_from_slice(&n0inv.to_le_bytes());
    out.append(&mut modulus_le);
    out.append(&mut rr_le);
    out.extend_from_slice(&exponent.to_le_bytes());
    Ok(out)
}

fn fixed_le_bytes(value: &BigUint, len: usize) -> Result<Vec<u8>> {
    let mut bytes = value.to_bytes_le();
    if bytes.len() > len {
        return Err(AdbError::Protocol(format!(
            "RSA modulus 超过 Android ADB 支持的 {len} 字节"
        )));
    }
    bytes.resize(len, 0);
    Ok(bytes)
}

fn bigint_to_u32(value: &BigUint) -> Result<u32> {
    let bytes = value.to_bytes_be();
    if bytes.len() > 4 {
        return Err(AdbError::Protocol("RSA exponent 超过 u32".to_string()));
    }
    let mut out = [0_u8; 4];
    out[4 - bytes.len()..].copy_from_slice(&bytes);
    Ok(u32::from_be_bytes(out))
}

fn n0_inverse(n0: u32) -> Result<u32> {
    if n0.is_multiple_of(2) {
        return Err(AdbError::Protocol("RSA modulus 不是奇数".to_string()));
    }

    let modulus = 1_i128 << 32;
    let inverse = mod_inverse(i128::from(n0), modulus)
        .ok_or_else(|| AdbError::Protocol("无法计算 RSA n0inv".to_string()))?;
    Ok(((modulus - inverse) % modulus) as u32)
}

fn mod_inverse(value: i128, modulus: i128) -> Option<i128> {
    let (mut t, mut new_t) = (0_i128, 1_i128);
    let (mut r, mut new_r) = (modulus, value.rem_euclid(modulus));
    while new_r != 0 {
        let quotient = r / new_r;
        (t, new_t) = (new_t, t - quotient * new_t);
        (r, new_r) = (new_r, r - quotient * new_r);
    }
    if r > 1 {
        return None;
    }
    Some(t.rem_euclid(modulus))
}

fn public_key_comment() -> String {
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".to_string());
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "host".to_string());
    format!("{user}@{host}")
}

fn write_private_key(path: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn parse_private_key_pem(pem: &str) -> std::result::Result<RsaPrivateKey, String> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .map_err(|err| err.to_string())
        .or_else(|pkcs8_err| {
            RsaPrivateKey::from_pkcs1_pem(pem)
                .map_err(|pkcs1_err| format!("PKCS#8: {pkcs8_err}; PKCS#1: {pkcs1_err}"))
        })
}

pub fn user_key_path() -> Result<PathBuf> {
    Ok(android_dir()?.join("adbkey"))
}

pub fn android_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("ANDROID_SDK_HOME") {
        return Ok(PathBuf::from(home).join(".android"));
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(home).join(".android"));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(".android"));
    }
    Err(AdbError::Server(
        "无法定位用户目录以读取 .android/adbkey".to_string(),
    ))
}

fn public_key_path(private_key_path: &Path) -> PathBuf {
    let mut path = private_key_path.as_os_str().to_os_string();
    path.push(".pub");
    PathBuf::from(path)
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use rand::rngs::OsRng;
    use rsa::pkcs8::EncodePrivateKey;

    use super::*;

    #[test]
    fn public_key_payload_is_nul_terminated() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let key = AuthKey::from_private_key(private_key, Some("abc user@host".to_string()));

        assert_eq!(key.public_key_payload().unwrap(), b"abc user@host\0");
    }

    #[test]
    fn signs_twenty_byte_token() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let key = AuthKey::from_private_key(private_key, None);

        let signature = key.sign_token(&[7_u8; 20]).unwrap();

        assert_eq!(signature.len(), 128);
    }

    #[test]
    fn android_public_key_binary_has_official_shape() {
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let encoded = encode_android_public_key_binary(&public_key).unwrap();

        assert_eq!(encoded.len(), 524);
        assert_eq!(u32::from_le_bytes(encoded[0..4].try_into().unwrap()), 64);
        assert_ne!(u32::from_le_bytes(encoded[4..8].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(encoded[520..524].try_into().unwrap()),
            65537
        );
    }

    #[test]
    fn generated_user_key_can_be_loaded() {
        let dir = unique_temp_dir("adb-rust-keygen");
        let key_path = dir.join("adbkey");

        generate_user_key(&key_path).unwrap();
        let key = AuthKey::load(&key_path).unwrap();
        let public_key = fs::read_to_string(public_key_path(&key_path)).unwrap();
        let base64 = public_key.split_whitespace().next().unwrap();
        let decoded = BASE64_STANDARD.decode(base64).unwrap();

        assert_eq!(key.path(), key_path);
        assert_eq!(decoded.len(), 524);
        assert!(key.public_key_payload().unwrap().ends_with(&[0]));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn public_key_from_private_key_matches_generated_pub_file() {
        let dir = unique_temp_dir("adb-rust-pubkey");
        let key_path = dir.join("adbkey");

        generate_user_key(&key_path).unwrap();
        let public_key = public_key_from_private_key(&key_path).unwrap();
        let saved_public_key = fs::read_to_string(public_key_path(&key_path)).unwrap();

        assert_eq!(public_key, saved_public_key);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn vendor_directory_loads_only_adb_key_files() {
        let dir = unique_temp_dir("adb-rust-vendor");
        let valid_path = dir.join("vendor.adb_key");
        let ignored_path = dir.join("ignored.txt");
        let private_key = RsaPrivateKey::new(&mut OsRng, 1024).unwrap();
        let pem = private_key.to_pkcs8_pem(LineEnding::LF).unwrap();
        fs::write(&valid_path, pem.as_bytes()).unwrap();
        fs::write(&ignored_path, pem.as_bytes()).unwrap();

        let keys = load_vendor_key_path(&dir);

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].path(), valid_path);

        let _ = fs::remove_dir_all(dir);
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
