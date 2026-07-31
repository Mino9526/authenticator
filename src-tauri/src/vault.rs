#![allow(unexpected_cfgs)]

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use percent_encoding::percent_decode_str;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, Sqlite, SqlitePool, Transaction,
};
#[cfg(not(vault_standalone))]
use std::{error::Error, fs};
#[cfg(not(vault_standalone))]
use tauri::{Manager, State};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const DATABASE_FILENAME: &str = "authenticator.sqlite";
const VAULT_FORMAT_VERSION: i64 = 1;
const BACKUP_FORMAT: &str = "totp-authenticator-backup";
const BACKUP_VERSION: u32 = 1;
const BACKUP_PAYLOAD_VERSION: u32 = 1;
const KDF_ALGORITHM: &str = "argon2id";
const CIPHER_ALGORITHM: &str = "xchacha20poly1305";
#[cfg(not(test))]
const KDF_MEMORY_KIB: u32 = 65_536;
#[cfg(test)]
const KDF_MEMORY_KIB: u32 = 8_192;
#[cfg(not(test))]
const KDF_ITERATIONS: u32 = 3;
#[cfg(test)]
const KDF_ITERATIONS: u32 = 1;
const KDF_PARALLELISM: u32 = 1;
const MIN_KDF_MEMORY_KIB: u32 = 8_192;
const MAX_KDF_MEMORY_KIB: u32 = 262_144;
const MAX_KDF_ITERATIONS: u32 = 10;
const MAX_KDF_PARALLELISM: u32 = 8;
const AUTO_LOCK_SECONDS: u64 = 300;
const MIN_PASSWORD_CHARS: usize = 8;
const MAX_PASSWORD_BYTES: usize = 1_024;
const MAX_BACKUP_BYTES: usize = 10 * 1024 * 1024;
const MAX_BACKUP_ENTRIES: usize = 10_000;
const ENTRY_KEY_INFO: &[u8] = b"totp-authenticator/entry-encryption/v1";
const FINGERPRINT_KEY_INFO: &[u8] = b"totp-authenticator/entry-fingerprint/v1";
const VAULT_KEY_AAD: &[u8] = b"totp-authenticator/vault-key/v1";
const LOCKED_ERROR: &str = "VAULT_LOCKED: 保险库已锁定。";

type CommandResult<T> = Result<T, String>;

pub struct VaultService {
    pool: SqlitePool,
    session: Mutex<VaultSession>,
}

#[derive(Default)]
struct VaultSession {
    key: Option<Zeroizing<[u8; 32]>>,
    last_activity: Option<Instant>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    initialized: bool,
    unlocked: bool,
    legacy_entry_count: u64,
    auto_lock_seconds: u64,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicEntry {
    id: String,
    label: String,
    account: String,
    issuer: String,
    algorithm: String,
    digits: u32,
    period: u32,
    notes: String,
    website: String,
    created_at: i64,
    updated_at: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryInput {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    label: String,
    #[serde(default)]
    account: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default = "default_algorithm")]
    algorithm: String,
    #[serde(default = "default_digits")]
    digits: u32,
    #[serde(default = "default_period")]
    period: u32,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    website: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    id: String,
    code: Option<String>,
    remaining: u32,
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    added: usize,
    replaced: usize,
    total: usize,
    encrypted: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct FullEntry {
    id: String,
    label: String,
    account: String,
    issuer: String,
    secret: String,
    algorithm: String,
    digits: u32,
    period: u32,
    notes: String,
    website: String,
    created_at: i64,
    updated_at: i64,
}

impl Drop for FullEntry {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct LegacyEntry {
    #[serde(default)]
    id: String,
    #[serde(default)]
    label: String,
    #[serde(default)]
    account: String,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    secret: String,
    #[serde(default = "default_algorithm")]
    algorithm: String,
    #[serde(default = "default_digits")]
    digits: u32,
    #[serde(default = "default_period")]
    period: u32,
    #[serde(default)]
    notes: String,
    #[serde(default)]
    website: String,
    #[serde(default)]
    created_at: i64,
    #[serde(default)]
    updated_at: i64,
}

#[derive(Deserialize)]
struct LegacySnapshot {
    entries: Vec<LegacyEntry>,
}

struct EncryptedEntry {
    id: String,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    fingerprint: Vec<u8>,
    created_at: i64,
    updated_at: i64,
}

struct KeyMetadata {
    format_version: i64,
    kdf_algorithm: String,
    cipher_algorithm: String,
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    kdf_parallelism: u32,
    salt: Vec<u8>,
    wrap_nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KdfDescriptor {
    name: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct CipherDescriptor {
    name: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EncryptedBackup {
    format: String,
    version: u32,
    created_at: i64,
    app_version: String,
    kdf: KdfDescriptor,
    cipher: CipherDescriptor,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BackupPayload {
    version: u32,
    entries: Vec<FullEntry>,
}

fn default_algorithm() -> String {
    "SHA1".to_string()
}

fn default_digits() -> u32 {
    6
}

fn default_period() -> u32 {
    30
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn database_error(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}：{error}")
}

impl VaultService {
    #[cfg(not(vault_standalone))]
    pub async fn open(app: &tauri::AppHandle) -> Result<Self, Box<dyn Error>> {
        let config_dir = app.path().app_config_dir()?;
        fs::create_dir_all(&config_dir)?;
        let options = SqliteConnectOptions::new()
            .filename(config_dir.join(DATABASE_FILENAME))
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;

        sqlx::query("PRAGMA secure_delete = ON")
            .execute(&pool)
            .await?;
        sqlx::query(
            "
      CREATE TABLE IF NOT EXISTS vault_metadata (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        format_version INTEGER NOT NULL,
        kdf_algorithm TEXT NOT NULL,
        cipher_algorithm TEXT NOT NULL,
        kdf_memory_kib INTEGER NOT NULL,
        kdf_iterations INTEGER NOT NULL,
        kdf_parallelism INTEGER NOT NULL,
        salt BLOB NOT NULL,
        wrap_nonce BLOB NOT NULL,
        wrapped_dek BLOB NOT NULL,
        created_at INTEGER NOT NULL
      )
      ",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
            "
      CREATE TABLE IF NOT EXISTS vault_entries (
        id TEXT PRIMARY KEY,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL,
        fingerprint BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
      ",
        )
        .execute(&pool)
        .await?;
        sqlx::query(
      "CREATE INDEX IF NOT EXISTS idx_vault_entries_fingerprint ON vault_entries(fingerprint)",
    )
    .execute(&pool)
    .await?;

        Ok(Self {
            pool,
            session: Mutex::new(VaultSession::default()),
        })
    }

    async fn status(&self) -> CommandResult<VaultStatus> {
        let initialized = self.key_metadata().await?.is_some();
        let legacy_entry_count = self.legacy_entry_count().await?;
        let unlocked = self.session_is_unlocked()?;

        Ok(VaultStatus {
            initialized,
            unlocked,
            legacy_entry_count,
            auto_lock_seconds: AUTO_LOCK_SECONDS,
        })
    }

    async fn initialize(&self, password: &str) -> CommandResult<VaultStatus> {
        validate_new_password(password)?;
        if self.key_metadata().await?.is_some() {
            return Err("保险库已经初始化。".to_string());
        }

        let mut dek_bytes = [0_u8; 32];
        let mut salt = vec![0_u8; 16];
        OsRng.fill_bytes(&mut dek_bytes);
        OsRng.fill_bytes(&mut salt);
        let dek = Zeroizing::new(dek_bytes);
        let kdf = KdfDescriptor {
            name: KDF_ALGORITHM.to_string(),
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt: BASE64.encode(&salt),
        };
        let kek = derive_password_key(password, &salt, &kdf)?;
        let (wrap_nonce, wrapped_dek) = encrypt_bytes(&kek, &dek[..], VAULT_KEY_AAD)?;

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_error("无法初始化保险库", error))?;

        sqlx::query(
            "
      INSERT INTO vault_metadata (
        singleton, format_version, kdf_algorithm, cipher_algorithm,
        kdf_memory_kib, kdf_iterations, kdf_parallelism,
        salt, wrap_nonce, wrapped_dek, created_at
      ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ",
        )
        .bind(VAULT_FORMAT_VERSION)
        .bind(KDF_ALGORITHM)
        .bind(CIPHER_ALGORITHM)
        .bind(i64::from(KDF_MEMORY_KIB))
        .bind(i64::from(KDF_ITERATIONS))
        .bind(i64::from(KDF_PARALLELISM))
        .bind(&salt)
        .bind(&wrap_nonce)
        .bind(&wrapped_dek)
        .bind(now_millis())
        .execute(&mut *transaction)
        .await
        .map_err(|error| database_error("无法保存保险库配置", error))?;

        self.migrate_legacy_entries(&mut transaction, &dek).await?;
        transaction
            .commit()
            .await
            .map_err(|error| database_error("无法提交保险库初始化", error))?;
        self.cleanup_legacy_pages().await;
        self.set_session_key(dek)?;
        self.status().await
    }

    async fn unlock(&self, password: &str) -> CommandResult<VaultStatus> {
        if password.is_empty() {
            return Err("请输入主密码。".to_string());
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err("主密码过长。".to_string());
        }

        let metadata = self
            .key_metadata()
            .await?
            .ok_or_else(|| "保险库尚未初始化。".to_string())?;
        validate_key_metadata(&metadata)?;
        let kdf = KdfDescriptor {
            name: metadata.kdf_algorithm.clone(),
            memory_kib: metadata.kdf_memory_kib,
            iterations: metadata.kdf_iterations,
            parallelism: metadata.kdf_parallelism,
            salt: BASE64.encode(&metadata.salt),
        };
        let kek = derive_password_key(password, &metadata.salt, &kdf)?;
        let plaintext = decrypt_bytes(
            &kek,
            &metadata.wrap_nonce,
            &metadata.wrapped_dek,
            VAULT_KEY_AAD,
        )
        .map_err(|_| "主密码错误或保险库已损坏。".to_string())?;
        if plaintext.len() != 32 {
            return Err("保险库密钥格式无效。".to_string());
        }
        let mut dek_bytes = [0_u8; 32];
        dek_bytes.copy_from_slice(&plaintext);
        let dek = Zeroizing::new(dek_bytes);

        if self.legacy_table_exists().await? {
            let mut transaction = self
                .pool
                .begin()
                .await
                .map_err(|error| database_error("无法开始旧数据迁移", error))?;
            self.migrate_legacy_entries(&mut transaction, &dek).await?;
            transaction
                .commit()
                .await
                .map_err(|error| database_error("无法提交旧数据迁移", error))?;
            self.cleanup_legacy_pages().await;
        }

        self.set_session_key(dek)?;
        self.status().await
    }

    async fn change_password(
        &self,
        current_password: &str,
        new_password: &str,
    ) -> CommandResult<VaultStatus> {
        validate_new_password(new_password)?;
        let session_key = self.current_key()?;
        let metadata = self
            .key_metadata()
            .await?
            .ok_or_else(|| "保险库尚未初始化。".to_string())?;
        validate_key_metadata(&metadata)?;
        let current_kdf = KdfDescriptor {
            name: metadata.kdf_algorithm,
            memory_kib: metadata.kdf_memory_kib,
            iterations: metadata.kdf_iterations,
            parallelism: metadata.kdf_parallelism,
            salt: BASE64.encode(&metadata.salt),
        };
        let current_kek = derive_password_key(current_password, &metadata.salt, &current_kdf)?;
        let unwrapped_key = decrypt_bytes(
            &current_kek,
            &metadata.wrap_nonce,
            &metadata.wrapped_dek,
            VAULT_KEY_AAD,
        )
        .map_err(|_| "当前主密码错误。".to_string())?;
        if unwrapped_key.as_slice() != &session_key[..] {
            return Err("当前主密码错误或保险库密钥不一致。".to_string());
        }

        let mut salt = vec![0_u8; 16];
        OsRng.fill_bytes(&mut salt);
        let new_kdf = KdfDescriptor {
            name: KDF_ALGORITHM.to_string(),
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt: BASE64.encode(&salt),
        };
        let new_kek = derive_password_key(new_password, &salt, &new_kdf)?;
        let (wrap_nonce, wrapped_dek) = encrypt_bytes(&new_kek, &session_key[..], VAULT_KEY_AAD)?;
        sqlx::query(
            "
      UPDATE vault_metadata
      SET kdf_algorithm = ?, cipher_algorithm = ?,
          kdf_memory_kib = ?, kdf_iterations = ?, kdf_parallelism = ?,
          salt = ?, wrap_nonce = ?, wrapped_dek = ?
      WHERE singleton = 1
      ",
        )
        .bind(KDF_ALGORITHM)
        .bind(CIPHER_ALGORITHM)
        .bind(i64::from(KDF_MEMORY_KIB))
        .bind(i64::from(KDF_ITERATIONS))
        .bind(i64::from(KDF_PARALLELISM))
        .bind(&salt)
        .bind(&wrap_nonce)
        .bind(&wrapped_dek)
        .execute(&self.pool)
        .await
        .map_err(|error| database_error("无法更新主密码", error))?;
        self.touch()?;
        self.status().await
    }

    fn lock(&self) -> CommandResult<()> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "保险库状态不可用。".to_string())?;
        session.key.take();
        session.last_activity = None;
        Ok(())
    }

    fn touch(&self) -> CommandResult<bool> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "保险库状态不可用。".to_string())?;
        expire_session_if_needed(&mut session);
        if session.key.is_none() {
            return Ok(false);
        }
        session.last_activity = Some(Instant::now());
        Ok(true)
    }

    fn set_session_key(&self, key: Zeroizing<[u8; 32]>) -> CommandResult<()> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "保险库状态不可用。".to_string())?;
        session.key = Some(key);
        session.last_activity = Some(Instant::now());
        Ok(())
    }

    fn session_is_unlocked(&self) -> CommandResult<bool> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "保险库状态不可用。".to_string())?;
        expire_session_if_needed(&mut session);
        Ok(session.key.is_some())
    }

    fn current_key(&self) -> CommandResult<Zeroizing<[u8; 32]>> {
        let mut session = self
            .session
            .lock()
            .map_err(|_| "保险库状态不可用。".to_string())?;
        expire_session_if_needed(&mut session);
        let key = session
            .key
            .as_ref()
            .ok_or_else(|| LOCKED_ERROR.to_string())?;
        Ok(Zeroizing::new(**key))
    }

    async fn key_metadata(&self) -> CommandResult<Option<KeyMetadata>> {
        let row = sqlx::query(
            "
      SELECT format_version, kdf_algorithm, cipher_algorithm,
             kdf_memory_kib, kdf_iterations, kdf_parallelism,
             salt, wrap_nonce, wrapped_dek
      FROM vault_metadata
      WHERE singleton = 1
      ",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_error("无法读取保险库配置", error))?;

        row.map(|row| {
            Ok(KeyMetadata {
                format_version: row.try_get("format_version")?,
                kdf_algorithm: row.try_get("kdf_algorithm")?,
                cipher_algorithm: row.try_get("cipher_algorithm")?,
                kdf_memory_kib: read_u32_column(&row, "kdf_memory_kib")?,
                kdf_iterations: read_u32_column(&row, "kdf_iterations")?,
                kdf_parallelism: read_u32_column(&row, "kdf_parallelism")?,
                salt: row.try_get("salt")?,
                wrap_nonce: row.try_get("wrap_nonce")?,
                wrapped_dek: row.try_get("wrapped_dek")?,
            })
        })
        .transpose()
        .map_err(|error: sqlx::Error| database_error("保险库配置格式无效", error))
    }

    async fn legacy_table_exists(&self) -> CommandResult<bool> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'entries'",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|error| database_error("无法检查旧版数据库", error))?;
        Ok(count > 0)
    }

    async fn legacy_entry_count(&self) -> CommandResult<u64> {
        if !self.legacy_table_exists().await? {
            return Ok(0);
        }
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM entries")
            .fetch_one(&self.pool)
            .await
            .map_err(|error| database_error("无法统计旧版条目", error))?;
        Ok(count.max(0) as u64)
    }

    async fn migrate_legacy_entries(
        &self,
        transaction: &mut Transaction<'_, Sqlite>,
        dek: &[u8; 32],
    ) -> CommandResult<usize> {
        let table_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'entries'",
        )
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| database_error("无法检查旧版数据库", error))?;
        if table_count == 0 {
            return Ok(0);
        }

        let rows = sqlx::query(
            "
      SELECT id, label, account, issuer, secret, algorithm, digits, period,
             notes, website, createdAt, updatedAt
      FROM entries
      ORDER BY createdAt ASC
      ",
        )
        .fetch_all(&mut **transaction)
        .await
        .map_err(|error| database_error("无法读取旧版明文条目", error))?;

        let migrated_count = rows.len();
        for row in rows {
            let entry = FullEntry {
                id: row
                    .try_get("id")
                    .map_err(|error| database_error("旧版条目 ID 无效", error))?,
                label: row
                    .try_get("label")
                    .map_err(|error| database_error("旧版条目名称无效", error))?,
                account: row
                    .try_get("account")
                    .map_err(|error| database_error("旧版条目账号无效", error))?,
                issuer: row
                    .try_get("issuer")
                    .map_err(|error| database_error("旧版条目发行方无效", error))?,
                secret: row
                    .try_get("secret")
                    .map_err(|error| database_error("旧版条目密钥无效", error))?,
                algorithm: row
                    .try_get("algorithm")
                    .map_err(|error| database_error("旧版条目算法无效", error))?,
                digits: read_u32_column(&row, "digits")
                    .map_err(|error| database_error("旧版条目位数无效", error))?,
                period: read_u32_column(&row, "period")
                    .map_err(|error| database_error("旧版条目周期无效", error))?,
                notes: row
                    .try_get("notes")
                    .map_err(|error| database_error("旧版条目备注无效", error))?,
                website: row
                    .try_get("website")
                    .map_err(|error| database_error("旧版条目网址无效", error))?,
                created_at: row
                    .try_get("createdAt")
                    .map_err(|error| database_error("旧版条目创建时间无效", error))?,
                updated_at: row
                    .try_get("updatedAt")
                    .map_err(|error| database_error("旧版条目更新时间无效", error))?,
            };
            let entry = normalize_full_entry(entry)?;
            let encrypted = encrypt_entry(dek, &entry)?;
            decrypt_entry(dek, &encrypted)?;
            insert_encrypted_entry(&mut **transaction, &encrypted).await?;
        }

        sqlx::query(
            "
      UPDATE entries
      SET label = '', account = '', issuer = '', secret = '', algorithm = '',
          notes = '', website = ''
      ",
        )
        .execute(&mut **transaction)
        .await
        .map_err(|error| database_error("无法清理旧版明文条目", error))?;
        sqlx::query("DROP TABLE entries")
            .execute(&mut **transaction)
            .await
            .map_err(|error| database_error("无法移除旧版明文表", error))?;

        Ok(migrated_count)
    }

    async fn cleanup_legacy_pages(&self) {
        let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await;
        let _ = sqlx::query("VACUUM").execute(&self.pool).await;
    }

    async fn full_entries(&self, key: &[u8; 32]) -> CommandResult<Vec<FullEntry>> {
        let rows = sqlx::query(
            "
      SELECT id, nonce, ciphertext, fingerprint, created_at, updated_at
      FROM vault_entries
      ORDER BY created_at ASC
      ",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| database_error("无法读取加密条目", error))?;

        rows.into_iter()
            .map(|row| encrypted_entry_from_row(&row).and_then(|entry| decrypt_entry(key, &entry)))
            .collect()
    }

    async fn public_entries(&self) -> CommandResult<Vec<PublicEntry>> {
        let key = self.current_key()?;
        let mut entries: Vec<PublicEntry> = self
            .full_entries(&key)
            .await?
            .iter()
            .map(PublicEntry::from)
            .collect();
        entries.sort_by(|left, right| {
            left.issuer
                .is_empty()
                .cmp(&right.issuer.is_empty())
                .then_with(|| left.issuer.to_lowercase().cmp(&right.issuer.to_lowercase()))
                .then_with(|| left.label.to_lowercase().cmp(&right.label.to_lowercase()))
                .then_with(|| left.created_at.cmp(&right.created_at))
        });
        Ok(entries)
    }

    async fn save_entry(&self, input: EntryInput) -> CommandResult<PublicEntry> {
        let key = self.current_key()?;
        let requested_id = input
            .id
            .as_deref()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(str::to_string);
        let existing = match requested_id.as_deref() {
            Some(id) => Some(self.entry_by_id(&key, id).await?),
            None => None,
        };
        if existing.is_some()
            && input
                .secret
                .as_deref()
                .is_some_and(|secret| !secret.trim().is_empty())
        {
            return Err("编辑条目时不能直接更换密钥。".to_string());
        }

        let entry = build_entry(input, existing.as_ref())?;
        let encrypted = encrypt_entry(&key, &entry)?;
        let duplicate_id: Option<String> = sqlx::query_scalar(
            "SELECT id FROM vault_entries WHERE fingerprint = ? AND id <> ? LIMIT 1",
        )
        .bind(&encrypted.fingerprint)
        .bind(&encrypted.id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_error("无法检查重复密钥", error))?;
        if duplicate_id.is_some() {
            return Err("该密钥已存在，不能重复新增。".to_string());
        }

        insert_encrypted_entry(&self.pool, &encrypted).await?;
        Ok(PublicEntry::from(&entry))
    }

    async fn entry_by_id(&self, key: &[u8; 32], id: &str) -> CommandResult<FullEntry> {
        let row = sqlx::query(
            "
      SELECT id, nonce, ciphertext, fingerprint, created_at, updated_at
      FROM vault_entries
      WHERE id = ?
      ",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| database_error("无法读取条目", error))?
        .ok_or_else(|| "找不到要编辑的条目。".to_string())?;
        let encrypted = encrypted_entry_from_row(&row)?;
        decrypt_entry(key, &encrypted)
    }

    async fn remove_entry(&self, id: &str) -> CommandResult<()> {
        let _key = self.current_key()?;
        let result = sqlx::query("DELETE FROM vault_entries WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|error| database_error("无法删除条目", error))?;
        if result.rows_affected() == 0 {
            return Err("找不到要删除的条目。".to_string());
        }
        Ok(())
    }

    async fn codes(&self) -> CommandResult<Vec<TotpCode>> {
        let key = self.current_key()?;
        let rows = sqlx::query(
            "
      SELECT id, nonce, ciphertext, fingerprint, created_at, updated_at
      FROM vault_entries
      ORDER BY created_at ASC
      ",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|error| database_error("无法读取验证码条目", error))?;
        let timestamp = now_seconds();

        Ok(rows
            .into_iter()
            .map(|row| {
                match encrypted_entry_from_row(&row).and_then(|stored| {
                    let id = stored.id.clone();
                    let entry = decrypt_entry(&key, &stored)?;
                    let remaining = entry.period - (timestamp % u64::from(entry.period)) as u32;
                    let code = generate_totp(&entry, timestamp)?;
                    Ok(TotpCode {
                        id,
                        code: Some(code),
                        remaining,
                        error: None,
                    })
                }) {
                    Ok(code) => code,
                    Err(error) => {
                        let id = row
                            .try_get::<String, _>("id")
                            .unwrap_or_else(|_| "unknown".to_string());
                        TotpCode {
                            id,
                            code: None,
                            remaining: 0,
                            error: Some(error),
                        }
                    }
                }
            })
            .collect())
    }

    async fn export_backup(&self, password: &str) -> CommandResult<String> {
        validate_new_password(password)?;
        let key = self.current_key()?;
        let entries = self.full_entries(&key).await?;
        create_encrypted_backup(entries, password)
    }

    async fn import_backup_text(
        &self,
        backup_text: &str,
        password: Option<&str>,
    ) -> CommandResult<ImportResult> {
        if backup_text.is_empty() {
            return Err("导入文件为空。".to_string());
        }
        if backup_text.len() > MAX_BACKUP_BYTES {
            return Err("备份文件过大。".to_string());
        }

        let trimmed = backup_text.trim();
        let trimmed = trimmed
            .strip_prefix('\u{feff}')
            .unwrap_or(trimmed)
            .trim_start();
        let (entries, encrypted) = if is_encrypted_backup(trimmed)? {
            let password =
                password.ok_or_else(|| "BACKUP_PASSWORD_REQUIRED: 请输入备份密码。".to_string())?;
            (decrypt_backup(trimmed, password)?, true)
        } else {
            (parse_legacy_backup(trimmed)?, false)
        };
        if entries.len() > MAX_BACKUP_ENTRIES {
            return Err("备份中的条目数量超过限制。".to_string());
        }
        if entries.is_empty() {
            return Err("备份中没有可导入的条目。".to_string());
        }

        let key = self.current_key()?;
        self.merge_imported_entries(&key, entries, encrypted).await
    }

    async fn merge_imported_entries(
        &self,
        key: &[u8; 32],
        imported_entries: Vec<FullEntry>,
        encrypted: bool,
    ) -> CommandResult<ImportResult> {
        let mut entries = self.full_entries(key).await?;
        let mut fingerprints = HashMap::<Vec<u8>, usize>::new();
        let mut ids = HashSet::<String>::new();
        for (index, entry) in entries.iter().enumerate() {
            fingerprints
                .entry(secret_fingerprint(key, &entry.secret)?)
                .or_insert(index);
            ids.insert(entry.id.clone());
        }

        let mut added = 0;
        let mut replaced = 0;
        for imported in imported_entries {
            let mut imported = normalize_full_entry(imported)?;
            let fingerprint = secret_fingerprint(key, &imported.secret)?;
            if let Some(index) = fingerprints.get(&fingerprint).copied() {
                imported.id = entries[index].id.clone();
                imported.created_at = entries[index].created_at;
                imported.updated_at = now_millis();
                entries[index] = imported;
                replaced += 1;
                continue;
            }

            if imported.id.is_empty() || ids.contains(&imported.id) {
                imported.id = Uuid::new_v4().to_string();
            }
            imported.updated_at = now_millis();
            ids.insert(imported.id.clone());
            let index = entries.len();
            fingerprints.insert(fingerprint, index);
            entries.push(imported);
            added += 1;
        }

        let encrypted_rows: Vec<EncryptedEntry> = entries
            .iter()
            .map(|entry| encrypt_entry(key, entry))
            .collect::<CommandResult<_>>()?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| database_error("无法开始导入事务", error))?;
        sqlx::query("DELETE FROM vault_entries")
            .execute(&mut *transaction)
            .await
            .map_err(|error| database_error("无法更新保险库条目", error))?;
        for row in &encrypted_rows {
            insert_encrypted_entry(&mut *transaction, row).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| database_error("无法提交导入结果", error))?;

        Ok(ImportResult {
            added,
            replaced,
            total: entries.len(),
            encrypted,
        })
    }
}

impl From<&FullEntry> for PublicEntry {
    fn from(entry: &FullEntry) -> Self {
        Self {
            id: entry.id.clone(),
            label: entry.label.clone(),
            account: entry.account.clone(),
            issuer: entry.issuer.clone(),
            algorithm: entry.algorithm.clone(),
            digits: entry.digits,
            period: entry.period,
            notes: entry.notes.clone(),
            website: entry.website.clone(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}

fn expire_session_if_needed(session: &mut VaultSession) {
    let expired = session.last_activity.is_some_and(|last_activity| {
        last_activity.elapsed() >= Duration::from_secs(AUTO_LOCK_SECONDS)
    });
    if expired {
        session.key.take();
        session.last_activity = None;
    }
}

fn validate_new_password(password: &str) -> CommandResult<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!("主密码至少需要 {MIN_PASSWORD_CHARS} 个字符。"));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err("主密码过长。".to_string());
    }
    Ok(())
}

fn validate_kdf(kdf: &KdfDescriptor) -> CommandResult<()> {
    if kdf.name != KDF_ALGORITHM {
        return Err("不支持的密钥派生算法。".to_string());
    }
    if !(MIN_KDF_MEMORY_KIB..=MAX_KDF_MEMORY_KIB).contains(&kdf.memory_kib)
        || !(1..=MAX_KDF_ITERATIONS).contains(&kdf.iterations)
        || !(1..=MAX_KDF_PARALLELISM).contains(&kdf.parallelism)
    {
        return Err("密钥派生参数超出安全范围。".to_string());
    }
    Ok(())
}

fn validate_key_metadata(metadata: &KeyMetadata) -> CommandResult<()> {
    if metadata.format_version != VAULT_FORMAT_VERSION {
        return Err("不支持的保险库版本。".to_string());
    }
    if metadata.kdf_algorithm != KDF_ALGORITHM || metadata.cipher_algorithm != CIPHER_ALGORITHM {
        return Err("保险库使用了不支持的加密算法。".to_string());
    }
    validate_kdf(&KdfDescriptor {
        name: metadata.kdf_algorithm.clone(),
        memory_kib: metadata.kdf_memory_kib,
        iterations: metadata.kdf_iterations,
        parallelism: metadata.kdf_parallelism,
        salt: String::new(),
    })?;
    if !(16..=64).contains(&metadata.salt.len())
        || metadata.wrap_nonce.len() != 24
        || metadata.wrapped_dek.len() != 48
    {
        return Err("保险库密钥数据格式无效。".to_string());
    }
    Ok(())
}

fn derive_password_key(
    password: &str,
    salt: &[u8],
    kdf: &KdfDescriptor,
) -> CommandResult<Zeroizing<[u8; 32]>> {
    validate_kdf(kdf)?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| "无法配置密钥派生参数。".to_string())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut output[..])
        .map_err(|_| "无法派生加密密钥。".to_string())?;
    Ok(output)
}

fn derive_subkey(master_key: &[u8; 32], info: &[u8]) -> CommandResult<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(None, master_key);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(info, &mut output[..])
        .map_err(|_| "无法派生条目密钥。".to_string())?;
    Ok(output)
}

fn encrypt_bytes(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> CommandResult<(Vec<u8>, Vec<u8>)> {
    let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(key)
        .map_err(|_| "无法初始化加密算法。".to_string())?;
    let mut nonce = vec![0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| "无法加密数据。".to_string())?;
    Ok((nonce, ciphertext))
}

fn decrypt_bytes(
    key: &[u8; 32],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> CommandResult<Zeroizing<Vec<u8>>> {
    if nonce.len() != 24 || ciphertext.len() < 16 {
        return Err("加密数据格式无效。".to_string());
    }
    let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(key)
        .map_err(|_| "无法初始化解密算法。".to_string())?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| "密码错误或加密数据已损坏。".to_string())?;
    Ok(Zeroizing::new(plaintext))
}

fn entry_aad(id: &str) -> Vec<u8> {
    format!("totp-authenticator/entry/v1/{id}").into_bytes()
}

fn encrypt_entry(key: &[u8; 32], entry: &FullEntry) -> CommandResult<EncryptedEntry> {
    let entry_key = derive_subkey(key, ENTRY_KEY_INFO)?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(entry).map_err(|_| "无法序列化保险库条目。".to_string())?,
    );
    let (nonce, ciphertext) = encrypt_bytes(&entry_key, &plaintext, &entry_aad(&entry.id))?;
    Ok(EncryptedEntry {
        id: entry.id.clone(),
        nonce,
        ciphertext,
        fingerprint: secret_fingerprint(key, &entry.secret)?,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })
}

fn decrypt_entry(key: &[u8; 32], encrypted: &EncryptedEntry) -> CommandResult<FullEntry> {
    let entry_key = derive_subkey(key, ENTRY_KEY_INFO)?;
    let plaintext = decrypt_bytes(
        &entry_key,
        &encrypted.nonce,
        &encrypted.ciphertext,
        &entry_aad(&encrypted.id),
    )
    .map_err(|_| format!("条目 {} 已损坏或被篡改。", encrypted.id))?;
    let entry: FullEntry =
        serde_json::from_slice(&plaintext).map_err(|_| "加密条目内容格式无效。".to_string())?;
    if entry.id != encrypted.id
        || entry.created_at != encrypted.created_at
        || entry.updated_at != encrypted.updated_at
    {
        return Err("加密条目元数据校验失败。".to_string());
    }
    let entry = normalize_full_entry(entry)?;
    if encrypted.fingerprint != secret_fingerprint(key, &entry.secret)? {
        return Err("加密条目指纹校验失败。".to_string());
    }
    Ok(entry)
}

fn secret_fingerprint(key: &[u8; 32], secret: &str) -> CommandResult<Vec<u8>> {
    let fingerprint_key = derive_subkey(key, FINGERPRINT_KEY_INFO)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&fingerprint_key[..])
        .map_err(|_| "无法初始化密钥指纹。".to_string())?;
    mac.update(secret.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn encrypted_entry_from_row(row: &sqlx::sqlite::SqliteRow) -> CommandResult<EncryptedEntry> {
    Ok(EncryptedEntry {
        id: row
            .try_get("id")
            .map_err(|error| database_error("条目 ID 无效", error))?,
        nonce: row
            .try_get("nonce")
            .map_err(|error| database_error("条目 nonce 无效", error))?,
        ciphertext: row
            .try_get("ciphertext")
            .map_err(|error| database_error("条目密文无效", error))?,
        fingerprint: row
            .try_get("fingerprint")
            .map_err(|error| database_error("条目指纹无效", error))?,
        created_at: row
            .try_get("created_at")
            .map_err(|error| database_error("条目创建时间无效", error))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|error| database_error("条目更新时间无效", error))?,
    })
}

async fn insert_encrypted_entry<'e, E>(executor: E, entry: &EncryptedEntry) -> CommandResult<()>
where
    E: sqlx::Executor<'e, Database = Sqlite>,
{
    sqlx::query(
        "
    INSERT INTO vault_entries (
      id, nonce, ciphertext, fingerprint, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      nonce = excluded.nonce,
      ciphertext = excluded.ciphertext,
      fingerprint = excluded.fingerprint,
      created_at = excluded.created_at,
      updated_at = excluded.updated_at
    ",
    )
    .bind(&entry.id)
    .bind(&entry.nonce)
    .bind(&entry.ciphertext)
    .bind(&entry.fingerprint)
    .bind(entry.created_at)
    .bind(entry.updated_at)
    .execute(executor)
    .await
    .map_err(|error| database_error("无法保存加密条目", error))?;
    Ok(())
}

fn read_u32_column(row: &sqlx::sqlite::SqliteRow, column: &str) -> Result<u32, sqlx::Error> {
    let value: i64 = row.try_get(column)?;
    u32::try_from(value).map_err(|error| sqlx::Error::Decode(Box::new(error)))
}

fn build_entry(input: EntryInput, existing: Option<&FullEntry>) -> CommandResult<FullEntry> {
    let now = now_millis();
    let secret = match existing {
        Some(entry) => entry.secret.clone(),
        None => normalize_secret(
            input
                .secret
                .as_deref()
                .ok_or_else(|| "密钥不能为空。".to_string())?,
        )?,
    };
    let entry = FullEntry {
        id: existing
            .map(|entry| entry.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string()),
        label: input.label,
        account: input.account,
        issuer: input.issuer,
        secret,
        algorithm: input.algorithm,
        digits: input.digits,
        period: input.period,
        notes: input.notes,
        website: input.website,
        created_at: existing.map_or(now, |entry| entry.created_at),
        updated_at: now,
    };
    normalize_full_entry(entry)
}

fn normalize_full_entry(mut entry: FullEntry) -> CommandResult<FullEntry> {
    entry.id = entry.id.trim().to_string();
    if entry.id.is_empty() {
        entry.id = Uuid::new_v4().to_string();
    }
    validate_length("条目 ID", &entry.id, 256)?;
    entry.label = entry.label.trim().to_string();
    entry.account = entry.account.trim().to_string();
    entry.issuer = entry.issuer.trim().to_string();
    entry.secret = normalize_secret(&entry.secret)?;
    entry.algorithm = entry.algorithm.trim().to_uppercase();
    entry.notes = entry.notes.trim().to_string();
    entry.website = entry.website.trim().to_string();

    if entry.label.is_empty() {
        return Err("条目名称不能为空。".to_string());
    }
    validate_length("名称", &entry.label, 200)?;
    validate_length("账号", &entry.account, 320)?;
    validate_length("发行方", &entry.issuer, 200)?;
    validate_length("密钥", &entry.secret, 1_024)?;
    validate_length("备注", &entry.notes, 4_000)?;
    validate_length("网址", &entry.website, 2_048)?;
    if !matches!(entry.algorithm.as_str(), "SHA1" | "SHA256" | "SHA512") {
        return Err("算法只支持 SHA1 / SHA256 / SHA512。".to_string());
    }
    if !matches!(entry.digits, 6 | 8) {
        return Err("位数只支持 6 或 8。".to_string());
    }
    if !matches!(entry.period, 15 | 30 | 45 | 60) {
        return Err("周期只支持 15 / 30 / 45 / 60 秒。".to_string());
    }
    if !entry.website.is_empty() {
        let parsed = Url::parse(&entry.website).map_err(|_| "网址格式无效。".to_string())?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err("网址只支持 http 或 https。".to_string());
        }
    }
    decode_base32(&entry.secret)?;
    if entry.created_at <= 0 {
        entry.created_at = now_millis();
    }
    if entry.updated_at <= 0 {
        entry.updated_at = entry.created_at;
    }
    Ok(entry)
}

fn validate_length(name: &str, value: &str, maximum: usize) -> CommandResult<()> {
    if value.chars().count() > maximum {
        return Err(format!("{name}长度不能超过 {maximum} 个字符。"));
    }
    Ok(())
}

fn normalize_secret(secret: &str) -> CommandResult<String> {
    let compact: String = secret
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if compact.is_empty() {
        return Err("密钥不能为空。".to_string());
    }
    let first_padding = compact.find('=').unwrap_or(compact.len());
    if compact[first_padding..]
        .chars()
        .any(|character| character != '=')
    {
        return Err("密钥包含无效的 Base32 填充。".to_string());
    }
    let normalized = compact[..first_padding].to_string();
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|character| character.is_ascii_uppercase() || matches!(character, '2'..='7'))
    {
        return Err("密钥包含无效的 Base32 字符。".to_string());
    }
    Ok(normalized)
}

fn decode_base32(secret: &str) -> CommandResult<Vec<u8>> {
    let normalized = normalize_secret(secret)?;
    let mut output = Vec::with_capacity(normalized.len() * 5 / 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in normalized.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err("密钥包含无效的 Base32 字符。".to_string()),
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    if output.is_empty() {
        return Err("Base32 密钥长度不足。".to_string());
    }
    Ok(output)
}

fn generate_totp(entry: &FullEntry, timestamp: u64) -> CommandResult<String> {
    let secret = Zeroizing::new(decode_base32(&entry.secret)?);
    let counter = timestamp / u64::from(entry.period);
    let counter_bytes = counter.to_be_bytes();
    let digest = match entry.algorithm.as_str() {
        "SHA1" => {
            let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&secret)
                .map_err(|_| "无法初始化 SHA1 TOTP。".to_string())?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA256" => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&secret)
                .map_err(|_| "无法初始化 SHA256 TOTP。".to_string())?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        "SHA512" => {
            let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&secret)
                .map_err(|_| "无法初始化 SHA512 TOTP。".to_string())?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        _ => return Err("不支持的 TOTP 算法。".to_string()),
    };
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulus = 10_u32.pow(entry.digits);
    Ok(format!(
        "{:0width$}",
        binary % modulus,
        width = entry.digits as usize
    ))
}

fn create_encrypted_backup(entries: Vec<FullEntry>, password: &str) -> CommandResult<String> {
    let mut salt = vec![0_u8; 16];
    OsRng.fill_bytes(&mut salt);
    let kdf = KdfDescriptor {
        name: KDF_ALGORITHM.to_string(),
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt: BASE64.encode(&salt),
    };
    let key = derive_password_key(password, &salt, &kdf)?;
    let created_at = now_millis();
    let payload = BackupPayload {
        version: BACKUP_PAYLOAD_VERSION,
        entries,
    };
    let plaintext =
        Zeroizing::new(serde_json::to_vec(&payload).map_err(|_| "无法创建备份内容。".to_string())?);
    let mut backup = EncryptedBackup {
        format: BACKUP_FORMAT.to_string(),
        version: BACKUP_VERSION,
        created_at,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        kdf,
        cipher: CipherDescriptor {
            name: CIPHER_ALGORITHM.to_string(),
            nonce: String::new(),
        },
        ciphertext: String::new(),
    };
    let aad = backup_aad(&backup);
    let (nonce, ciphertext) = encrypt_bytes(&key, &plaintext, aad.as_bytes())?;
    backup.cipher.nonce = BASE64.encode(nonce);
    backup.ciphertext = BASE64.encode(ciphertext);
    serde_json::to_string_pretty(&backup).map_err(|_| "无法序列化加密备份。".to_string())
}

fn backup_aad(backup: &EncryptedBackup) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        backup.format,
        backup.version,
        backup.created_at,
        backup.app_version,
        backup.kdf.name,
        backup.kdf.memory_kib,
        backup.kdf.iterations,
        backup.kdf.parallelism,
        backup.cipher.name,
    )
}

fn is_encrypted_backup(text: &str) -> CommandResult<bool> {
    if !text.starts_with('{') {
        return Ok(false);
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "JSON 备份格式无效。".to_string())?;
    match value.get("format").and_then(serde_json::Value::as_str) {
        Some(BACKUP_FORMAT) => Ok(true),
        Some(_) => Err("不支持的备份文件格式。".to_string()),
        None => Ok(false),
    }
}

fn decrypt_backup(text: &str, password: &str) -> CommandResult<Vec<FullEntry>> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
        return Err("备份密码无效。".to_string());
    }
    let backup: EncryptedBackup =
        serde_json::from_str(text).map_err(|_| "加密备份格式无效。".to_string())?;
    if backup.format != BACKUP_FORMAT || backup.version != BACKUP_VERSION {
        return Err("不支持的加密备份版本。".to_string());
    }
    if backup.cipher.name != CIPHER_ALGORITHM {
        return Err("不支持的备份加密算法。".to_string());
    }
    validate_kdf(&backup.kdf)?;
    let salt = BASE64
        .decode(&backup.kdf.salt)
        .map_err(|_| "备份 KDF salt 格式无效。".to_string())?;
    if !(16..=64).contains(&salt.len()) {
        return Err("备份 KDF salt 长度无效。".to_string());
    }
    let nonce = BASE64
        .decode(&backup.cipher.nonce)
        .map_err(|_| "备份 nonce 格式无效。".to_string())?;
    let ciphertext = BASE64
        .decode(&backup.ciphertext)
        .map_err(|_| "备份密文格式无效。".to_string())?;
    if ciphertext.len() > MAX_BACKUP_BYTES {
        return Err("备份密文过大。".to_string());
    }
    let key = derive_password_key(password, &salt, &backup.kdf)?;
    let aad = backup_aad(&backup);
    let plaintext = decrypt_bytes(&key, &nonce, &ciphertext, aad.as_bytes())
        .map_err(|_| "备份密码错误或文件已损坏。".to_string())?;
    let payload: BackupPayload =
        serde_json::from_slice(&plaintext).map_err(|_| "备份内容格式无效。".to_string())?;
    if payload.version != BACKUP_PAYLOAD_VERSION {
        return Err("不支持的备份内容版本。".to_string());
    }
    if payload.entries.len() > MAX_BACKUP_ENTRIES {
        return Err("备份中的条目数量超过限制。".to_string());
    }
    payload
        .entries
        .into_iter()
        .map(normalize_full_entry)
        .collect()
}

fn parse_legacy_backup(text: &str) -> CommandResult<Vec<FullEntry>> {
    if text.starts_with('{') || text.starts_with('[') {
        let value: serde_json::Value =
            serde_json::from_str(text).map_err(|_| "旧版 JSON 备份格式无效。".to_string())?;
        let legacy_entries: Vec<LegacyEntry> = if value.is_array() {
            serde_json::from_value(value).map_err(|_| "旧版条目数组格式无效。".to_string())?
        } else {
            serde_json::from_value::<LegacySnapshot>(value)
                .map_err(|_| "旧版 JSON 备份缺少 entries 数组。".to_string())?
                .entries
        };
        return legacy_entries
            .into_iter()
            .map(legacy_entry_to_full)
            .collect();
    }

    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(parse_otpauth_uri)
        .collect()
}

fn legacy_entry_to_full(entry: LegacyEntry) -> CommandResult<FullEntry> {
    normalize_full_entry(FullEntry {
        id: entry.id,
        label: entry.label,
        account: entry.account,
        issuer: entry.issuer,
        secret: entry.secret,
        algorithm: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
        notes: entry.notes,
        website: entry.website,
        created_at: entry.created_at,
        updated_at: entry.updated_at,
    })
}

fn parse_otpauth_uri(text: &str) -> CommandResult<FullEntry> {
    let parsed = Url::parse(text).map_err(|_| "无效的 otpauth URI。".to_string())?;
    if parsed.scheme() != "otpauth" || parsed.host_str() != Some("totp") {
        return Err("仅支持 otpauth://totp 类型。".to_string());
    }
    let label_text = percent_decode_str(parsed.path().trim_start_matches('/'))
        .decode_utf8()
        .map_err(|_| "otpauth 标签编码无效。".to_string())?
        .trim()
        .to_string();
    let (label_issuer, account) = label_text
        .split_once(':')
        .map(|(issuer, account)| (issuer.trim().to_string(), account.trim().to_string()))
        .unwrap_or_else(|| (String::new(), String::new()));
    let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
    let issuer = query.get("issuer").cloned().unwrap_or(label_issuer);
    let secret = query
        .get("secret")
        .cloned()
        .ok_or_else(|| "otpauth URI 缺少 secret 参数。".to_string())?;
    let algorithm = query
        .get("algorithm")
        .cloned()
        .unwrap_or_else(default_algorithm);
    let digits = query
        .get("digits")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "otpauth digits 参数无效。".to_string())?
        .unwrap_or_else(default_digits);
    let period = query
        .get("period")
        .map(|value| value.parse::<u32>())
        .transpose()
        .map_err(|_| "otpauth period 参数无效。".to_string())?
        .unwrap_or_else(default_period);
    let display_label = if !account.is_empty() {
        account.clone()
    } else if !label_text.is_empty() {
        label_text
    } else {
        issuer.clone()
    };

    normalize_full_entry(FullEntry {
        id: Uuid::new_v4().to_string(),
        label: display_label,
        account,
        issuer,
        secret,
        algorithm,
        digits,
        period,
        notes: String::new(),
        website: String::new(),
        created_at: now_millis(),
        updated_at: now_millis(),
    })
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn vault_status(state: State<'_, VaultService>) -> CommandResult<VaultStatus> {
    state.status().await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn initialize_vault(
    state: State<'_, VaultService>,
    password: String,
) -> CommandResult<VaultStatus> {
    let password = Zeroizing::new(password);
    state.initialize(&password).await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn unlock_vault(
    state: State<'_, VaultService>,
    password: String,
) -> CommandResult<VaultStatus> {
    let password = Zeroizing::new(password);
    state.unlock(&password).await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn change_master_password(
    state: State<'_, VaultService>,
    current_password: String,
    new_password: String,
) -> CommandResult<VaultStatus> {
    let current_password = Zeroizing::new(current_password);
    let new_password = Zeroizing::new(new_password);
    state
        .change_password(&current_password, &new_password)
        .await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub fn lock_vault(state: State<'_, VaultService>) -> CommandResult<()> {
    state.lock()
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub fn touch_vault(state: State<'_, VaultService>) -> CommandResult<bool> {
    state.touch()
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn list_entries(state: State<'_, VaultService>) -> CommandResult<Vec<PublicEntry>> {
    state.public_entries().await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn upsert_entry(
    state: State<'_, VaultService>,
    entry: EntryInput,
) -> CommandResult<PublicEntry> {
    state.save_entry(entry).await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn delete_entry(state: State<'_, VaultService>, id: String) -> CommandResult<()> {
    state.remove_entry(&id).await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn generate_codes(state: State<'_, VaultService>) -> CommandResult<Vec<TotpCode>> {
    state.codes().await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn export_encrypted_backup(
    state: State<'_, VaultService>,
    password: String,
) -> CommandResult<String> {
    let password = Zeroizing::new(password);
    state.export_backup(&password).await
}

#[cfg(not(vault_standalone))]
#[tauri::command]
pub async fn import_backup(
    state: State<'_, VaultService>,
    backup_text: String,
    password: Option<String>,
) -> CommandResult<ImportResult> {
    let backup_text = Zeroizing::new(backup_text);
    let password = password.map(Zeroizing::new);
    state
        .import_backup_text(&backup_text, password.as_deref().map(String::as_str))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;

    #[cfg(not(vault_standalone))]
    fn test_block_on<F: Future>(future: F) -> F::Output {
        tauri::async_runtime::block_on(future)
    }

    #[cfg(vault_standalone)]
    fn test_block_on<F: Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    async fn legacy_test_service() -> VaultService {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::query("PRAGMA secure_delete = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "
      CREATE TABLE vault_metadata (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        format_version INTEGER NOT NULL,
        kdf_algorithm TEXT NOT NULL,
        cipher_algorithm TEXT NOT NULL,
        kdf_memory_kib INTEGER NOT NULL,
        kdf_iterations INTEGER NOT NULL,
        kdf_parallelism INTEGER NOT NULL,
        salt BLOB NOT NULL,
        wrap_nonce BLOB NOT NULL,
        wrapped_dek BLOB NOT NULL,
        created_at INTEGER NOT NULL
      )
      ",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "
      CREATE TABLE vault_entries (
        id TEXT PRIMARY KEY,
        nonce BLOB NOT NULL,
        ciphertext BLOB NOT NULL,
        fingerprint BLOB NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      )
      ",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "
      CREATE TABLE entries (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        account TEXT NOT NULL,
        issuer TEXT NOT NULL,
        secret TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        digits INTEGER NOT NULL,
        period INTEGER NOT NULL,
        notes TEXT NOT NULL DEFAULT '',
        website TEXT NOT NULL DEFAULT '',
        createdAt INTEGER NOT NULL,
        updatedAt INTEGER NOT NULL
      )
      ",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "
      INSERT INTO entries (
        id, label, account, issuer, secret, algorithm, digits, period,
        notes, website, createdAt, updatedAt
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ",
        )
        .bind("legacy-entry")
        .bind("demo@example.com")
        .bind("demo@example.com")
        .bind("Example")
        .bind("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
        .bind("SHA1")
        .bind(8_i64)
        .bind(30_i64)
        .bind("legacy note")
        .bind("https://example.com")
        .bind(1_i64)
        .bind(1_i64)
        .execute(&pool)
        .await
        .unwrap();

        VaultService {
            pool,
            session: Mutex::new(VaultSession::default()),
        }
    }

    fn test_entry() -> FullEntry {
        FullEntry {
            id: "test-entry".to_string(),
            label: "RFC test".to_string(),
            account: "demo@example.com".to_string(),
            issuer: "Example".to_string(),
            secret: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string(),
            algorithm: "SHA1".to_string(),
            digits: 8,
            period: 30,
            notes: String::new(),
            website: String::new(),
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vector() {
        assert_eq!(generate_totp(&test_entry(), 59).unwrap(), "94287082");
    }

    #[test]
    fn encrypted_entry_round_trip_and_tamper_detection() {
        let key = [7_u8; 32];
        let entry = test_entry();
        let mut encrypted = encrypt_entry(&key, &entry).unwrap();
        assert_eq!(
            decrypt_entry(&key, &encrypted).unwrap().secret,
            entry.secret
        );

        encrypted.ciphertext[0] ^= 1;
        assert!(decrypt_entry(&key, &encrypted).is_err());

        let mut encrypted = encrypt_entry(&key, &entry).unwrap();
        encrypted.fingerprint[0] ^= 1;
        assert!(decrypt_entry(&key, &encrypted).is_err());
    }

    #[test]
    fn base32_validation_rejects_invalid_input() {
        assert_eq!(
            normalize_secret("jbsw y3dp ehpk 3pxp===").unwrap(),
            "JBSWY3DPEHPK3PXP"
        );
        assert!(normalize_secret("JBSW0Y3D").is_err());
        assert_eq!(decode_base32("MZXW6===").unwrap(), b"foo");
    }

    #[test]
    fn backup_round_trip_and_wrong_password_detection() {
        let correct_password = format!("{} {}", "correct", "horse");
        let wrong_password = format!("{} {}", "wrong", "password");

        let backup = create_encrypted_backup(vec![test_entry()], &correct_password).unwrap();
        let entries = decrypt_backup(&backup, &correct_password).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].secret, test_entry().secret);
        assert!(decrypt_backup(&backup, &wrong_password).is_err());

        let mut tampered: EncryptedBackup = serde_json::from_str(&backup).unwrap();
        let mut ciphertext = BASE64.decode(&tampered.ciphertext).unwrap();
        ciphertext[0] ^= 1;
        tampered.ciphertext = BASE64.encode(ciphertext);
        let tampered = serde_json::to_string(&tampered).unwrap();
        assert!(decrypt_backup(&tampered, &correct_password).is_err());
    }

    #[test]
    fn legacy_backup_parsing_supports_json_and_otpauth() {
        let json = serde_json::json!({
          "version": 1,
          "entries": [{
            "id": "legacy-json",
            "label": "JSON",
            "account": "json@example.com",
            "issuer": "Example",
            "secret": "JBSWY3DPEHPK3PXP",
            "algorithm": "SHA1",
            "digits": 6,
            "period": 30
          }]
        })
        .to_string();
        let entries = parse_legacy_backup(&json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "legacy-json");

        let entries = parse_legacy_backup(
            "otpauth://totp/Example:uri@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        )
        .unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].account, "uri@example.com");
    }

    #[test]
    fn vault_migrates_crud_changes_password_and_restores_backup() {
        test_block_on(async {
            let service = legacy_test_service().await;
            let initial_status = service.status().await.unwrap();
            assert!(!initial_status.initialized);
            assert_eq!(initial_status.legacy_entry_count, 1);

            let test_password = format!(
                "test-password-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let status = service.initialize(&test_password).await.unwrap();
            assert!(status.initialized);
            assert!(status.unlocked);
            assert_eq!(status.legacy_entry_count, 0);
            assert!(!service.legacy_table_exists().await.unwrap());

            let entries = service.public_entries().await.unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].id, "legacy-entry");
            let public_json = serde_json::to_string(&entries).unwrap();
            assert!(!public_json.contains("GEZDGNBV"));
            assert!(!public_json.contains("\"secret\""));

            let ciphertext: Vec<u8> =
                sqlx::query_scalar("SELECT ciphertext FROM vault_entries WHERE id = ?")
                    .bind("legacy-entry")
                    .fetch_one(&service.pool)
                    .await
                    .unwrap();
            assert!(!ciphertext
                .windows(b"GEZDGNBVGY3TQOJQ".len())
                .any(|window| window == b"GEZDGNBVGY3TQOJQ"));
            let codes = service.codes().await.unwrap();
            assert_eq!(codes.len(), 1);
            assert_eq!(codes[0].code.as_ref().unwrap().len(), 8);

            let seed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let initial_password = format!("initial-{seed}");
            let updated_password = format!("updated-{seed}");
            let backup_password = format!("backup-{seed}");

            let backup = service
                .export_backup(backup_password.as_str())
                .await
                .unwrap();
            assert!(!backup.contains("GEZDGNBV"));
            service
                .change_password(initial_password.as_str(), updated_password.as_str())
                .await
                .unwrap();
            service.lock().unwrap();
            assert!(service.unlock(initial_password.as_str()).await.is_err());
            service.unlock(updated_password.as_str()).await.unwrap();

            service.remove_entry("legacy-entry").await.unwrap();
            assert!(service.public_entries().await.unwrap().is_empty());
            let import = service
                .import_backup_text(&backup, Some(backup_password.as_str()))
                .await
                .unwrap();
            assert_eq!(import.added, 1);
            assert_eq!(import.replaced, 0);
            assert_eq!(service.public_entries().await.unwrap().len(), 1);

            let repeated_import = service
                .import_backup_text(&format!("\u{feff}{backup}"), Some(backup_password.as_str()))
                .await
                .unwrap();
            assert_eq!(repeated_import.added, 0);
            assert_eq!(repeated_import.replaced, 1);

            {
                let mut session = service.session.lock().unwrap();
                session.last_activity =
                    Some(Instant::now() - Duration::from_secs(AUTO_LOCK_SECONDS + 1));
            }
            assert!(!service.session_is_unlocked().unwrap());
        });
    }
}
