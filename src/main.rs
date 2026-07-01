#![windows_subsystem = "windows"]

use std::fs::{self, File};
use std::io::{Cursor, Read, Write};
use std::path::PathBuf;
use std::time::{Instant, Duration};
use std::thread;
use std::sync::mpsc;
use std::error::Error as StdError;

use aead::{Aead, KeyInit};
use argon2::{Argon2, Params, Version, Algorithm};
use base64::{engine::general_purpose, Engine as _};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use directories::ProjectDirs;
use eframe::{egui, App, Frame};
use hmac::{Hmac, Mac};
use rand::{RngCore, Rng};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use arboard::Clipboard;

// - - - Embedded logo pixel data - - -
include!("logo_data.rs");

// - - - Embedded sound assets - - -
// Path is relative to this file (src/main.rs), so assets/ lives at the project root,
// i.e. ZeroPass/assets/unlock.mp3, alongside Cargo.toml.
static UNLOCK_SOUND_BYTES: &[u8] = include_bytes!("../assets/unlock.mp3");

/// Plays the embedded unlock sound on a throwaway background thread so it never
/// blocks the UI thread. Failures (no audio device, bad decode, etc.) are swallowed
/// since a missing sound should never crash or interrupt the app.
fn play_unlock_sound() {
    thread::spawn(|| {
        let (_stream, stream_handle) = match rodio::OutputStream::try_default() {
            Ok(s) => s,
            Err(_) => return,
        };
        let sink = match rodio::Sink::try_new(&stream_handle) {
            Ok(s) => s,
            Err(_) => return,
        };
        if let Ok(source) = rodio::Decoder::new(Cursor::new(UNLOCK_SOUND_BYTES)) {
            sink.append(source);
            sink.sleep_until_end(); // keeps _stream/sink alive on this thread until playback finishes
        }
    });
}

// - - - Constants - - -
const MAGIC: &str = "RV_GUI_V1";
const MINIMUM_LOAD_TIME: Duration = Duration::from_millis(0);

// - - - Version checker constants - - -
/// The app's own version, shown in the UI and compared against GitHub releases.
/// Update this alongside Cargo.toml's `version` field on each release.
const APP_VERSION: &str = "2.0.2-release";
/// Whether this build is itself a pre-release/beta build. Affects how the
/// version checker interprets "newer" releases (see `check_for_updates`).
const APP_IS_PRERELEASE: bool = false;
const GITHUB_OWNER: &str = "makke08";
const GITHUB_REPO: &str = "ZeroPass";

/// Restricts a file (or directory) to owner-only access (0600 / 0700) on Unix.
/// No-op on Windows, where files already inherit the user profile's ACLs and
/// `ProjectDirs` resolves under `%APPDATA%`, which is already user-private.
/// Failures are swallowed — a permission tweak should never block startup or
/// crash the app, but we still attempt it on every save for defense in depth.
#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path, is_dir: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if is_dir { 0o700 } else { 0o600 };
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(mode);
        let _ = fs::set_permissions(path, perms);
    }
}
#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path, _is_dir: bool) {}

struct ArgonParams {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

const KDF_PARAMS: ArgonParams = ArgonParams {
    m_cost: 65536,
    t_cost: 3,
    p_cost: 1,
};

// - - - Toast Notifications - - -
#[derive(Debug, Clone, PartialEq)]
enum ToastKind { Success, Error, Info }

struct Toast {
    message: String,
    kind: ToastKind,
    spawned: Instant,
    duration: f32,
}

const TOAST_ENTER_SECS: f32 = 0.25;  
const TOAST_EXIT_SECS:  f32 = 0.30;  
const TOAST_HOLD_SECS:  f32 = 2.80;  
const TOAST_TOTAL_SECS: f32 = TOAST_ENTER_SECS + TOAST_HOLD_SECS + TOAST_EXIT_SECS;

// - - - Error Handling - - -
#[derive(Error, Debug)]
enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("{0}")]
    Msg(String),
}

// - - - TOTP Engine (RFC 6238 / RFC 4226) - - -
// - - - HMAC-SHA1 via the audited RustCrypto `hmac` + `sha1` crates; base32 decode is hand-rolled. - - -

fn totp_base32_decode(s: &str) -> Option<Vec<u8>> {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let s = s.trim().to_uppercase().replace(['=', ' ', '-'], "");
    let mut bits: u64 = 0;
    let mut bit_count: u32 = 0;
    let mut out = Vec::new();
    for ch in s.bytes() {
        let val = alphabet.iter().position(|&b| b == ch)? as u64;
        bits = (bits << 5) | val;
        bit_count += 5;
        if bit_count >= 8 {
            bit_count -= 8;
            out.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }
    Some(out)
}

/// Returns (code, seconds_remaining) for a 30-second TOTP window, or None if secret is invalid.
fn totp_now(secret_b32: &str) -> Option<(String, u64)> {
    let key = totp_base32_decode(secret_b32)?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
    let counter = secs / 30;
    let remaining = 30 - (secs % 30);
    let msg = counter.to_be_bytes();

    // - - - HMAC-SHA1 via the audited RustCrypto `hmac` + `sha1` crates - - -
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&key).ok()?;
    mac.update(&msg);
    let mac = mac.finalize().into_bytes();

    let offset = (mac[19] & 0x0F) as usize;
    let code = u32::from_be_bytes(mac[offset..offset+4].try_into().unwrap()) & 0x7FFF_FFFF;
    Some((format!("{:06}", code % 1_000_000), remaining))
}


#[derive(Serialize, Deserialize, Clone, Debug)]
struct PasswordHistoryEntry {
    password: String,
    /// Unix timestamp (seconds) of when this password was replaced.
    changed_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    id: String,
    service: String,
    username: String,
    password: String,
    #[serde(default)]
    totp_secret: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    pinned: bool,
    /// Previous passwords for this entry, most recent first.
    #[serde(default)]
    password_history: Vec<PasswordHistoryEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SecureNote {
    id: String,
    title: String,
    content: String,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Vault {
    entries: Vec<Entry>,
    #[serde(default)]
    notes: Vec<SecureNote>,
}

#[derive(Serialize, Deserialize)]
struct EncFile {
    magic: String,
    salt_b64: String,
    nonce_b64: String,
    cipher_b64: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct Settings {
    vsync_enabled: bool,
    dark_mode: bool,
    clipboard_timeout_secs: Option<u64>,
    auto_lock_enabled: bool,
    auto_lock_timeout_mins: u64,
    lock_on_focus_loss: bool,
    default_password_length: u32,
    gen_use_uppercase: bool,
    gen_use_numbers: bool,
    gen_use_symbols: bool,
    show_passwords: bool,
    #[serde(default)]
    has_seen_beta_warning: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            vsync_enabled: true,
            dark_mode: true,
            clipboard_timeout_secs: Some(10),
            auto_lock_enabled: false,
            auto_lock_timeout_mins: 5,
            lock_on_focus_loss: false,
            default_password_length: 16,
            gen_use_uppercase: true,
            gen_use_numbers: true,
            gen_use_symbols: true,
            show_passwords: false,
            has_seen_beta_warning: false,
        }
    }
}

// - - - Core Logic - - -

fn default_vault_path() -> Result<PathBuf, VaultError> {
    let proj = ProjectDirs::from("com", "example", "ZeroPass")
        .ok_or_else(|| VaultError::Msg("Unable to determine data dir".into()))?;
    let dir = proj.data_dir();
    fs::create_dir_all(dir)?;
    restrict_permissions(dir, true);
    Ok(dir.join("vault.json.enc"))
}

fn settings_path() -> Result<PathBuf, Box<dyn StdError>> {
    let proj = ProjectDirs::from("com", "example", "ZeroPass")
        .ok_or_else(|| VaultError::Msg("Unable to determine data dir".into()))?;
    let dir = proj.data_dir();
    fs::create_dir_all(dir)?;
    restrict_permissions(dir, true);
    Ok(dir.join("settings.json"))
}

fn load_settings() -> Settings {
    if let Ok(path) = settings_path() {
        if let Ok(mut file) = File::open(&path) {
            let mut buf = String::new();
            if file.read_to_string(&mut buf).is_ok() {
                if let Ok(settings) = serde_json::from_str(&buf) {
                    return settings;
                }
            }
        }
    }
    Settings::default()
}

fn save_settings(settings: &Settings) {
    if let Ok(path) = settings_path() {
        if let Ok(mut file) = File::create(&path) {
            if let Ok(json) = serde_json::to_string_pretty(settings) {
                let _ = file.write_all(json.as_bytes());
            }
        }
        restrict_permissions(&path, false);
    }
}
// ─── Vault Registry ──────────────────────────────────────────────────────────
// Tracks every vault the user has created/opened, plus which was last used.

#[derive(Serialize, Deserialize, Clone, Debug)]
struct VaultRecord {
    /// Human-readable name shown in the vault manager UI
    name: String,
    /// Absolute path to the encrypted .enc file
    path: String,
    /// Unix timestamp of the last time this vault was unlocked
    #[serde(default)]
    last_opened: u64,
}

#[derive(Serialize, Deserialize, Debug, Default)]
struct VaultRegistry {
    vaults: Vec<VaultRecord>,
    /// Index into `vaults` of the last-opened vault (None = use default)
    #[serde(default)]
    last_used_index: Option<usize>,
}

fn registry_path() -> Result<PathBuf, VaultError> {
    let proj = ProjectDirs::from("com", "example", "ZeroPass")
        .ok_or_else(|| VaultError::Msg("Unable to determine data dir".into()))?;
    let dir = proj.data_dir();
    fs::create_dir_all(dir)?;
    restrict_permissions(dir, true);
    Ok(dir.join("vaults.json"))
}

fn load_registry() -> VaultRegistry {
    if let Ok(path) = registry_path() {
        if let Ok(mut f) = File::open(&path) {
            let mut buf = String::new();
            if f.read_to_string(&mut buf).is_ok() {
                if let Ok(r) = serde_json::from_str(&buf) {
                    return r;
                }
            }
        }
    }
    VaultRegistry::default()
}

fn save_registry(reg: &VaultRegistry) {
    if let Ok(path) = registry_path() {
        if let Ok(mut f) = File::create(&path) {
            if let Ok(json) = serde_json::to_string_pretty(reg) {
                let _ = f.write_all(json.as_bytes());
            }
        }
        restrict_permissions(&path, false);
    }
}

/// Returns the data directory used by ZeroPass (creates it if needed).
fn data_dir() -> Result<PathBuf, VaultError> {
    let proj = ProjectDirs::from("com", "example", "ZeroPass")
        .ok_or_else(|| VaultError::Msg("Unable to determine data dir".into()))?;
    let dir = proj.data_dir().to_path_buf();
    fs::create_dir_all(&dir)?;
    restrict_permissions(&dir, true);
    Ok(dir)
}



fn derive_key(password: &str, salt: &[u8], params: &ArgonParams) -> Result<[u8; 32], VaultError> {
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, None)
        .map_err(|e| VaultError::Crypto(format!("Argon2 params error: {e}")))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; 32];
    argon
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| VaultError::Crypto(format!("KDF failed: {e}")))?;
    Ok(key)
}

fn encrypt_vault(vault: &Vault, password: &str) -> Result<EncFile, VaultError> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let mut key_bytes = derive_key(password, &salt, &KDF_PARAMS)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let plaintext = serde_json::to_vec(vault)?;
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| VaultError::Crypto("Encryption failed".into()))?;

    Ok(EncFile {
        magic: MAGIC.to_string(),
        salt_b64: general_purpose::STANDARD.encode(salt),
        nonce_b64: general_purpose::STANDARD.encode(nonce),
        cipher_b64: general_purpose::STANDARD.encode(ciphertext),
        m_cost: KDF_PARAMS.m_cost,
        t_cost: KDF_PARAMS.t_cost,
        p_cost: KDF_PARAMS.p_cost,
    })
}

fn decrypt_vault(enc: &EncFile, password: &str) -> Result<Vault, VaultError> {
    if enc.magic != MAGIC { return Err(VaultError::Msg("Bad file magic".into())); }
    
    let salt = general_purpose::STANDARD.decode(&enc.salt_b64).map_err(|_| VaultError::Msg("Bad salt".into()))?;
    let nonce = general_purpose::STANDARD.decode(&enc.nonce_b64).map_err(|_| VaultError::Msg("Bad nonce".into()))?;
    let cipher_bytes = general_purpose::STANDARD.decode(&enc.cipher_b64).map_err(|_| VaultError::Msg("Bad ciphertext".into()))?;

    let params = ArgonParams { m_cost: enc.m_cost, t_cost: enc.t_cost, p_cost: enc.p_cost };
    let mut key_bytes = derive_key(password, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce), cipher_bytes.as_ref())
        .map_err(|_| VaultError::Msg("Decryption failed (wrong password?)".into()))?;
        
    serde_json::from_slice(&plaintext).map_err(Into::into)
}

fn read_enc_file(path: &PathBuf) -> Result<EncFile, VaultError> {
    let mut f = File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    serde_json::from_slice(&buf).map_err(Into::into)
}

fn write_enc_file(path: &PathBuf, enc: &EncFile) -> Result<(), VaultError> {
    let json = serde_json::to_vec_pretty(enc)?;
    let mut f = File::create(path)?;
    f.write_all(&json)?;
    drop(f);
    restrict_permissions(path, false);
    Ok(())
}

fn save_vault_file(path: &PathBuf, vault: &Vault, password: &str) -> Result<(), VaultError> {
    let enc = encrypt_vault(vault, password)?;
    write_enc_file(path, &enc)
}

fn gen_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

/// Truncates a string (by char count, not bytes, so it's UTF-8/emoji safe) to
/// `max_chars` and appends an ellipsis if it was cut short. Used anywhere
/// user-supplied free text (titles, categories, tags, etc.) is rendered in a
/// fixed-width UI element, so a single very long word can't blow out layout,
/// overlap other widgets, or run off the edge of the window.
fn truncate_display(s: &str, max_chars: usize) -> String {
    let char_count = s.chars().count();
    if char_count <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        format!("{}…", truncated)
    }
}

/// Formats a Unix timestamp (seconds) as a short relative "time ago" string
/// for display in the password history list, e.g. "3 days ago" or "just now".
fn format_timestamp_ago(unix_secs: u64) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(unix_secs);
    let diff = now.saturating_sub(unix_secs);
    if diff < 60 {
        "Just now".to_string()
    } else if diff < 3600 {
        let m = diff / 60;
        format!("{} minute{} ago", m, if m == 1 { "" } else { "s" })
    } else if diff < 86_400 {
        let h = diff / 3600;
        format!("{} hour{} ago", h, if h == 1 { "" } else { "s" })
    } else if diff < 86_400 * 30 {
        let d = diff / 86_400;
        format!("{} day{} ago", d, if d == 1 { "" } else { "s" })
    } else if diff < 86_400 * 365 {
        let mo = diff / (86_400 * 30);
        format!("{} month{} ago", mo, if mo == 1 { "" } else { "s" })
    } else {
        let y = diff / (86_400 * 365);
        format!("{} year{} ago", y, if y == 1 { "" } else { "s" })
    }
}

fn generate_password(length: usize, upper: bool, nums: bool, syms: bool) -> String {
    let mut charset = b"abcdefghijklmnopqrstuvwxyz".to_vec();
    if upper { charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
    if nums { charset.extend_from_slice(b"0123456789"); }
    if syms { charset.extend_from_slice(b"!@#$%^&*()-_=+[]{}|;:,.<>?"); }

    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..charset.len());
            charset[idx] as char
        })
        .collect()
}

// - - - Import / Export - - -
// Plaintext JSON: { "entries": [...], "notes": [...] }
// Exported JSON uses the same Entry/SecureNote shapes so import is lossless.

fn export_vault_json(vault: &Vault) -> Result<String, VaultError> {
    serde_json::to_string_pretty(vault).map_err(Into::into)
}

fn import_vault_json(json: &str, vault: &mut Vault) -> Result<usize, VaultError> {
    let imported: Vault = serde_json::from_str(json)?;
    let existing_ids: std::collections::HashSet<String> = vault.entries.iter().map(|e| e.id.clone()).collect();
    let existing_note_ids: std::collections::HashSet<String> = vault.notes.iter().map(|n| n.id.clone()).collect();
    let mut added = 0usize;
    for mut entry in imported.entries {
        if existing_ids.contains(&entry.id) {
            entry.id = gen_id();
        }
        vault.entries.push(entry);
        added += 1;
    }
    for mut note in imported.notes {
        if existing_note_ids.contains(&note.id) {
            note.id = gen_id();
        }
        vault.notes.push(note);
        added += 1;
    }
    Ok(added)
}

// - - - Version Checker - - -
// - - - Queries the GitHub Releases API for the latest stable and latest - - -
// - - - pre-release tags, compares them against APP_VERSION, and reports - - -
// - - - whether a stable or beta update is available. Runs on a background - - -
// - - - thread (like vault unlock/creation) so the UI never blocks on network I/O. - - -

#[derive(Debug, Clone, PartialEq)]
enum UpdateStatus {
    /// Haven't checked yet, or the last check is still in flight.
    Unknown,
    /// Checked successfully — current build is up to date.
    UpToDate,
    /// A newer stable release is available.
    StableAvailable { version: String, url: String },
    /// A newer pre-release/beta build is available (only surfaced if this
    /// build is itself a beta — stable users aren't offered beta upgrades).
    BetaAvailable { version: String, url: String },
    /// The check failed (offline, rate-limited, GitHub unreachable, etc).
    CheckFailed(String),
}

#[derive(Deserialize, Debug, Clone)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
    prerelease: bool,
    #[serde(default)]
    draft: bool,
}

/// Strips a leading "v"/"V" and any whitespace from a release tag, e.g. "v2.1.0" -> "2.1.0".
fn normalize_version_tag(tag: &str) -> String {
    tag.trim().trim_start_matches(['v', 'V']).to_string()
}

/// Parses a dotted version string into numeric components for comparison,
/// e.g. "2.1.0" -> [2, 1, 0]. Non-numeric trailing suffixes (like "-beta.2")
/// are split off and compared lexically only as a tiebreaker.
fn parse_version_parts(v: &str) -> (Vec<u64>, String) {
    let (numeric_part, suffix) = match v.split_once('-') {
        Some((n, s)) => (n, s.to_string()),
        None => (v, String::new()),
    };
    let parts = numeric_part
        .split('.')
        .map(|p| p.parse::<u64>().unwrap_or(0))
        .collect();
    (parts, suffix)
}

/// Returns true if `candidate` is a strictly newer version than `current`.
/// Compares numeric dot-separated components first (1.2.3 vs 1.10.0 sorts
/// correctly since each component compares as an integer, not lexically),
/// falling back to a lexical suffix comparison only if the numeric parts are
/// equal (e.g. distinguishing "2.0.0-beta.1" from "2.0.0-beta.2").
fn is_newer_version(candidate: &str, current: &str) -> bool {
    let (c_parts, c_suffix) = parse_version_parts(candidate);
    let (cur_parts, cur_suffix) = parse_version_parts(current);
    let len = c_parts.len().max(cur_parts.len());
    for i in 0..len {
        let c = c_parts.get(i).copied().unwrap_or(0);
        let u = cur_parts.get(i).copied().unwrap_or(0);
        if c != u { return c > u; }
    }
    // - - - Numeric parts equal: a build with no suffix outranks one with a - - -
    // - - - suffix (e.g. "2.0.0" > "2.0.0-beta.1"); otherwise compare suffixes lexically. - - -
    match (c_suffix.is_empty(), cur_suffix.is_empty()) {
        (true, false) => true,
        (false, true) => false,
        _ => c_suffix > cur_suffix,
    }
}

/// Fetches all releases from GitHub and determines update status relative to
/// APP_VERSION. Stable users only ever see `StableAvailable`; beta/pre-release
/// builds (APP_IS_PRERELEASE = true) are additionally offered `BetaAvailable`
/// when a newer pre-release exists, so beta testers can stay on the bleeding edge.
fn check_for_updates() -> UpdateStatus {
    let url = format!("https://api.github.com/repos/{GITHUB_OWNER}/{GITHUB_REPO}/releases");
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(8))
        .build();
    let resp = match agent.get(&url)
        .set("User-Agent", "ZeroPass-UpdateChecker")
        .set("Accept", "application/vnd.github+json")
        .call()
    {
        Ok(r) => r,
        Err(e) => return UpdateStatus::CheckFailed(format!("Network error: {e}")),
    };

    let releases: Vec<GithubRelease> = match resp.into_json() {
        Ok(r) => r,
        Err(e) => return UpdateStatus::CheckFailed(format!("Bad response: {e}")),
    };

    // - - - Newest non-draft stable release (prerelease == false) - - -
    let latest_stable = releases.iter()
        .filter(|r| !r.draft && !r.prerelease)
        .map(|r| (normalize_version_tag(&r.tag_name), r.html_url.clone()))
        .max_by(|a, b| {
            if is_newer_version(&a.0, &b.0) { std::cmp::Ordering::Greater }
            else if is_newer_version(&b.0, &a.0) { std::cmp::Ordering::Less }
            else { std::cmp::Ordering::Equal }
        });

    if let Some((ver, url)) = &latest_stable {
        if is_newer_version(ver, APP_VERSION) {
            return UpdateStatus::StableAvailable { version: ver.clone(), url: url.clone() };
        }
    }

    // - - - Only beta builds get offered newer pre-releases; stable users - - -
    // - - - shouldn't be nudged toward beta channels they didn't opt into. - - -
    if APP_IS_PRERELEASE {
        let latest_pre = releases.iter()
            .filter(|r| !r.draft && r.prerelease)
            .map(|r| (normalize_version_tag(&r.tag_name), r.html_url.clone()))
            .max_by(|a, b| {
                if is_newer_version(&a.0, &b.0) { std::cmp::Ordering::Greater }
                else if is_newer_version(&b.0, &a.0) { std::cmp::Ordering::Less }
                else { std::cmp::Ordering::Equal }
            });
        if let Some((ver, url)) = latest_pre {
            if is_newer_version(&ver, APP_VERSION) {
                return UpdateStatus::BetaAvailable { version: ver, url };
            }
        }
    }

    UpdateStatus::UpToDate
}

// - - - GUI State Management - - -

#[derive(PartialEq, Debug)]
enum AppState {
    Locked,
    Unlocking(Instant),
    Unlocked,
    NoVault,
    CreatingVault(Instant),
    KnownBugs,
    Notes,
    SettingsView,
    GeneratorView,
    VaultManager,          // - - - Vault manager / switcher screen - - -
}

enum UnlockResult {
    Success(Vault),
    Error(String),
}

#[derive(Default)]
enum Modal {
    #[default]
    None,
    BetaWarning,
    AddEntry { service: String, username: String, password: String, password_length: f32, totp_secret: String, totp_open: bool, category: String, tags: String },
    EditEntry { original_id: String, service: String, username: String, password: String, totp_secret: String, totp_open: bool, category: String, tags: String },
    ChangePassword { old: String, new: String, confirm: String },
    DeleteVault { confirmation: String },
    CreateVault { name: String, path_input: String, password: String, confirm: String },
    RenameVault { index: usize, new_name: String },
    DeleteVaultRecord { index: usize, confirmation: String },

    AddNote { title: String, content: String, category: String, tags: String },
    EditNote { original_id: String, title: String, content: String, category: String, tags: String },
    ImportExport {
        active_tab: u8, // - - - 0=Export, 1=Import - - -
        import_text: String,
        export_preview: String,
        export_password: String,
        import_password: String,
        encrypted_export: bool, // - - - true = write EncFile JSON, false = plaintext - - -
    },
    /// Shows the password history for a single entry, oldest-to-newest reveal toggles tracked locally in the view.
    PasswordHistory { entry_id: String },
}

impl Modal {
    /// Best-effort zeroization of any plaintext password/secret fields a modal
    /// may be holding, called right before the modal is dropped (on close or
    /// cancel) so secrets don't linger in freed heap memory longer than needed.
    fn zeroize_sensitive(&mut self) {
        match self {
            Modal::AddEntry { password, totp_secret, .. } => { password.zeroize(); totp_secret.zeroize(); }
            Modal::EditEntry { password, totp_secret, .. } => { password.zeroize(); totp_secret.zeroize(); }
            Modal::ChangePassword { old, new, confirm } => { old.zeroize(); new.zeroize(); confirm.zeroize(); }
            Modal::DeleteVault { confirmation } => confirmation.zeroize(),
            Modal::CreateVault { password, confirm, .. } => { password.zeroize(); confirm.zeroize(); }
            Modal::DeleteVaultRecord { confirmation, .. } => confirmation.zeroize(),
            Modal::ImportExport { export_password, import_password, .. } => {
                export_password.zeroize(); import_password.zeroize();
            }
            _ => {}
        }
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct VaultGui {
    #[zeroize(skip)]
    state: AppState,
    #[zeroize(skip)]
    logo_texture: Option<egui::TextureHandle>,
    #[zeroize(skip)]
    message: String,
    #[zeroize(skip)]
    vault_path: PathBuf,
    
    #[zeroize(skip)]
    vault: Vault,
    
    master_password: String,

    master_password_confirm: String,

    #[zeroize(skip)]
    unlock_receiver: Option<mpsc::Receiver<UnlockResult>>,

    #[zeroize(skip)]
    modal: Modal,

    #[zeroize(skip)]
    clipboard_clear_time: Option<Instant>,

    #[zeroize(skip)]
    vsync_enabled: bool,

    #[zeroize(skip)]
    dark_mode: bool,

    #[zeroize(skip)]
    search_query: String,

    #[zeroize(skip)]
    clipboard_timeout_secs: Option<u64>,

    #[zeroize(skip)]
    auto_lock_enabled: bool,

    #[zeroize(skip)]
    auto_lock_timeout_mins: u64,

    #[zeroize(skip)]
    lock_on_focus_loss: bool,

    #[zeroize(skip)]
    default_password_length: u32,

    #[zeroize(skip)]
    gen_use_uppercase: bool,

    #[zeroize(skip)]
    gen_use_numbers: bool,

    #[zeroize(skip)]
    gen_use_symbols: bool,

    #[zeroize(skip)]
    show_passwords: bool,

    #[zeroize(skip)]
    has_seen_beta_warning: bool,

    #[zeroize(skip)]
    last_activity: Instant,

    #[zeroize(skip)]
    toasts: Vec<Toast>,

    #[zeroize(skip)]
    info_page_opened: Option<Instant>,

    #[zeroize(skip)]
    view_opened: Option<Instant>,

    // - - - Drag-to-reorder state - - -
    #[zeroize(skip)]
    drag_source_idx: Option<usize>,
    #[zeroize(skip)]
    drag_target_idx: Option<usize>,
    #[zeroize(skip)]
    drag_pointer_y: f32,

    // - - - Category / tag filter state - - -
    #[zeroize(skip)]
    active_category_filter: Option<String>,
    active_note_category_filter: Option<String>,
    #[zeroize(skip)]
    active_tag_filter: Option<String>,
    active_note_tag_filter: Option<String>,

    // - - - Notes page animation - - -
    #[zeroize(skip)]
    notes_page_opened: Option<Instant>,

    // - - - Settings view animation - - -
    #[zeroize(skip)]
    settings_page_opened: Option<Instant>,

    // - - - Generator view animation - - -
    #[zeroize(skip)]
    generator_page_opened: Option<Instant>,

    // - - - Vault registry (all known vaults) - - -
    #[zeroize(skip)]
    vault_registry: VaultRegistry,

    // - - - Vault manager view animation - - -
    #[zeroize(skip)]
    vault_manager_opened: Option<Instant>,

    // - - - Version / update checker state - - -
    #[zeroize(skip)]
    update_status: UpdateStatus,
    #[zeroize(skip)]
    update_check_receiver: Option<mpsc::Receiver<UpdateStatus>>,
}

impl VaultGui {
    fn new(vault_path: PathBuf, settings: Settings) -> Self {
        let state = if vault_path.exists() { AppState::Locked } else { AppState::NoVault };
        Self {
            state,
            vault_path,
            message: String::new(),
            vault: Vault::default(),
            master_password: String::new(),
            master_password_confirm: String::new(),
            unlock_receiver: None,
            modal: if settings.has_seen_beta_warning { Modal::None } else { Modal::BetaWarning },
            clipboard_clear_time: None,
            vsync_enabled: settings.vsync_enabled,
            dark_mode: settings.dark_mode,
            search_query: String::new(),
            clipboard_timeout_secs: settings.clipboard_timeout_secs,
            auto_lock_enabled: settings.auto_lock_enabled,
            auto_lock_timeout_mins: settings.auto_lock_timeout_mins,
            lock_on_focus_loss: settings.lock_on_focus_loss,
            default_password_length: settings.default_password_length,
            gen_use_uppercase: settings.gen_use_uppercase,
            gen_use_numbers: settings.gen_use_numbers,
            gen_use_symbols: settings.gen_use_symbols,
            show_passwords: settings.show_passwords,
            has_seen_beta_warning: settings.has_seen_beta_warning,
            last_activity: Instant::now(),
            toasts: Vec::new(),
            info_page_opened: None,
            view_opened: Some(Instant::now()),
            drag_source_idx: None,
            drag_target_idx: None,
            drag_pointer_y: 0.0,
            active_category_filter: None,
            active_tag_filter: None,
            active_note_category_filter: None,
            active_note_tag_filter: None,
            notes_page_opened: None,
            settings_page_opened: None,
            generator_page_opened: None,
            vault_registry: load_registry(),
            vault_manager_opened: None,
            logo_texture: None,
            update_status: UpdateStatus::Unknown,
            update_check_receiver: None,
        }
    }

    /// Kicks off a background check against GitHub Releases (see `check_for_updates`).
    /// Safe to call repeatedly — if a check is already in flight, this just resets
    /// the receiver and starts a fresh one rather than stacking up threads.
    fn check_for_updates_async(&mut self) {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = check_for_updates();
            let _ = tx.send(result);
        });
        self.update_check_receiver = Some(rx);
    }

    fn push_toast(&mut self, message: String, kind: ToastKind) {
        self.toasts.retain(|t| t.kind != kind);
        self.toasts.push(Toast {
            message,
            kind,
            spawned: Instant::now(),
            duration: TOAST_TOTAL_SECS,
        });
    }

    fn handle_error(&mut self, e: VaultError) {
        let msg = format!("Error: {}", e);
        self.push_toast(msg.clone(), ToastKind::Error);
        self.message = msg;
    }
    
    fn handle_success(&mut self, msg: &str) {
        self.push_toast(msg.to_string(), ToastKind::Success);
        self.message = msg.to_string();
    }

    fn create_new_vault(&mut self) {
        if self.master_password.is_empty() {
            self.push_toast("Master password cannot be empty".into(), ToastKind::Error);
            return;
        }
        if self.master_password.len() < 8 {
            self.push_toast("Master password must be at least 8 characters".into(), ToastKind::Error);
            return;
        }
        if self.master_password != self.master_password_confirm {
            self.push_toast("Passwords don't match".into(), ToastKind::Error);
            return;
        }

        self.state = AppState::CreatingVault(Instant::now());
        let password = self.master_password.clone();
        let vault_path = self.vault_path.clone();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let v = Vault::default();
            let result = match save_vault_file(&vault_path, &v, &password) {
                Ok(()) => UnlockResult::Success(v),
                Err(e) => UnlockResult::Error(format!("Failed to create vault: {}", e)),
            };
            let _ = tx.send(result);
        });
        self.master_password_confirm.zeroize();
        self.unlock_receiver = Some(rx);
    }

    fn unlock_vault(&mut self) {
        if self.master_password.is_empty() {
            self.push_toast("Enter master password".into(), ToastKind::Error);
            return;
        }

        self.state = AppState::Unlocking(Instant::now());
        let password = self.master_password.clone();
        let vault_path = self.vault_path.clone();
        let (tx, rx) = mpsc::channel();

        thread::spawn(move || {
            let start_time = Instant::now();
            let result = match read_enc_file(&vault_path)
                .and_then(|enc| decrypt_vault(&enc, &password)) 
            {
                Ok(v) => UnlockResult::Success(v),
                Err(e) => UnlockResult::Error(format!("{}", e)),
            };
            
            let elapsed = start_time.elapsed();
            if elapsed < MINIMUM_LOAD_TIME {
                thread::sleep(MINIMUM_LOAD_TIME - elapsed);
            }
            let _ = tx.send(result);
        });
        self.unlock_receiver = Some(rx);
    }
    
    fn lock_vault(&mut self) {
        self.master_password.zeroize();
        self.master_password_confirm.zeroize();
        self.vault = Vault::default();
        self.state = if self.vault_path.exists() { AppState::Locked } else { AppState::NoVault };
        self.view_opened = Some(Instant::now());
        self.push_toast("Vault locked.".to_string(), ToastKind::Info);
        self.clipboard_clear_time = None;
        self.unlock_receiver = None;
        self.modal.zeroize_sensitive();
        self.modal = Modal::None;
        self.search_query.clear();
        self.active_category_filter = None;
        self.active_tag_filter = None;
        self.active_note_category_filter = None;
        self.active_note_tag_filter = None;
        self.notes_page_opened = None;
        self.vault_manager_opened = None;
    }

    fn add_entry_and_save(&mut self, service: String, username: String, password: String, totp_secret: Option<String>, category: Option<String>, tags: Vec<String>) {
        if service.is_empty() || username.is_empty() {
            self.push_toast("Service and username are required".into(), ToastKind::Error);
            return;
        }
        let entry = Entry {
            id: gen_id(),
            service: service.trim().to_string(),
            username: username.trim().to_string(),
            password,
            totp_secret,
            category: category.filter(|c| !c.trim().is_empty()).map(|c| c.trim().to_string()),
            tags,
            pinned: false,
            password_history: Vec::new(),
        };
        self.vault.entries.push(entry);
        
        match save_vault_file(&self.vault_path, &self.vault, &self.master_password) {
            Ok(_) => {
                self.handle_success("Entry saved successfully.");
            }
            Err(e) => self.handle_error(e),
        }
    }

    fn save_after_change(&mut self) {
        if let Err(e) = save_vault_file(&self.vault_path, &self.vault, &self.master_password) {
            self.handle_error(e);
        } else {
            self.handle_success("Vault updated.");
        }
    }

    fn add_note_and_save(&mut self, title: String, content: String, category: Option<String>, tags: Vec<String>) {
        if title.is_empty() {
            self.push_toast("Title is required".into(), ToastKind::Error);
            return;
        }
        let note = SecureNote {
            id: gen_id(),
            title: title.trim().to_string(),
            content,
            category: category.filter(|c| !c.trim().is_empty()).map(|c| c.trim().to_string()),
            tags,
        };
        self.vault.notes.push(note);
        if let Err(e) = save_vault_file(&self.vault_path, &self.vault, &self.master_password) {
            self.handle_error(e);
        } else {
            self.handle_success("Note saved.");
        }
    }
    
    fn copy_to_clipboard(&mut self, text: String, _service: String) {
            if let Ok(mut clipboard) = Clipboard::new() {
                if clipboard.set_text(text).is_ok() {
                    if let Some(secs) = self.clipboard_timeout_secs {
                        let msg = format!("Copied. Clearing clipboard in {}s.", secs);
                        self.push_toast(msg, ToastKind::Success);
                        self.clipboard_clear_time = Some(Instant::now() + Duration::from_secs(secs));
                    } else {
                        self.push_toast("Copied to clipboard.".to_string(), ToastKind::Success);
                        self.clipboard_clear_time = None;
                    }
                } else {
                    self.push_toast("Failed to copy to clipboard.".to_string(), ToastKind::Error);
                }
            } else {
                self.push_toast("Failed to access clipboard.".to_string(), ToastKind::Error);
            }
        }
    
    fn clear_clipboard_if_needed(&mut self) {
        if let Some(clear_time) = self.clipboard_clear_time {
            if Instant::now() >= clear_time {
                if let Ok(mut clipboard) = Clipboard::new() {
                    let _ = clipboard.set_text("").or_else(|_| clipboard.clear());
                    self.push_toast("Clipboard cleared.".to_string(), ToastKind::Info);
                }
                self.clipboard_clear_time = None;
            }
        }
    }
    fn to_settings(&self) -> Settings {
        Settings {
            vsync_enabled: self.vsync_enabled,
            dark_mode: self.dark_mode,
            clipboard_timeout_secs: self.clipboard_timeout_secs,
            auto_lock_enabled: self.auto_lock_enabled,
            auto_lock_timeout_mins: self.auto_lock_timeout_mins,
            lock_on_focus_loss: self.lock_on_focus_loss,
            default_password_length: self.default_password_length,
            gen_use_uppercase: self.gen_use_uppercase,
            gen_use_numbers: self.gen_use_numbers,
            gen_use_symbols: self.gen_use_symbols,
            show_passwords: self.show_passwords,
            has_seen_beta_warning: self.has_seen_beta_warning,
        }
    }
}

// - - - Modern UI Drawing Logic --- bright - - -
impl VaultGui {
    fn draw_loading_spinner(&self, ui: &mut egui::Ui, elapsed_time: f32) {
        let spinner_radius = 30.0;
        let center = ui.available_rect_before_wrap().center();
        let painter = ui.painter();
        
        // - - - Outer ring - - -
        let num_dots = 12;
        for i in 0..num_dots {
            let angle = (i as f32 / num_dots as f32) * std::f32::consts::TAU - elapsed_time * 4.0;
            let dot_pos = center + egui::vec2(spinner_radius * angle.cos(), spinner_radius * angle.sin());
            let progress = (i as f32 / num_dots as f32 + elapsed_time).fract();
            let alpha = (progress * 255.0) as u8;
            let size = 3.0 + progress * 2.0;
            painter.circle_filled(dot_pos, size, egui::Color32::from_rgba_premultiplied(100, 150, 255, alpha));
        }
    }

    fn draw_loading_view(&self, ui: &mut egui::Ui, start_time: Instant, title: &str, subtitle: &str) {
        let dm = self.dark_mode;
        ui.vertical_centered(|ui| {
            ui.add_space(120.0);
            self.draw_loading_spinner(ui, start_time.elapsed().as_secs_f32());
            ui.add_space(40.0);
            ui.label(egui::RichText::new(title).size(18.0)
                .color(if dm { egui::Color32::from_rgb(235, 235, 245) } else { egui::Color32::from_rgb(22, 19, 14) }));
            ui.add_space(8.0);
            ui.label(egui::RichText::new(subtitle).size(13.0)
                .color(if dm { egui::Color32::from_rgb(165, 165, 185) } else { egui::Color32::from_rgb(100, 94, 82) }));
        });
    }


    // - - - Get or lazily load the logo texture - - -
    fn logo_texture(&mut self, ctx: &egui::Context) -> egui::TextureHandle {
        self.logo_texture.get_or_insert_with(|| {
            let pixels: Vec<egui::Color32> = LOGO_48_RGBA
                .chunks_exact(4)
                .map(|c| egui::Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3]))
                .collect();
            let color_image = egui::ColorImage {
                size: [LOGO_48_W as usize, LOGO_48_H as usize],
                pixels,
            };
            ctx.load_texture("app_logo", color_image, egui::TextureOptions::LINEAR)
        }).clone()
    }

    fn draw_locked_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let dm = self.dark_mode;
        let c_brand   = egui::Color32::from_rgb(46, 120, 43);   // - - - #2e782b - - -
        let c_title   = if dm { egui::Color32::from_rgb(228, 228, 242) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub     = if dm { egui::Color32::from_rgb(128, 132, 162) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_card    = if dm { egui::Color32::from_rgb(20, 22, 34) } else { egui::Color32::WHITE };
        let c_bg      = if dm { egui::Color32::from_rgb(11, 12, 20) } else { egui::Color32::from_rgb(240, 238, 245) };
        let c_input   = if dm { egui::Color32::from_rgb(14, 16, 26) } else { egui::Color32::from_rgb(248, 247, 252) };
        let c_border  = if dm { egui::Color32::from_rgb(44, 48, 72) } else { egui::Color32::from_rgb(210, 205, 225) };
        let c_card_border = if dm { egui::Color32::from_rgb(38, 42, 62) } else { egui::Color32::from_rgb(218, 213, 230) };

        // - - - Animation - - -
        const ANIM_DUR: f32 = 0.4;
        let elapsed = self.view_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        if elapsed < ANIM_DUR + 0.25 { ctx.request_repaint(); }
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };

        let full_rect = ui.available_rect_before_wrap();

        // - - - Plain flat background — no texture, no glow - - -
        ui.painter().rect_filled(full_rect, 0.0, c_bg);

        let t0 = anim_t(0.0);
        let t1 = anim_t(0.06);

        ui.allocate_ui_at_rect(full_rect, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_max_width(360.0);

                let card_top_offset = full_rect.height() * 0.22 + 12.0 * (1.0 - t0);
                ui.add_space(card_top_offset);

                // - - - LOGOTYPE: drawn mark + wordmark - - -
                {
                    ui.horizontal(|ui| {
                        ui.add_space((360.0 - 120.0) / 2.0);

                        // - - - Logo image in login card header - - -
                        let logo_tex = self.logo_texture.get_or_insert_with(|| {
                            let pixels: Vec<egui::Color32> = LOGO_48_RGBA
                                .chunks_exact(4)
                                .map(|c| egui::Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3]))
                                .collect();
                            ctx.load_texture("app_logo", egui::ColorImage {
                                size: [LOGO_48_W as usize, LOGO_48_H as usize],
                                pixels,
                            }, egui::TextureOptions::LINEAR)
                        }).clone();
                        let tint = egui::Color32::from_rgba_unmultiplied(255, 255, 255, (t0 * 255.0) as u8);
                        ui.add(egui::Image::new(&logo_tex)
                            .fit_to_exact_size(egui::vec2(24.0, 26.0))
                            .tint(tint));
                        ui.add_space(8.0);
                        ui.label(egui::RichText::new("ZeroPass")
                            .size(17.0).strong()
                            .color(fc(c_title, t0)));
                    });
                }

                ui.add_space(24.0);

                // - - - LOGIN CARD - - -
                let card_frame = egui::Frame::none()
                    .fill(fc(c_card, t1))
                    .rounding(14.0)
                    .inner_margin(egui::Margin::symmetric(30.0, 28.0))
                    .stroke(egui::Stroke::new(1.0, fc(c_card_border, t1)));

                card_frame.show(ui, |ui| {
                    ui.set_min_width(300.0);

                    // - - - Card heading - - -
                    ui.label(egui::RichText::new("Unlock your vault")
                        .size(17.0).strong().color(fc(c_title, t1)));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Enter your master password to continue.")
                        .size(12.0).color(fc(c_sub, t1)));

                    ui.add_space(22.0);

                    // - - - Field with brand green focus ring - - -
                    let pw_id = egui::Id::new("pw_field");
                    let pw_focused = ctx.memory(|m| m.focused() == Some(pw_id));
                    let stroke_col = if pw_focused { c_brand } else { c_border };
                    let stroke_w   = if pw_focused { 2.0 } else { 1.5 };
                    egui::Frame::none()
                        .fill(fc(c_input, t1))
                        .rounding(9.0)
                        .stroke(egui::Stroke::new(stroke_w, fc(stroke_col, t1)))
                        .inner_margin(egui::Margin { left: 13.0, right: 13.0, top: 11.0, bottom: 11.0 })
                        .show(ui, |ui| {
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut self.master_password)
                                    .id(pw_id)
                                    .password(true)
                                    .hint_text("Master password")
                                    .desired_width(ui.available_width())
                                    .frame(false)
                            );
                            if resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.unlock_vault();
                            }
                        });

                    ui.add_space(16.0);

                    // - - - Unlock button in brand green - - -
                    let can_unlock = !self.master_password.is_empty();
                    let btn_fill = if can_unlock {
                        fc(c_brand, t1)
                    } else {
                        fc(if dm { egui::Color32::from_rgb(36, 40, 54) } else { egui::Color32::from_rgb(200, 196, 188) }, t1)
                    };
                    let btn_txt_col = if can_unlock { egui::Color32::WHITE } else {
                        if dm { egui::Color32::from_rgb(80, 84, 105) } else { egui::Color32::from_rgb(150, 146, 138) }
                    };
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 44.0),
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("Unlock").size(14.0).strong()
                                    .color(fc(btn_txt_col, t1))
                            ).fill(btn_fill).rounding(9.0);
                            if ui.add_enabled(can_unlock, btn).clicked() {
                                self.unlock_vault();
                            }
                        }
                    );
                });

                // - - - Single understated trust line instead of three loud badges - - -
                ui.add_space(18.0);
                ui.label(egui::RichText::new("Encrypted locally with XChaCha20-Poly1305")
                    .size(10.5).color(fc(c_sub, anim_t(0.18))));
            });
        });
    }

    fn draw_no_vault_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let dm        = self.dark_mode;
        let c_brand   = egui::Color32::from_rgb(46, 120, 43);
        let c_title   = if dm { egui::Color32::from_rgb(228, 228, 242) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub     = if dm { egui::Color32::from_rgb(128, 132, 162) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_card    = if dm { egui::Color32::from_rgb(20, 22, 34) }    else { egui::Color32::WHITE };
        let c_bg      = if dm { egui::Color32::from_rgb(11, 12, 20) }    else { egui::Color32::from_rgb(240, 238, 245) };
        let c_input   = if dm { egui::Color32::from_rgb(14, 16, 26) }    else { egui::Color32::from_rgb(248, 247, 252) };
        let c_border  = if dm { egui::Color32::from_rgb(44, 48, 72) }    else { egui::Color32::from_rgb(210, 205, 225) };
        let c_card_border = if dm { egui::Color32::from_rgb(38, 42, 62) } else { egui::Color32::from_rgb(218, 213, 230) };

        // - - - Animation (same timing as login screen) - - -
        const ANIM_DUR: f32 = 0.4;
        let elapsed = self.view_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth  = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t  = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_DUR + 0.25 { ctx.request_repaint(); }

        let t0 = anim_t(0.0);
        let t1 = anim_t(0.06);

        let full_rect = ui.available_rect_before_wrap();

        // - - - Plain flat background — no texture, no glow - - -
        ui.painter().rect_filled(full_rect, 0.0, c_bg);

        ui.allocate_ui_at_rect(full_rect, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_max_width(360.0);

                let card_top_offset = full_rect.height() * 0.16 + 12.0 * (1.0 - t0);
                ui.add_space(card_top_offset);

                // - - - LOGOTYPE (same as login) - - -
                ui.horizontal(|ui| {
                    ui.add_space((360.0 - 120.0) / 2.0);
                    let logo_tex = self.logo_texture.get_or_insert_with(|| {
                        let pixels: Vec<egui::Color32> = LOGO_48_RGBA
                            .chunks_exact(4)
                            .map(|c| egui::Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3]))
                            .collect();
                        ctx.load_texture("app_logo", egui::ColorImage {
                            size: [LOGO_48_W as usize, LOGO_48_H as usize],
                            pixels,
                        }, egui::TextureOptions::LINEAR)
                    }).clone();
                    let tint = egui::Color32::from_rgba_unmultiplied(255, 255, 255, (t0 * 255.0) as u8);
                    ui.add(egui::Image::new(&logo_tex)
                        .fit_to_exact_size(egui::vec2(24.0, 26.0))
                        .tint(tint));
                    ui.add_space(8.0);
                    ui.label(egui::RichText::new("ZeroPass")
                        .size(17.0).strong()
                        .color(fc(c_title, t0)));
                });

                ui.add_space(24.0);

                // - - - CARD (same frame style as login) - - -
                let card_frame = egui::Frame::none()
                    .fill(fc(c_card, t1))
                    .rounding(14.0)
                    .inner_margin(egui::Margin::symmetric(30.0, 28.0))
                    .stroke(egui::Stroke::new(1.0, fc(c_card_border, t1)));

                card_frame.show(ui, |ui| {
                    ui.set_min_width(300.0);

                    // - - - Card heading - - -
                    ui.label(egui::RichText::new("Create your vault")
                        .size(17.0).strong().color(fc(c_title, t1)));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Choose a master password — it encrypts everything.")
                        .size(12.0).color(fc(c_sub, t1)));

                    ui.add_space(22.0);

                    // - - - Password field - - -
                    let pw_id = egui::Id::new("create_pw_field");
                    let pw_focused = ctx.memory(|m| m.focused() == Some(pw_id));
                    let stroke_col = if pw_focused { c_brand } else { c_border };
                    let stroke_w   = if pw_focused { 2.0 } else { 1.5 };
                    egui::Frame::none()
                        .fill(fc(c_input, t1))
                        .rounding(9.0)
                        .stroke(egui::Stroke::new(stroke_w, fc(stroke_col, t1)))
                        .inner_margin(egui::Margin { left: 13.0, right: 13.0, top: 11.0, bottom: 11.0 })
                        .show(ui, |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.master_password)
                                    .id(pw_id)
                                    .password(true)
                                    .hint_text("Master password")
                                    .desired_width(ui.available_width())
                                    .frame(false)
                            );
                        });

                    ui.add_space(10.0);

                    // - - - Confirm password field - - -
                    let mismatch = !self.master_password.is_empty()
                        && !self.master_password_confirm.is_empty()
                        && self.master_password != self.master_password_confirm;
                    let confirm_id = egui::Id::new("create_pw_confirm_field");
                    let confirm_focused = ctx.memory(|m| m.focused() == Some(confirm_id));
                    let confirm_stroke_col = if mismatch {
                        egui::Color32::from_rgb(200, 80, 80)
                    } else if confirm_focused { c_brand } else { c_border };
                    let confirm_stroke_w = if confirm_focused || mismatch { 2.0 } else { 1.5 };
                    egui::Frame::none()
                        .fill(fc(c_input, t1))
                        .rounding(9.0)
                        .stroke(egui::Stroke::new(confirm_stroke_w, fc(confirm_stroke_col, t1)))
                        .inner_margin(egui::Margin { left: 13.0, right: 13.0, top: 11.0, bottom: 11.0 })
                        .show(ui, |ui| {
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut self.master_password_confirm)
                                    .id(confirm_id)
                                    .password(true)
                                    .hint_text("Confirm master password")
                                    .desired_width(ui.available_width())
                                    .frame(false)
                            );
                            if resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.create_new_vault();
                            }
                        });

                    // - - - Strength / match hint - - -
                    if mismatch {
                        ui.add_space(6.0);
                        ui.label(egui::RichText::new("Passwords don't match")
                            .size(11.0).color(fc(egui::Color32::from_rgb(200, 80, 80), t1)));
                    } else if !self.master_password.is_empty() {
                        ui.add_space(6.0);
                        let len = self.master_password.len();
                        let (hint, hint_col) = if len < 8 {
                            ("Too short — use at least 8 characters", egui::Color32::from_rgb(200, 80, 80))
                        } else if len < 12 {
                            ("Fair — consider a longer passphrase", egui::Color32::from_rgb(200, 150, 40))
                        } else {
                            ("Strong password", c_brand)
                        };
                        ui.label(egui::RichText::new(hint).size(11.0).color(fc(hint_col, t1)));
                    }

                    ui.add_space(14.0);

                    // - - - Create button in brand green - - -
                    let can_create = self.master_password.len() >= 8
                        && self.master_password == self.master_password_confirm;
                    let btn_fill = if can_create {
                        fc(c_brand, t1)
                    } else {
                        fc(if dm { egui::Color32::from_rgb(36, 40, 54) } else { egui::Color32::from_rgb(200, 196, 188) }, t1)
                    };
                    let btn_txt_col = if can_create { egui::Color32::WHITE } else {
                        if dm { egui::Color32::from_rgb(80, 84, 105) } else { egui::Color32::from_rgb(150, 146, 138) }
                    };
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 44.0),
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("Create Vault").size(14.0).strong()
                                    .color(fc(btn_txt_col, t1))
                            ).fill(btn_fill).rounding(9.0);
                            if ui.add_enabled(can_create, btn).clicked() {
                                self.create_new_vault();
                            }
                        }
                    );
                });

                // - - - Single understated trust line instead of three loud badges - - -
                ui.add_space(18.0);
                ui.label(egui::RichText::new("Encrypted locally with XChaCha20-Poly1305")
                    .size(10.5).color(fc(c_sub, anim_t(0.18))));
            });
        });
    }

    fn draw_unlocked_view(&mut self, ui: &mut egui::Ui) {
        let dm = self.dark_mode;
        let accent     = egui::Color32::from_rgb(99, 111, 245);
        let green      = egui::Color32::from_rgb(46, 120, 43);   // - - - #2e782b brand green - - -
        let c_title   = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub     = if dm { egui::Color32::from_rgb(160, 162, 185) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_card    = if dm { egui::Color32::from_rgb(28, 31, 44)  } else { egui::Color32::WHITE };
        let c_border  = if dm { egui::Color32::from_rgb(62, 68, 95)  } else { egui::Color32::from_rgb(210, 205, 225) };
        let c_input   = if dm { egui::Color32::from_rgb(13, 14, 21)  } else { egui::Color32::from_rgb(243, 241, 250) };

        // - - - Animation — bar + search slide in as one block, entries stagger per-card - - -
        const ANIM_DUR: f32 = 0.40;
        const SLIDE_PX: f32 = 22.0;
        let elapsed = self.view_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_DUR + 0.5 { ui.ctx().request_repaint(); }

        // - - - HEADER ROW: title + entry count + new entry button - - -
        let t_bar = anim_t(0.0);
        ui.add_space(4.0 + 16.0 * (1.0 - t_bar));
        ui.horizontal(|ui| {
            let alpha = (t_bar * 255.0) as u8;
            ui.label(egui::RichText::new("Passwords").size(20.0).strong()
                .color(egui::Color32::from_rgba_unmultiplied(c_title.r(), c_title.g(), c_title.b(), alpha)));
            let count = self.vault.entries.len();
            let badge_bg = if dm { egui::Color32::from_rgb(42, 46, 68) } else { egui::Color32::from_rgb(224, 222, 248) };
            let badge_txt = if dm { egui::Color32::from_rgb(170, 178, 245) } else { accent };
            ui.add_space(6.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgba_unmultiplied(badge_bg.r(), badge_bg.g(), badge_bg.b(), alpha))
                .rounding(10.0)
                .inner_margin(egui::Margin { left: 7.0, right: 7.0, top: 3.0, bottom: 3.0 })
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(format!("{}", count)).size(11.0).strong()
                        .color(egui::Color32::from_rgba_unmultiplied(badge_txt.r(), badge_txt.g(), badge_txt.b(), alpha)));
                });
        });

        // - - - SEARCH BAR - - -
        let t_search = anim_t(0.06);
        ui.add_space(14.0 + 12.0 * (1.0 - t_search));

        let search_alpha = (t_search * 255.0) as u8;
        let search_frame = egui::Frame::none()
            .fill(egui::Color32::from_rgba_unmultiplied(c_input.r(), c_input.g(), c_input.b(), search_alpha))
            .rounding(10.0)
            .inner_margin(egui::Margin { left: 12.0, right: 12.0, top: 9.0, bottom: 9.0 })
            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(c_border.r(), c_border.g(), c_border.b(), search_alpha)));

        search_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🔍").size(13.0)
                    .color(egui::Color32::from_rgba_unmultiplied(c_sub.r(), c_sub.g(), c_sub.b(), search_alpha)));
                ui.add_space(6.0);
                ui.add(egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Search…")
                    .desired_width(ui.available_width())
                    .frame(false));
            });
        });

        ui.add_space(16.0);

        // - - - ENTRIES LIST — each card staggered, with drag-to-reorder - - -
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            let mut to_remove_id: Option<String> = None;
            let search_lower = self.search_query.to_lowercase();
            let is_searching = !search_lower.is_empty();

            // - - - Build an index list of matching entries in the vault (we keep vault indices for reordering) - - -
            let mut filtered_indices: Vec<usize> = self.vault.entries.iter()
                .enumerate()
                .filter(|(_, e)| {
                    // - - - Text search across service, username, category, tags - - -
                    let text_match = search_lower.is_empty()
                        || e.service.to_lowercase().contains(&search_lower)
                        || e.username.to_lowercase().contains(&search_lower)
                        || e.category.as_deref().unwrap_or("").to_lowercase().contains(&search_lower)
                        || e.tags.iter().any(|t| t.to_lowercase().contains(&search_lower));
                    // - - - Category sidebar filter - - -
                    let cat_match = self.active_category_filter.as_ref()
                        .map_or(true, |f| e.category.as_deref() == Some(f.as_str()));
                    // - - - Tag sidebar filter - - -
                    let tag_match = self.active_tag_filter.as_ref()
                        .map_or(true, |f| e.tags.iter().any(|t| t == f));
                    text_match && cat_match && tag_match
                })
                .map(|(i, _)| i)
                .collect();

            // - - - Pinned entries float to the top; relative order otherwise preserved - - -
            // - - - (skipped while actively dragging so reordering isn't fought by re-sorting) - - -
            if self.drag_source_idx.is_none() {
                filtered_indices.sort_by_key(|&i| !self.vault.entries[i].pinned);
            }

            if filtered_indices.is_empty() {
                let t_empty = anim_t(0.12);
                ui.add_space(SLIDE_PX * (1.0 - t_empty));
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    let empty_icon_col = if dm { egui::Color32::WHITE } else { egui::Color32::from_rgb(150, 150, 175) };
                    ui.label(egui::RichText::new("🔍").size(44.0).color(fc(empty_icon_col, t_empty)));
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("No entries found").size(15.0).color(fc(c_sub, t_empty)));
                    if !self.search_query.is_empty() {
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Try a different search term").size(12.0)
                            .color(fc(if dm { egui::Color32::from_rgb(115, 115, 138) } else { egui::Color32::from_rgb(130, 124, 112) }, t_empty)));
                    }
                });
            }

            // - - - Update pointer Y every frame while dragging - - -
            if self.drag_source_idx.is_some() {
                if let Some(pos) = ui.input(|i| i.pointer.hover_pos()) {
                    self.drag_pointer_y = pos.y;
                }
                // - - - Reset target each frame so we re-pick the best one below - - -
                self.drag_target_idx = None;
                ui.ctx().request_repaint();
            }

            // - - - Request repaint each frame while hovered for smooth hover effects - - -
            ui.ctx().request_repaint_after(Duration::from_millis(50));

            let mut drop_happened = false;

            for (list_pos, &vault_idx) in filtered_indices.iter().enumerate() {
                let entry = self.vault.entries[vault_idx].clone();

                let t_card = anim_t(0.12 + list_pos as f32 * 0.04);
                ui.add_space(SLIDE_PX * (1.0 - t_card));

                // - - - Determine visual state for this card - - -
                let is_dragged = self.drag_source_idx == Some(vault_idx);
                let is_drop_target = !is_dragged && self.drag_source_idx.is_some()
                    && self.drag_target_idx == Some(vault_idx);

                // - - - Draw a drop indicator line above this card when it is the drop target - - -
                if is_drop_target {
                    let cursor = ui.cursor();
                    let line_y = cursor.top() - 2.0;
                    let x_range = egui::Rangef::new(
                        ui.available_rect_before_wrap().left(),
                        ui.available_rect_before_wrap().right(),
                    );
                    ui.painter().hline(x_range, line_y, egui::Stroke::new(2.0, accent));
                }

                let alpha_mult = if is_dragged { 0.5 } else { 1.0 };
                let fc_a = |base: egui::Color32, t: f32| -> egui::Color32 {
                    egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0 * alpha_mult) as u8)
                };

                let card_bg = fc_a(c_card, t_card);
                let card_border_col = fc_a(c_border, t_card);
                let card = egui::Frame::none()
                    .fill(card_bg)
                    .rounding(12.0)
                    .stroke(egui::Stroke::new(1.0, card_border_col))
                    .inner_margin(egui::Margin { left: 12.0, right: 10.0, top: 11.0, bottom: 11.0 });

                let card_resp = card.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        // - - - Drag handle - - -
                        if !is_searching {
                            let (handle_rect, handle_resp) = ui.allocate_exact_size(
                                egui::vec2(10.0, 40.0),
                                egui::Sense::drag(),
                            );

                            if handle_resp.drag_started() {
                                self.drag_source_idx = Some(vault_idx);
                                self.drag_pointer_y = ui.input(|i| i.pointer.hover_pos().map(|p| p.y).unwrap_or(0.0));
                            }
                            if handle_resp.drag_stopped() && self.drag_source_idx.is_some() {
                                drop_happened = true;
                            }
                            if handle_resp.hovered() || handle_resp.dragged() {
                                ui.ctx().set_cursor_icon(egui::CursorIcon::Grab);
                            }

                            // - - - Draw dots — stored for later so we know if hovered - - -
                            let cx = handle_rect.center().x;
                            for row in 0..3 {
                                let y = handle_rect.top() + 11.0 + row as f32 * 7.0;
                                for col in 0..2 {
                                    let x = cx - 2.0 + col as f32 * 4.0;
                                    // - - - Will tint after we know hovered state - - -
                                    ui.painter().circle_filled(egui::pos2(x, y), 1.1,
                                        fc_a(if dm { egui::Color32::from_rgb(70, 76, 108) } else { egui::Color32::from_rgb(190, 185, 175) }, t_card));
                                }
                            }
                            ui.add_space(8.0);
                        }

                        // - - - Initial avatar: rounded square, not a circle - - -
                        let first_char = entry.service.chars().next().unwrap_or('?').to_uppercase().to_string();
                        let avatar_size = 36.0;
                        // - - - Deterministic hue from service name for variety - - -
                        let hue_seed = entry.service.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32));
                        let hues = [
                            (99u8, 111u8, 245u8),   // indigo
                            (55,  168,  90),          // green
                            (230, 100,  80),          // coral
                            (80,  180, 220),          // sky
                            (180, 100, 220),          // purple
                            (240, 160,  50),          // amber
                        ];
                        let (hr, hg, hb) = hues[(hue_seed as usize) % hues.len()];
                        let avatar_col = fc_a(egui::Color32::from_rgb(hr, hg, hb), t_card);
                        let avatar_bg  = fc_a(egui::Color32::from_rgba_unmultiplied(hr, hg, hb, if dm { 35 } else { 28 }), t_card);

                        let (avatar_rect, _) = ui.allocate_exact_size(egui::vec2(avatar_size, avatar_size), egui::Sense::hover());
                        ui.painter().rect_filled(avatar_rect, 8.0, avatar_bg);
                        ui.painter().text(
                            avatar_rect.center(), egui::Align2::CENTER_CENTER, &first_char,
                            egui::FontId::proportional(15.0), avatar_col,
                        );
                        ui.add_space(10.0);

                        ui.vertical(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(truncate_display(&entry.service, 40)).size(15.0).strong().color(fc_a(c_title, t_card)));
                                if entry.pinned {
                                    ui.add_space(5.0);
                                    let pin_col = fc_a(egui::Color32::from_rgb(240, 180, 50), t_card);
                                    ui.label(egui::RichText::new("📌").size(10.5).color(pin_col));
                                }
                            });
                            ui.add_space(2.0);
                            ui.label(egui::RichText::new(truncate_display(&entry.username, 48)).size(12.0).color(fc_a(c_sub, t_card)));
                            // - - - Category & tags row - - -
                            let has_cat  = entry.category.as_deref().map_or(false, |c| !c.is_empty());
                            let has_tags = !entry.tags.is_empty();
                            if has_cat || has_tags {
                                ui.add_space(4.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    if let Some(cat) = &entry.category {
                                        if !cat.is_empty() {
                                            let cat_bg = if dm { egui::Color32::from_rgb(36, 40, 68) } else { egui::Color32::from_rgb(228, 225, 252) };
                                            let cat_txt = if dm { egui::Color32::from_rgb(155, 165, 245) } else { egui::Color32::from_rgb(80, 72, 200) };
                                            egui::Frame::none()
                                                .fill(fc_a(cat_bg, t_card))
                                                .rounding(6.0)
                                                .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new(format!("📁 {}", truncate_display(cat, 20))).size(10.0).color(fc_a(cat_txt, t_card)));
                                                });
                                        }
                                    }
                                    for tag in &entry.tags {
                                        if !tag.is_empty() {
                                            let tag_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                            let tag_txt = if dm { egui::Color32::from_rgb(90, 190, 120) } else { egui::Color32::from_rgb(32, 128, 60) };
                                            egui::Frame::none()
                                                .fill(fc_a(tag_bg, t_card))
                                                .rounding(6.0)
                                                .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new(format!("🏷 {}", truncate_display(tag, 20))).size(10.0).color(fc_a(tag_txt, t_card)));
                                                });
                                        }
                                    }
                                });
                            }
                            if self.show_passwords {
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(&entry.password).size(10.5)
                                    .color(fc_a(if dm { egui::Color32::from_rgb(120, 195, 120) } else { egui::Color32::from_rgb(35, 128, 58) }, t_card))
                                    .monospace());
                            }
                            // - - - TOTP live code - - -
                            if let Some(ref secret) = entry.totp_secret {
                                if let Some((code, secs)) = totp_now(secret) {
                                    ui.add_space(4.0);
                                    let totp_col = fc_a(egui::Color32::from_rgb(120, 160, 255), t_card);
                                    let countdown_col = fc_a(if secs <= 5 {
                                        egui::Color32::from_rgb(230, 100, 80)
                                    } else {
                                        c_sub
                                    }, t_card);
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("🔒").size(11.0));
                                        ui.add_space(3.0);
                                        let code_btn = egui::Button::new(
                                            egui::RichText::new(&code).size(13.0).strong().monospace().color(totp_col)
                                        )
                                        .fill(egui::Color32::TRANSPARENT)
                                        .stroke(egui::Stroke::NONE)
                                        .rounding(4.0);
                                        if ui.add(code_btn).on_hover_text("Click to copy TOTP code").clicked() {
                                            self.copy_to_clipboard(code.clone(), entry.service.clone());
                                        }
                                        // - - - Countdown ring drawn manually - - -
                                        let (ring_rect, _) = ui.allocate_exact_size(egui::vec2(22.0, 18.0), egui::Sense::hover());
                                        let rc = ring_rect.center();
                                        let r = 7.0_f32;
                                        let progress = secs as f32 / 30.0;
                                        // - - - Background ring - - -
                                        ui.painter().circle_stroke(rc, r, egui::Stroke::new(2.0, fc_a(c_border, t_card)));
                                        // - - - Foreground arc — approximate with line segments - - -
                                        let arc_col = if secs <= 5 {
                                            fc_a(egui::Color32::from_rgb(230, 100, 80), t_card)
                                        } else {
                                            fc_a(egui::Color32::from_rgb(120, 160, 255), t_card)
                                        };
                                        let segments = 32;
                                        let _sweep = progress * std::f32::consts::TAU;
                                        let start = -std::f32::consts::FRAC_PI_2;
                                        let mut prev = egui::pos2(rc.x + r * start.cos(), rc.y + r * start.sin());
                                        for i in 1..=segments {
                                            let frac = i as f32 / segments as f32;
                                            if frac > progress { break; }
                                            let angle = start + frac * std::f32::consts::TAU;
                                            let next = egui::pos2(rc.x + r * angle.cos(), rc.y + r * angle.sin());
                                            ui.painter().line_segment([prev, next], egui::Stroke::new(2.0, arc_col));
                                            prev = next;
                                        }
                                        ui.add_space(2.0);
                                        ui.label(egui::RichText::new(format!("{}s", secs)).size(10.5).color(countdown_col));
                                    });
                                    ui.ctx().request_repaint_after(Duration::from_secs(1));
                                }
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // - - - Delete - - -
                            let del_col = if dm { egui::Color32::from_rgb(215, 80, 80) } else { egui::Color32::from_rgb(190, 50, 50) };
                            let del_btn = egui::Button::new(
                                egui::RichText::new("🗑").size(12.0).color(fc_a(del_col, t_card))
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::NONE)
                            .rounding(6.0)
                            .min_size(egui::vec2(28.0, 28.0));
                            if ui.add(del_btn).on_hover_text("Delete").clicked() {
                                to_remove_id = Some(entry.id.clone());
                            }

                            // - - - Edit - - -
                            let edit_btn = egui::Button::new(
                                egui::RichText::new("✏").size(12.0).color(fc_a(c_sub, t_card))
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::NONE)
                            .rounding(6.0)
                            .min_size(egui::vec2(28.0, 28.0));
                            if ui.add(edit_btn).on_hover_text("Edit").clicked() {
                                self.modal = Modal::EditEntry {
                                    original_id: entry.id.clone(),
                                    service: entry.service.clone(),
                                    username: entry.username.clone(),
                                    password: entry.password.clone(),
                                    totp_secret: entry.totp_secret.clone().unwrap_or_default(),
                                    totp_open: entry.totp_secret.is_some(),
                                    category: entry.category.clone().unwrap_or_default(),
                                    tags: entry.tags.join(", "),
                                };
                            }

                            // - - - History (only shown once there's something to show) - - -
                            if !entry.password_history.is_empty() {
                                let hist_btn = egui::Button::new(
                                    egui::RichText::new("🕘").size(12.0).color(fc_a(c_sub, t_card))
                                )
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::NONE)
                                .rounding(6.0)
                                .min_size(egui::vec2(28.0, 28.0));
                                if ui.add(hist_btn).on_hover_text("Password history").clicked() {
                                    self.modal = Modal::PasswordHistory { entry_id: entry.id.clone() };
                                }
                            }

                            // - - - Pin / favorite toggle - - -
                            let pin_active_col = egui::Color32::from_rgb(240, 180, 50);
                            let pin_col = if entry.pinned { fc_a(pin_active_col, t_card) } else { fc_a(c_sub, t_card) };
                            let pin_btn = egui::Button::new(
                                egui::RichText::new(if entry.pinned { "★" } else { "☆" }).size(13.0).color(pin_col)
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::NONE)
                            .rounding(6.0)
                            .min_size(egui::vec2(28.0, 28.0));
                            if ui.add(pin_btn).on_hover_text(if entry.pinned { "Unpin" } else { "Pin to top" }).clicked() {
                                if let Some(e) = self.vault.entries.iter_mut().find(|e| e.id == entry.id) {
                                    e.pinned = !e.pinned;
                                }
                                self.save_after_change();
                            }

                            ui.add_space(4.0);

                            // - - - Copy password — accent pill - - -
                            let copy_bg = if dm {
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, 30)
                            } else {
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, 18)
                            };
                            let copy_btn = egui::Button::new(
                                egui::RichText::new("Copy").size(11.5).color(fc_a(accent, t_card))
                            )
                            .fill(fc_a(copy_bg, t_card))
                            .stroke(egui::Stroke::new(1.0, fc_a(
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, 60), t_card)))
                            .rounding(7.0)
                            .min_size(egui::vec2(48.0, 28.0));
                            if ui.add(copy_btn).on_hover_text("Copy password").clicked() {
                                self.copy_to_clipboard(entry.password.clone(), entry.service.clone());
                            }
                        });
                    });
                });

                // - - - Paint hover/drag bg AFTER show() so rect is known - - -
                let row_hovered = card_resp.response.hovered();
                if row_hovered && !is_dragged {
                    ui.painter().rect_filled(
                        card_resp.response.rect,
                        10.0,
                        if dm { egui::Color32::from_rgba_unmultiplied(255, 255, 255, 7) }
                        else   { egui::Color32::from_rgba_unmultiplied(0, 0, 0, 6) },
                    );
                }
                if is_dragged {
                    ui.painter().rect_filled(
                        card_resp.response.rect,
                        10.0,
                        if dm { egui::Color32::from_rgb(30, 34, 54) } else { egui::Color32::from_rgb(240, 238, 255) },
                    );
                }

                if let Some(src) = self.drag_source_idx {
                    if src != vault_idx {
                        let card_rect = card_resp.response.rect;
                        let card_mid_y = card_rect.center().y;
                        // - - - "Insert before this card" when pointer is above its midpoint. - - -
                        // - - - Because we reset drag_target_idx before the loop and iterate - - -
                        // - - - top-to-bottom, the first time this triggers we record the target - - -
                        // - - - (and don't overwrite again thanks to the is_none() guard). - - -
                        if self.drag_pointer_y <= card_mid_y && self.drag_target_idx.is_none() {
                            self.drag_target_idx = Some(vault_idx);
                        }
                        // - - - When the pointer is below ALL card midpoints, fall through to the - - -
                        // - - - "insert at end" fallback after the loop. - - -
                    }
                }

                // - - - Gap between cards (border on each card replaces old hairline divider) - - -
                ui.add_space(6.0);
            }

            // - - - "Insert at end" — pointer is below all card midpoints; use usize::MAX as sentinel - - -
            if self.drag_source_idx.is_some() && self.drag_target_idx.is_none() && !filtered_indices.is_empty() {
                self.drag_target_idx = Some(usize::MAX);
                // - - - Draw the drop line at the very bottom of the list - - -
                let cursor = ui.cursor();
                let line_y = cursor.top() - 2.0;
                let x_range = egui::Rangef::new(
                    ui.available_rect_before_wrap().left(),
                    ui.available_rect_before_wrap().right(),
                );
                ui.painter().hline(x_range, line_y, egui::Stroke::new(2.5, accent));
            }

            // - - - Commit drop - - -
            if drop_happened {
                if let Some(src_vault_idx) = self.drag_source_idx {
                    let n = self.vault.entries.len();
                    if src_vault_idx < n {
                        let tgt = self.drag_target_idx.unwrap_or(usize::MAX);
                        if tgt == usize::MAX {
                            // - - - Move to end - - -
                            let entry = self.vault.entries.remove(src_vault_idx);
                            self.vault.entries.push(entry);
                        } else if tgt < n && tgt != src_vault_idx {
                            let entry = self.vault.entries.remove(src_vault_idx);
                            let insert_at = if tgt > src_vault_idx { tgt - 1 } else { tgt };
                            self.vault.entries.insert(insert_at, entry);
                        }
                        self.save_after_change();
                    }
                }
                self.drag_source_idx = None;
                self.drag_target_idx = None;
            }

            if let Some(id) = to_remove_id {
                self.vault.entries.retain(|e| e.id != id);
                self.save_after_change();
            }
        });
    }

    fn draw_notes_view(&mut self, ui: &mut egui::Ui) {
        let dm = self.dark_mode;
        let accent    = egui::Color32::from_rgb(99, 111, 245);
        let green     = egui::Color32::from_rgb(66, 153, 54);
        let c_title   = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub     = if dm { egui::Color32::from_rgb(160, 162, 185) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_card    = if dm { egui::Color32::from_rgb(28, 31, 44)  } else { egui::Color32::WHITE };
        let c_border  = if dm { egui::Color32::from_rgb(62, 68, 95)  } else { egui::Color32::from_rgb(210, 205, 225) };
        let red_col   = egui::Color32::from_rgb(210, 60, 60);

        // - - - Animation - - -
        const ANIM_DUR: f32 = 0.40;
        const SLIDE_PX: f32 = 22.0;
        let elapsed = self.notes_page_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_DUR + 0.5 { ui.ctx().request_repaint(); }

        // - - - Header - - -
        // - - - Compute count label before drawing (needs to be in scope for badge) - - -
        let note_total = self.vault.notes.len();
        let is_notes_filtered = self.active_note_category_filter.is_some() || self.active_note_tag_filter.is_some();
        let note_filtered_count = if is_notes_filtered {
            self.vault.notes.iter().filter(|n| {
                let cm = self.active_note_category_filter.as_ref().map_or(true, |f| n.category.as_deref() == Some(f.as_str()));
                let tm = self.active_note_tag_filter.as_ref().map_or(true, |f| n.tags.iter().any(|t| t == f));
                cm && tm
            }).count()
        } else { note_total };
        let count_label = if is_notes_filtered {
            format!("{}/{}", note_filtered_count, note_total)
        } else {
            format!("{}", note_total)
        };

        let t_bar = anim_t(0.0);
        ui.add_space(4.0 + SLIDE_PX * (1.0 - t_bar));
        ui.horizontal(|ui| {
            let alpha = (t_bar * 255.0) as u8;
            ui.label(egui::RichText::new("Secure Notes").size(20.0).strong()
                .color(egui::Color32::from_rgba_unmultiplied(c_title.r(), c_title.g(), c_title.b(), alpha)));
            let badge_bg  = if dm { egui::Color32::from_rgb(40, 44, 30) } else { egui::Color32::from_rgb(220, 248, 228) };
            let badge_txt = if dm { egui::Color32::from_rgb(140, 195, 100) } else { egui::Color32::from_rgb(50, 130, 50) };
            ui.add_space(6.0);
            egui::Frame::none()
                .fill(egui::Color32::from_rgba_unmultiplied(badge_bg.r(), badge_bg.g(), badge_bg.b(), alpha))
                .rounding(10.0)
                .inner_margin(egui::Margin { left: 7.0, right: 7.0, top: 3.0, bottom: 3.0 })
                .show(ui, |ui| {
                    ui.label(egui::RichText::new(&count_label).size(11.0).strong()
                        .color(egui::Color32::from_rgba_unmultiplied(badge_txt.r(), badge_txt.g(), badge_txt.b(), alpha)));
                });
            // - - - "encrypted" pill — reinforces security at a glance - - -
            ui.add_space(6.0);
            let enc_bg  = if dm { egui::Color32::from_rgba_unmultiplied(44, 52, 88, alpha) } else { egui::Color32::from_rgba_unmultiplied(230, 228, 255, alpha) };
            let enc_txt = if dm { egui::Color32::from_rgba_unmultiplied(170, 178, 245, alpha) } else { egui::Color32::from_rgba_unmultiplied(88, 101, 242, alpha) };
            egui::Frame::none().fill(enc_bg).rounding(8.0)
                .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 2.0, bottom: 2.0 })
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("🔐 encrypted").size(10.0).color(enc_txt));
                });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let add_btn = egui::Button::new(
                    egui::RichText::new("➕  New Note").size(12.5).color(egui::Color32::WHITE)
                ).fill(egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), alpha))
                .rounding(8.0).min_size(egui::vec2(100.0, 28.0));
                if ui.add(add_btn).clicked() {
                    self.modal = Modal::AddNote {
                        title: String::new(), content: String::new(),
                        category: String::new(), tags: String::new(),
                    };
                }
            });
        });

        ui.add_space(20.0);

        // - - - Notes list - - -
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            let mut to_remove_id: Option<String> = None;
            let notes: Vec<SecureNote> = self.vault.notes.iter().filter(|n| {
                let cat_match = self.active_note_category_filter.as_ref()
                    .map_or(true, |f| n.category.as_deref() == Some(f.as_str()));
                let tag_match = self.active_note_tag_filter.as_ref()
                    .map_or(true, |f| n.tags.iter().any(|t| t == f));
                cat_match && tag_match
            }).cloned().collect();

            let is_filtered = self.active_note_category_filter.is_some() || self.active_note_tag_filter.is_some();
            let _ = self.vault.notes.len(); // - - - keep borrow checker happy - - -

            if notes.is_empty() {
                let t_empty = anim_t(0.12);
                ui.add_space(SLIDE_PX * (1.0 - t_empty));
                ui.vertical_centered(|ui| {
                    ui.add_space(60.0);
                    if is_filtered {
                        ui.label(egui::RichText::new("🔍").size(44.0).color(fc(
                            if dm { egui::Color32::WHITE } else { egui::Color32::from_rgb(150, 150, 175) }, t_empty)));
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("No notes match this filter").size(15.0).color(fc(c_sub, t_empty)));
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Try a different category or tag").size(12.0)
                            .color(fc(if dm { egui::Color32::from_rgb(115, 115, 138) } else { egui::Color32::from_rgb(130, 124, 112) }, t_empty)));
                    } else {
                        ui.label(egui::RichText::new("📝").size(44.0).color(fc(
                            if dm { egui::Color32::WHITE } else { egui::Color32::from_rgb(150, 150, 175) }, t_empty)));
                        ui.add_space(10.0);
                        ui.label(egui::RichText::new("No notes yet").size(15.0).color(fc(c_sub, t_empty)));
                        ui.add_space(4.0);
                        ui.label(egui::RichText::new("Click ➕ New Note to get started").size(12.0)
                            .color(fc(if dm { egui::Color32::from_rgb(115, 115, 138) } else { egui::Color32::from_rgb(130, 124, 112) }, t_empty)));
                    }
                });
            }

            for (i, note) in notes.iter().enumerate() {
                let t_card = anim_t(0.12 + i as f32 * 0.04);
                ui.add_space(SLIDE_PX * (1.0 - t_card));

                let card_bg = fc(c_card, t_card);
                let card_border_col = fc(c_border, t_card);
                let card = egui::Frame::none()
                    .fill(card_bg)
                    .rounding(12.0)
                    .stroke(egui::Stroke::new(1.0, card_border_col))
                    .inner_margin(egui::Margin { left: 14.0, right: 12.0, top: 12.0, bottom: 12.0 });

                let card_resp = card.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        // - - - Note icon with deterministic colour - - -
                        let hue_seed = note.title.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32));
                        let note_hues: [(u8,u8,u8); 6] = [
                            (140, 100, 220), (55, 168, 90), (80, 180, 220),
                            (240, 160, 50), (230, 100, 80), (99, 111, 245),
                        ];
                        let (hr, hg, hb) = note_hues[(hue_seed as usize) % note_hues.len()];
                        let icon_col = fc(egui::Color32::from_rgb(hr, hg, hb), t_card);
                        let icon_bg  = fc(egui::Color32::from_rgba_unmultiplied(hr, hg, hb, if dm { 35 } else { 28 }), t_card);
                        let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(36.0, 36.0), egui::Sense::hover());
                        ui.painter().rect_filled(icon_rect, 8.0, icon_bg);
                        ui.painter().text(icon_rect.center(), egui::Align2::CENTER_CENTER, "📝",
                            egui::FontId::proportional(15.0), icon_col);
                        ui.add_space(10.0);

                        ui.vertical(|ui| {
                            // - - - Title row with word count - - -
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(truncate_display(&note.title, 40)).size(14.0).strong().color(fc(c_title, t_card)));
                                if !note.content.is_empty() {
                                    let word_count = note.content.split_whitespace().count();
                                    let wc_txt = format!("{} w", word_count);
                                    let wc_col = if dm {
                                        egui::Color32::from_rgba_unmultiplied(120, 122, 145, (t_card * 200.0) as u8)
                                    } else {
                                        egui::Color32::from_rgba_unmultiplied(150, 144, 132, (t_card * 200.0) as u8)
                                    };
                                    ui.add_space(4.0);
                                    ui.label(egui::RichText::new(wc_txt).size(10.0).color(wc_col));
                                }
                            });
                            if !note.content.is_empty() {
                                ui.add_space(2.0);
                                // - - - Preview: first non-empty line, up to 72 chars - - -
                                let first_line = note.content.lines()
                                    .find(|l| !l.trim().is_empty()).unwrap_or("");
                                let preview: String = first_line.chars().take(72).collect();
                                let preview = if first_line.chars().count() > 72 || note.content.lines().count() > 1 {
                                    format!("{}…", preview)
                                } else { preview };
                                ui.label(egui::RichText::new(preview).size(11.5).color(fc(c_sub, t_card)));
                            }
                            let has_cat  = note.category.as_deref().map_or(false, |c| !c.is_empty());
                            let has_tags = !note.tags.is_empty();
                            if has_cat || has_tags {
                                ui.add_space(4.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing.x = 4.0;
                                    if let Some(cat) = &note.category {
                                        if !cat.is_empty() {
                                            let cat_bg = if dm { egui::Color32::from_rgb(36, 40, 68) } else { egui::Color32::from_rgb(228, 225, 252) };
                                            let cat_txt = if dm { egui::Color32::from_rgb(155, 165, 245) } else { egui::Color32::from_rgb(80, 72, 200) };
                                            egui::Frame::none().fill(fc(cat_bg, t_card)).rounding(6.0)
                                                .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new(format!("📁 {}", truncate_display(cat, 20))).size(10.0).color(fc(cat_txt, t_card)));
                                                });
                                        }
                                    }
                                    for tag in &note.tags {
                                        if !tag.is_empty() {
                                            let tag_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                            let tag_txt = if dm { egui::Color32::from_rgb(90, 190, 120) } else { egui::Color32::from_rgb(32, 128, 60) };
                                            egui::Frame::none().fill(fc(tag_bg, t_card)).rounding(6.0)
                                                .inner_margin(egui::Margin::symmetric(5.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new(format!("🏷 {}", truncate_display(tag, 20))).size(10.0).color(fc(tag_txt, t_card)));
                                                });
                                        }
                                    }
                                });
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            // - - - Delete button - - -
                            let del_bg = if dm { egui::Color32::from_rgba_unmultiplied(80, 30, 30, 60) } else { egui::Color32::from_rgba_unmultiplied(255, 220, 220, 80) };
                            let del_btn = egui::Button::new(
                                egui::RichText::new("🗑").size(13.0).color(fc(red_col, t_card))
                            ).fill(del_bg).rounding(7.0).min_size(egui::vec2(30.0, 30.0));
                            if ui.add(del_btn).clicked() {
                                to_remove_id = Some(note.id.clone());
                            }
                            ui.add_space(4.0);
                            // - - - Edit button - - -
                            let edit_bg = if dm { egui::Color32::from_rgba_unmultiplied(60, 70, 140, 60) } else { egui::Color32::from_rgba_unmultiplied(210, 215, 255, 80) };
                            let edit_btn = egui::Button::new(
                                egui::RichText::new("✏").size(13.0).color(fc(accent, t_card))
                            ).fill(edit_bg).rounding(7.0).min_size(egui::vec2(30.0, 30.0));
                            if ui.add(edit_btn).clicked() {
                                self.modal = Modal::EditNote {
                                    original_id: note.id.clone(),
                                    title: note.title.clone(),
                                    content: note.content.clone(),
                                    category: note.category.clone().unwrap_or_default(),
                                    tags: note.tags.join(", "),
                                };
                            }
                        });
                    });
                });

                // - - - Left accent stripe (matches icon colour) - - -
                {
                    let hue_seed = note.title.bytes().fold(0u32, |a, b| a.wrapping_add(b as u32));
                    let note_hues: [(u8,u8,u8); 6] = [
                        (140, 100, 220), (55, 168, 90), (80, 180, 220),
                        (240, 160, 50), (230, 100, 80), (99, 111, 245),
                    ];
                    let (hr, hg, hb) = note_hues[(hue_seed as usize) % note_hues.len()];
                    let stripe_rect = egui::Rect::from_min_size(
                        card_resp.response.rect.min + egui::vec2(0.0, 4.0),
                        egui::vec2(3.0, card_resp.response.rect.height() - 8.0),
                    );
                    ui.painter().rect_filled(stripe_rect, 2.0,
                        egui::Color32::from_rgba_unmultiplied(hr, hg, hb, (t_card * 160.0) as u8));
                }
                // - - - Hover highlight - - -
                if card_resp.response.hovered() {
                    ui.painter().rect_filled(
                        card_resp.response.rect, 12.0,
                        if dm { egui::Color32::from_rgba_unmultiplied(255, 255, 255, 7) }
                        else   { egui::Color32::from_rgba_unmultiplied(0, 0, 0, 6) },
                    );
                }

                ui.add_space(6.0);
            }

            if let Some(id) = to_remove_id {
                self.vault.notes.retain(|n| n.id != id);
                if let Err(e) = save_vault_file(&self.vault_path, &self.vault, &self.master_password) {
                    self.handle_error(e);
                } else {
                    self.push_toast("Note deleted.".into(), ToastKind::Info);
                }
            }
        });
    }

    fn draw_vault_manager(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let dm      = self.dark_mode;
        let accent  = egui::Color32::from_rgb(99, 111, 245);
        let green   = egui::Color32::from_rgb(46, 153, 54);
        let red     = egui::Color32::from_rgb(210, 72, 72);
        let c_title  = if dm { egui::Color32::from_rgb(225, 225, 240) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub    = if dm { egui::Color32::from_rgb(148, 151, 175) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_card   = if dm { egui::Color32::from_rgb(26, 28, 42) }    else { egui::Color32::WHITE };
        let c_border = if dm { egui::Color32::from_rgb(55, 60, 88) }    else { egui::Color32::from_rgb(210, 205, 225) };

        const SLIDE_PX: f32 = 16.0;
        const ANIM_SECS: f32 = 0.28;
        let elapsed = self.vault_manager_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let anim_t  = |delay: f32| -> f32 { ((elapsed - delay) / ANIM_SECS).clamp(0.0, 1.0) };
        let fc = |col: egui::Color32, t: f32| egui::Color32::from_rgba_unmultiplied(
            col.r(), col.g(), col.b(), (t * 255.0) as u8
        );
        if elapsed < ANIM_SECS + 0.3 { ctx.request_repaint(); }

        let current_path = self.vault_path.to_string_lossy().to_string();

        // - - - Clone registry so we can mutate self inside the loop - - -
        let vaults: Vec<VaultRecord> = self.vault_registry.vaults.clone();
        let mut action: Option<VaultManagerAction> = None;

        enum VaultManagerAction {
            Switch(usize),
            Rename(usize),
            Delete(usize),
            CreateNew,
        }

        egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Frame::none()
            .inner_margin(egui::Margin { left: 32.0, right: 32.0, top: 20.0, bottom: 32.0 })
            .show(ui, |ui| {
                ui.set_max_width(700.0);

                // - - - Header - - -
                let t0 = anim_t(0.0);
                ui.add_space(4.0 + SLIDE_PX * (1.0 - t0));
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("Vaults").size(22.0).strong().color(fc(c_title, t0)));
                    ui.add_space(8.0);
                    let badge_bg = egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), if dm { 35 } else { 22 });
                    egui::Frame::none().fill(badge_bg).rounding(8.0)
                        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(format!("{}", vaults.len())).size(12.5).strong().color(fc(accent, t0)));
                        });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let new_btn = egui::Button::new(
                            egui::RichText::new("➕  New Vault").size(12.5).color(egui::Color32::WHITE)
                        ).fill(fc(green, t0)).rounding(8.0).min_size(egui::vec2(110.0, 30.0));
                        if ui.add(new_btn).clicked() { action = Some(VaultManagerAction::CreateNew); }
                    });
                });
                ui.label(egui::RichText::new("Create, switch, rename, and delete your encrypted vaults.")
                    .size(12.5).color(fc(c_sub, t0)));
                ui.add_space(22.0);

                if vaults.is_empty() {
                    let t_e = anim_t(0.08);
                    ui.vertical_centered(|ui| {
                        ui.add_space(50.0);
                        ui.label(egui::RichText::new("No vaults registered yet.").size(15.0).color(fc(c_sub, t_e)));
                        ui.add_space(8.0);
                        let new_btn = egui::Button::new(
                            egui::RichText::new("➕  Create your first vault").size(13.0).color(egui::Color32::WHITE)
                        ).fill(fc(green, t_e)).rounding(9.0).min_size(egui::vec2(200.0, 38.0));
                        if ui.add(new_btn).clicked() { action = Some(VaultManagerAction::CreateNew); }
                    });
                } else {
                    for (i, record) in vaults.iter().enumerate() {
                        let t_card = anim_t(0.06 + i as f32 * 0.04);
                        let is_unlocked_current = record.path == current_path;

                        ui.add_space(SLIDE_PX * (1.0 - t_card) * 0.5);

                        // - - - Card background with active highlight - - -
                        let card_bg = if is_unlocked_current {
                            egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), if dm { 14 } else { 8 })
                        } else { c_card };
                        let card_border = if is_unlocked_current {
                            egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), if dm { 80 } else { 55 })
                        } else { c_border };

                        let card_resp = egui::Frame::none()
                            .fill(egui::Color32::from_rgba_unmultiplied(card_bg.r(), card_bg.g(), card_bg.b(), (t_card * 255.0) as u8))
                            .rounding(12.0)
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(card_border.r(), card_border.g(), card_border.b(), (t_card * 255.0) as u8)))
                            .inner_margin(egui::Margin { left: 16.0, right: 12.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    // - - - Vault icon - - -
                                    let icon_bg = if is_unlocked_current {
                                        egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), if dm { 40 } else { 25 })
                                    } else {
                                        if dm { egui::Color32::from_rgb(36, 40, 60) } else { egui::Color32::from_rgb(230, 228, 222) }
                                    };
                                    let (icon_rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 40.0), egui::Sense::hover());
                                    ui.painter().rect_filled(icon_rect, 10.0, icon_bg);
                                    ui.painter().text(icon_rect.center(), egui::Align2::CENTER_CENTER,
                                        if is_unlocked_current { "🔓" } else { "🔐" },
                                        egui::FontId::proportional(18.0), fc(c_title, t_card));
                                    ui.add_space(12.0);

                                    ui.vertical(|ui| {
                                        // - - - Name row - - -
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(&record.name)
                                                .size(14.5).strong().color(fc(c_title, t_card)));
                                            if is_unlocked_current {
                                                ui.add_space(6.0);
                                                let act_bg = egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), if dm { 35 } else { 22 });
                                                egui::Frame::none().fill(act_bg).rounding(6.0)
                                                    .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                                    .show(ui, |ui| {
                                                        ui.label(egui::RichText::new("active").size(10.0)
                                                            .color(fc(green, t_card)));
                                                    });
                                            }
                                        });
                                        ui.add_space(3.0);

                                        // - - - Path - - -
                                        let path_display = PathBuf::from(&record.path)
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or(&record.path)
                                            .to_string();
                                        ui.label(egui::RichText::new(&path_display).size(11.0)
                                            .color(fc(c_sub, t_card)));

                                        // - - - Last opened - - -
                                        if record.last_opened > 0 {
                                            let secs_ago = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap_or_default().as_secs()
                                                .saturating_sub(record.last_opened);
                                            let ago = if secs_ago < 60 { "just now".to_string() }
                                                else if secs_ago < 3600 { format!("{} min ago", secs_ago / 60) }
                                                else if secs_ago < 86400 { format!("{} hr ago", secs_ago / 3600) }
                                                else { format!("{} days ago", secs_ago / 86400) };
                                            ui.add_space(2.0);
                                            ui.label(egui::RichText::new(format!("Last opened {}", ago))
                                                .size(10.5).color(fc(c_sub, t_card)));
                                        }
                                    });

                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        // - - - Delete - - -
                                        let del_bg = egui::Color32::from_rgba_unmultiplied(red.r(), red.g(), red.b(), if dm { 22 } else { 14 });
                                        let del_btn = egui::Button::new(
                                            egui::RichText::new("🗑").size(13.0).color(fc(red, t_card))
                                        ).fill(del_bg).stroke(egui::Stroke::new(1.0,
                                            egui::Color32::from_rgba_unmultiplied(red.r(), red.g(), red.b(), 50)))
                                        .rounding(7.0).min_size(egui::vec2(32.0, 32.0));
                                        if ui.add(del_btn).on_hover_text("Delete vault").clicked() {
                                            action = Some(VaultManagerAction::Delete(i));
                                        }
                                        ui.add_space(6.0);

                                        // - - - Rename - - -
                                        let ren_bg = egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), if dm { 22 } else { 14 });
                                        let ren_btn = egui::Button::new(
                                            egui::RichText::new("✏").size(13.0).color(fc(accent, t_card))
                                        ).fill(ren_bg).stroke(egui::Stroke::new(1.0,
                                            egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 50)))
                                        .rounding(7.0).min_size(egui::vec2(32.0, 32.0));
                                        if ui.add(ren_btn).on_hover_text("Rename vault").clicked() {
                                            action = Some(VaultManagerAction::Rename(i));
                                        }
                                        ui.add_space(6.0);

                                        // - - - Switch / Open - - -
                                        if !is_unlocked_current {
                                            let sw_bg = egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), if dm { 28 } else { 18 });
                                            let sw_btn = egui::Button::new(
                                                egui::RichText::new("Open  →").size(12.0).color(fc(green, t_card))
                                            ).fill(sw_bg).stroke(egui::Stroke::new(1.0,
                                                egui::Color32::from_rgba_unmultiplied(green.r(), green.g(), green.b(), 60)))
                                            .rounding(7.0).min_size(egui::vec2(76.0, 32.0));
                                            if ui.add(sw_btn).on_hover_text("Switch to this vault").clicked() {
                                                action = Some(VaultManagerAction::Switch(i));
                                            }
                                        }
                                    });
                                });
                            });

                        // - - - Left accent stripe - - -
                        let stripe_col = if is_unlocked_current { green } else { accent };
                        let stripe_rect = egui::Rect::from_min_size(
                            card_resp.response.rect.min + egui::vec2(0.0, 4.0),
                            egui::vec2(3.0, card_resp.response.rect.height() - 8.0),
                        );
                        ui.painter().rect_filled(stripe_rect, 2.0,
                            egui::Color32::from_rgba_unmultiplied(stripe_col.r(), stripe_col.g(), stripe_col.b(), (t_card * 120.0) as u8));

                        if card_resp.response.hovered() && !is_unlocked_current {
                            ui.painter().rect_filled(card_resp.response.rect, 12.0,
                                egui::Color32::from_rgba_unmultiplied(255, 255, 255, if dm { 5 } else { 4 }));
                        }
                        ui.add_space(6.0);
                    }
                }

                let _ = red;
            }); // frame
        }); // scroll

        // - - - Handle actions - - -
        match action {
            Some(VaultManagerAction::CreateNew) => {
                self.modal = Modal::CreateVault {
                    name: String::new(), path_input: String::new(),
                    password: String::new(), confirm: String::new(),
                };
            }
            Some(VaultManagerAction::Rename(i)) => {
                let current_name = self.vault_registry.vaults.get(i).map(|r| r.name.clone()).unwrap_or_default();
                self.modal = Modal::RenameVault { index: i, new_name: current_name };
            }
            Some(VaultManagerAction::Delete(i)) => {
                self.modal = Modal::DeleteVaultRecord { index: i, confirmation: String::new() };
            }
            Some(VaultManagerAction::Switch(i)) => {
                // - - - Lock current vault and switch path - - -
                if let Some(record) = self.vault_registry.vaults.get(i) {
                    let new_path = PathBuf::from(&record.path);
                    self.lock_vault();
                    self.vault_path = new_path;
                    self.vault_registry.last_used_index = Some(i);
                    save_registry(&self.vault_registry);
                    // - - - Go to lock/novault screen for the new vault - - -
                    self.state = if self.vault_path.exists() { AppState::Locked } else { AppState::NoVault };
                    self.view_opened = Some(Instant::now());
                }
            }
            None => {}
        }
    }

    fn draw_generator_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let dm     = self.dark_mode;
        let accent = egui::Color32::from_rgb(99, 111, 245);
        let green  = egui::Color32::from_rgb(66, 153, 54);
        let c_title  = if dm { egui::Color32::from_rgb(225, 225, 240) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub    = if dm { egui::Color32::from_rgb(148, 151, 175) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_border = if dm { egui::Color32::from_rgb(55, 60, 88) }   else { egui::Color32::from_rgb(210, 205, 225) };
        let c_input  = if dm { egui::Color32::from_rgb(22, 24, 36) }   else { egui::Color32::from_rgb(248, 246, 252) };
        let c_card   = if dm { egui::Color32::from_rgb(26, 28, 42) }   else { egui::Color32::WHITE };

        const SLIDE_PX: f32 = 18.0;
        const ANIM_SECS: f32 = 0.25;
        let elapsed = self.generator_page_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let anim_t  = |delay: f32| -> f32 { ((elapsed - delay) / ANIM_SECS).clamp(0.0, 1.0) };
        let fc = |col: egui::Color32, t: f32| egui::Color32::from_rgba_unmultiplied(
            col.r(), col.g(), col.b(), (t * 255.0) as u8
        );
        if elapsed < ANIM_SECS + 0.3 { ctx.request_repaint(); }

        // - - - Per-frame generator state stored in egui memory - - -
        let id_len    = egui::Id::new("gen_view_length");
        let id_result = egui::Id::new("gen_view_result");
        let id_upper  = egui::Id::new("gen_view_upper");
        let id_nums   = egui::Id::new("gen_view_nums");
        let id_syms   = egui::Id::new("gen_view_syms");

        let mut pw_length: f32 = ctx.data_mut(|d| *d.get_temp_mut_or(id_len, self.default_password_length as f32));
        let mut result: String = ctx.data(|d| d.get_temp::<String>(id_result).unwrap_or_default());
        let mut use_upper: bool = ctx.data_mut(|d| *d.get_temp_mut_or(id_upper, self.gen_use_uppercase));
        let mut use_nums:  bool = ctx.data_mut(|d| *d.get_temp_mut_or(id_nums,  self.gen_use_numbers));
        let mut use_syms:  bool = ctx.data_mut(|d| *d.get_temp_mut_or(id_syms,  self.gen_use_symbols));

        let mut changed = false;

        egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Frame::none()
            .inner_margin(egui::Margin { left: 32.0, right: 32.0, top: 20.0, bottom: 32.0 })
            .show(ui, |ui| {
                ui.set_max_width(580.0);

                // - - - Header - - -
                let t0 = anim_t(0.0);
                ui.add_space(4.0 + SLIDE_PX * (1.0 - t0));
                ui.label(egui::RichText::new("Password Generator").size(22.0).strong().color(fc(c_title, t0)));
                ui.label(egui::RichText::new("Create strong, random passwords instantly.")
                    .size(12.5).color(fc(c_sub, t0)));
                ui.add_space(24.0);

                // - - - Result card - - -
                let t1 = anim_t(0.06);
                ui.add_space(SLIDE_PX * (1.0 - t1));
                let result_bg = if dm { egui::Color32::from_rgb(18, 20, 34) } else { egui::Color32::from_rgb(246, 244, 255) };
                let result_border = if result.is_empty() { fc(c_border, t1) } else { fc(accent, t1) };
                egui::Frame::none()
                    .fill(egui::Color32::from_rgba_unmultiplied(result_bg.r(), result_bg.g(), result_bg.b(), (t1 * 255.0) as u8))
                    .rounding(12.0)
                    .stroke(egui::Stroke::new(1.5, result_border))
                    .inner_margin(egui::Margin { left: 18.0, right: 14.0, top: 14.0, bottom: 14.0 })
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            // - - - Password text (monospace, large) - - -
                            let display = if result.is_empty() {
                                egui::RichText::new("Click Generate to create a password")
                                    .size(13.5).color(fc(c_sub, t1)).italics()
                            } else {
                                egui::RichText::new(&result).size(16.0).strong()
                                    .color(fc(c_title, t1)).monospace()
                            };
                            ui.label(display);
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                // - - - Copy button - - -
                                if !result.is_empty() {
                                    let copy_col = fc(accent, t1);
                                    let copy_btn = egui::Button::new(
                                        egui::RichText::new("📋").size(15.0).color(copy_col)
                                    ).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE).rounding(6.0);
                                    if ui.add(copy_btn).on_hover_text("Copy to clipboard").clicked() {
                                        if let Ok(mut cb) = arboard::Clipboard::new() {
                                            let _ = cb.set_text(result.clone());
                                            self.push_toast("Password copied to clipboard.".into(), ToastKind::Success);
                                        }
                                    }
                                }
                            });
                        });

                        // - - - Strength bar - - -
                        if !result.is_empty() {
                            ui.add_space(8.0);
                            let len = result.len();
                            let has_upper = result.chars().any(|c| c.is_uppercase());
                            let has_digit = result.chars().any(|c| c.is_ascii_digit());
                            let has_sym   = result.chars().any(|c| !c.is_alphanumeric());
                            let score = (len >= 12) as u8 + (len >= 16) as u8 + (len >= 20) as u8
                                      + has_upper as u8 + has_digit as u8 + has_sym as u8;
                            let (strength_label, strength_col, bar_fill) = match score {
                                0..=2 => ("Weak",   egui::Color32::from_rgb(210, 80,  80),  0.25_f32),
                                3..=4 => ("Fair",   egui::Color32::from_rgb(220, 160, 50),  0.55_f32),
                                5     => ("Strong", egui::Color32::from_rgb(66,  153, 54),  0.80_f32),
                                _     => ("Very Strong", accent,                             1.00_f32),
                            };
                            let bar_rect = ui.available_rect_before_wrap();
                            let bar_h = 4.0_f32;
                            let full_w = bar_rect.width();
                            let bar_bg   = if dm { egui::Color32::from_rgb(40, 44, 62) } else { egui::Color32::from_rgb(224, 220, 212) };
                            let bar_full = egui::Rect::from_min_size(bar_rect.min, egui::vec2(full_w, bar_h));
                            let bar_fill_rect = egui::Rect::from_min_size(bar_rect.min, egui::vec2(full_w * bar_fill, bar_h));
                            ui.painter().rect_filled(bar_full,     2.0, bar_bg);
                            ui.painter().rect_filled(bar_fill_rect, 2.0, strength_col);
                            ui.advance_cursor_after_rect(bar_full);
                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new(strength_label).size(10.5).strong().color(strength_col));
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    ui.label(egui::RichText::new(format!("{} chars", result.chars().count())).size(10.5).color(c_sub));
                                });
                            });
                        }
                    });
                ui.add_space(18.0);

                // - - - Options card - - -
                let t2 = anim_t(0.10);
                ui.add_space(SLIDE_PX * (1.0 - t2));
                egui::Frame::none()
                    .fill(egui::Color32::from_rgba_unmultiplied(c_card.r(), c_card.g(), c_card.b(), (t2 * 255.0) as u8))
                    .rounding(12.0)
                    .stroke(egui::Stroke::new(1.0, fc(c_border, t2)))
                    .inner_margin(egui::Margin::symmetric(18.0, 16.0))
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                        // - - - Length slider - - -
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new("Length").size(13.0).color(fc(c_title, t2)));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                let len_badge_bg = if dm { egui::Color32::from_rgb(36, 40, 68) } else { egui::Color32::from_rgb(228, 225, 252) };
                                egui::Frame::none()
                                    .fill(egui::Color32::from_rgba_unmultiplied(len_badge_bg.r(), len_badge_bg.g(), len_badge_bg.b(), (t2 * 255.0) as u8))
                                    .rounding(8.0).inner_margin(egui::Margin::symmetric(8.0, 3.0))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new(format!("{} chars", pw_length as u32))
                                            .size(12.0).strong().color(fc(accent, t2)));
                                    });
                            });
                        });
                        ui.add_space(8.0);
                        let old_len = pw_length;
                        ui.add(egui::Slider::new(&mut pw_length, 8.0..=64.0).show_value(false));
                        if (pw_length - old_len).abs() > 0.01 { changed = true; }
                        ui.add_space(14.0);

                        // - - - Character set toggles - - -
                        let sep_col = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(215, 210, 228) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                            egui::Stroke::new(1.0, fc(sep_col, t2)));
                        ui.add_space(12.0);

                        let toggle_row = |ui: &mut egui::Ui, label: &str, desc: &str, val: bool| -> bool {
                            let mut clicked = false;
                            ui.horizontal(|ui| {
                                ui.set_min_height(32.0);
                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new(label).size(13.0).color(fc(c_title, t2)));
                                    ui.label(egui::RichText::new(desc).size(11.0).color(fc(c_sub, t2)));
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    // - - - Simple pill checkbox - - -
                                    let ta = ctx.animate_bool_with_time(egui::Id::new(label), val, 0.15);
                                    let off_col = if dm { egui::Color32::from_rgb(62, 66, 88) } else { egui::Color32::from_rgb(200, 196, 188) };
                                    let (rect, resp) = ui.allocate_exact_size(egui::vec2(44.0, 24.0), egui::Sense::click());
                                    let bg = egui::Color32::from_rgb(
                                        (off_col.r() as f32 + (accent.r() as f32 - off_col.r() as f32) * ta) as u8,
                                        (off_col.g() as f32 + (accent.g() as f32 - off_col.g() as f32) * ta) as u8,
                                        (off_col.b() as f32 + (accent.b() as f32 - off_col.b() as f32) * ta) as u8,
                                    );
                                    ui.painter().rect_filled(rect, 12.0, bg);
                                    let kx = rect.left() + 11.0 + (rect.width() - 22.0) * ta;
                                    ui.painter().circle_filled(egui::pos2(kx, rect.center().y + 0.5), 8.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 28));
                                    ui.painter().circle_filled(egui::pos2(kx, rect.center().y), 8.0, egui::Color32::WHITE);
                                    if ta > 0.01 && ta < 0.99 { ctx.request_repaint(); }
                                    if resp.clicked() { clicked = true; }
                                });
                            });
                            clicked
                        };

                        if toggle_row(ui, "Uppercase letters", "A – Z", use_upper) { use_upper = !use_upper; changed = true; }
                        ui.add_space(6.0);
                        if toggle_row(ui, "Numbers", "0 – 9", use_nums) { use_nums = !use_nums; changed = true; }
                        ui.add_space(6.0);
                        if toggle_row(ui, "Symbols", "! @ # $ …", use_syms) { use_syms = !use_syms; changed = true; }
                    });
                ui.add_space(18.0);

                // - - - Generate button - - -
                let t3 = anim_t(0.14);
                ui.add_space(SLIDE_PX * (1.0 - t3));
                ui.horizontal(|ui| {
                    let gen_btn = egui::Button::new(
                        egui::RichText::new("🎲  Generate Password").size(14.0).strong().color(egui::Color32::WHITE)
                    ).fill(egui::Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), (t3 * 255.0) as u8))
                    .rounding(10.0).min_size(egui::vec2(200.0, 42.0));
                    if ui.add(gen_btn).clicked() || (changed && !result.is_empty()) {
                        result = generate_password(pw_length as usize, use_upper, use_nums, use_syms);
                        changed = false;
                    }
                    // - - - "Use in new entry" shortcut - - -
                    if !result.is_empty() {
                        ui.add_space(10.0);
                        let use_btn = egui::Button::new(
                            egui::RichText::new("➕  New Entry with this").size(12.5).color(fc(c_title, t3))
                        ).fill(egui::Color32::from_rgba_unmultiplied(
                            if dm { 36 } else { 228 },
                            if dm { 40 } else { 226 },
                            if dm { 68 } else { 248 },
                            (t3 * 200.0) as u8,
                        )).rounding(10.0).min_size(egui::vec2(180.0, 42.0));
                        if ui.add(use_btn).clicked() {
                            self.modal = Modal::AddEntry {
                                service: String::new(),
                                username: String::new(),
                                password: result.clone(),
                                password_length: pw_length,
                                totp_secret: String::new(),
                                totp_open: false,
                                category: String::new(),
                                tags: String::new(),
                            };
                            self.state = AppState::Unlocked;
                            self.view_opened = Some(Instant::now());
                        }
                    }
                });

                ui.add_space(8.0);
                ui.label(egui::RichText::new("Tip: passwords are generated locally and never leave your device.")
                    .size(11.0).color(fc(c_sub, anim_t(0.18))));

                let _ = (green, c_input);
            }); // inner frame
        }); // scroll area

        // - - - Persist state in egui memory - - -
        ctx.data_mut(|d| {
            d.insert_temp(id_len, pw_length);
            d.insert_temp(id_result, result);
            d.insert_temp(id_upper, use_upper);
            d.insert_temp(id_nums, use_nums);
            d.insert_temp(id_syms, use_syms);
        });
    }

    fn draw_settings_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let dm     = self.dark_mode;
        let accent = egui::Color32::from_rgb(99, 111, 245);
        let c_title  = if dm { egui::Color32::from_rgb(225, 225, 240) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub    = if dm { egui::Color32::from_rgb(148, 151, 175) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_border = if dm { egui::Color32::from_rgb(55, 60, 88) }   else { egui::Color32::from_rgb(210, 205, 225) };

        const SLIDE_PX: f32 = 18.0;
        const ANIM_SECS: f32 = 0.28;
        let elapsed = self.settings_page_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let anim_t = |delay: f32| -> f32 { ((elapsed - delay) / ANIM_SECS).clamp(0.0, 1.0) };
        let fc = |col: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_SECS + 0.5 { ctx.request_repaint(); }

        let draw_toggle = |ui: &mut egui::Ui, ctx: &egui::Context, id: &str, value: bool, accent: egui::Color32| -> bool {
            let switch_size = egui::vec2(44.0, 24.0);
            let (rect, response) = ui.allocate_exact_size(switch_size, egui::Sense::click());
            let clicked = response.clicked();
            let cur_val = if clicked { !value } else { value };
            let t = ctx.animate_bool_with_time(egui::Id::new(id), cur_val, 0.18);
            if ui.is_rect_visible(rect) {
                let off_col = if dm { egui::Color32::from_rgb(62, 66, 88) } else { egui::Color32::from_rgb(200, 196, 188) };
                let bg = egui::Color32::from_rgb(
                    (off_col.r() as f32 + (accent.r() as f32 - off_col.r() as f32) * t) as u8,
                    (off_col.g() as f32 + (accent.g() as f32 - off_col.g() as f32) * t) as u8,
                    (off_col.b() as f32 + (accent.b() as f32 - off_col.b() as f32) * t) as u8,
                );
                ui.painter().rect_filled(rect, 12.0, bg);
                let knob_x = rect.left() + 11.0 + (rect.width() - 22.0) * t;
                ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y + 0.5), 8.0, egui::Color32::from_rgba_premultiplied(0, 0, 0, 28));
                ui.painter().circle_filled(egui::pos2(knob_x, rect.center().y), 8.0, egui::Color32::WHITE);
                if t > 0.01 && t < 0.99 { ctx.request_repaint(); }
            }
            clicked
        };

        let sep_col = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(215, 210, 228) };

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Frame::none()
                .inner_margin(egui::Margin { left: 32.0, right: 32.0, top: 20.0, bottom: 32.0 })
                .show(ui, |ui| {
                    ui.set_max_width(640.0);

                    // - - - Page header - - -
                    let t0 = anim_t(0.0);
                    ui.add_space(4.0 + SLIDE_PX * (1.0 - t0));
                    ui.label(egui::RichText::new("Settings").size(22.0).strong().color(fc(c_title, t0)));
                    ui.label(egui::RichText::new("Customize appearance, security, and generator defaults.").size(12.5).color(fc(c_sub, t0)));
                    ui.add_space(24.0);

                    // - - - Section header helper - - -
                    let section_hdr = |ui: &mut egui::Ui, icon: &str, label: &str, t: f32| {
                        ui.add_space(SLIDE_PX * (1.0 - t));
                        ui.horizontal(|ui| {
                            let pill_bg  = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(225, 245, 228) };
                            let pill_txt = if dm { egui::Color32::from_rgb(90, 190, 120) } else { egui::Color32::from_rgb(30, 120, 55) };
                            egui::Frame::none()
                                .fill(egui::Color32::from_rgba_unmultiplied(pill_bg.r(), pill_bg.g(), pill_bg.b(), (t * 255.0) as u8))
                                .rounding(6.0).inner_margin(egui::Margin::symmetric(7.0, 4.0))
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new(format!("{} {}", icon, label)).size(10.5).strong().color(
                                        egui::Color32::from_rgba_unmultiplied(pill_txt.r(), pill_txt.g(), pill_txt.b(), (t * 255.0) as u8)));
                                });
                        });
                        ui.add_space(2.0);
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                            egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(sep_col.r(), sep_col.g(), sep_col.b(), (t * 255.0) as u8)));
                    };

                    // ---- APPEARANCE ----
                    section_hdr(ui, "🎨", "APPEARANCE", anim_t(0.04));
                    ui.add_space(8.0);

                    let card_bg = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::WHITE };
                    let card_stroke = fc(c_border, anim_t(0.04));
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgba_unmultiplied(card_bg.r(), card_bg.g(), card_bg.b(), (anim_t(0.04) * 255.0) as u8))
                        .rounding(12.0)
                        .stroke(egui::Stroke::new(1.0, card_stroke))
                        .inner_margin(egui::Margin::symmetric(18.0, 14.0))
                        .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                    let toggle_row = |ui: &mut egui::Ui, title: &str, desc: &str, t: f32| {
                        ui.add_space(SLIDE_PX * (1.0 - t) * 0.4);
                        ui.horizontal(|ui| { ui.set_min_height(40.0);
                            ui.vertical(|ui| {
                                ui.label(egui::RichText::new(title).size(13.0).color(fc(c_title, t)));
                                ui.label(egui::RichText::new(desc).size(11.0).color(fc(c_sub, t)));
                            });
                        });
                    };
                    let _ = toggle_row; // suppress if unused

                    // Dark mode
                    ui.add_space(SLIDE_PX * (1.0 - anim_t(0.06)) * 0.4);
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Dark Mode").size(13.0).color(fc(c_title, anim_t(0.06))));
                            ui.label(egui::RichText::new("Toggle dark / light theme").size(11.0).color(fc(c_sub, anim_t(0.06))));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let was = self.dark_mode;
                            if draw_toggle(ui, ctx, "s_dark_mode", self.dark_mode, accent) { self.dark_mode = !self.dark_mode; }
                            if was != self.dark_mode {
                                save_settings(&self.to_settings());
                                ctx.set_visuals(if self.dark_mode { egui::Visuals::dark() } else { egui::Visuals::light() });
                            }
                        });
                    });

                    // Separator between rows
                    ui.add_space(10.0);
                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                        egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(sep_col.r(), sep_col.g(), sep_col.b(), (anim_t(0.06) * 120.0) as u8)));
                    ui.add_space(10.0);

                    // Show passwords
                    ui.add_space(SLIDE_PX * (1.0 - anim_t(0.10)) * 0.4);
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Show Passwords").size(13.0).color(fc(c_title, anim_t(0.10))));
                            ui.label(egui::RichText::new("Reveal passwords in the vault list by default").size(11.0).color(fc(c_sub, anim_t(0.10))));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if draw_toggle(ui, ctx, "s_show_pw", self.show_passwords, accent) {
                                self.show_passwords = !self.show_passwords; save_settings(&self.to_settings());
                            }
                        });
                    });
                    ui.add_space(6.0);
                    }); // end card
                    ui.add_space(20.0);

                    // ---- SECURITY ----
                    section_hdr(ui, "🔒", "SECURITY", anim_t(0.12));
                    ui.add_space(8.0);

                    let sec_card_bg = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::WHITE };
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgba_unmultiplied(sec_card_bg.r(), sec_card_bg.g(), sec_card_bg.b(), (anim_t(0.12) * 255.0) as u8))
                        .rounding(12.0)
                        .stroke(egui::Stroke::new(1.0, fc(c_border, anim_t(0.12))))
                        .inner_margin(egui::Margin::symmetric(18.0, 14.0))
                        .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                    // Auto-lock
                    ui.add_space(SLIDE_PX * (1.0 - anim_t(0.14)) * 0.4);
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Auto-lock").size(13.0).color(fc(c_title, anim_t(0.14))));
                            ui.label(egui::RichText::new("Lock the vault automatically after inactivity").size(11.0).color(fc(c_sub, anim_t(0.14))));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if draw_toggle(ui, ctx, "s_autolock", self.auto_lock_enabled, accent) {
                                self.auto_lock_enabled = !self.auto_lock_enabled; save_settings(&self.to_settings());
                            }
                        });
                    });
                    if self.auto_lock_enabled {
                        ui.add_space(4.0);
                        let indent_bg = if dm { egui::Color32::from_rgb(18, 20, 30) } else { egui::Color32::from_rgb(245, 243, 252) };
                        egui::Frame::none().fill(indent_bg).rounding(10.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 10.0)).stroke(egui::Stroke::new(1.0, fc(c_border, anim_t(0.14))))
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Timeout").size(12.5).color(c_title));
                                    ui.label(egui::RichText::new("minutes of inactivity").size(11.0).color(c_sub));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let mut mins = self.auto_lock_timeout_mins as f32;
                                        if ui.add(egui::Slider::new(&mut mins, 1.0..=60.0).suffix(" min").show_value(true).integer()).changed() {
                                            self.auto_lock_timeout_mins = mins as u64; save_settings(&self.to_settings());
                                        }
                                    });
                                });
                            });
                        ui.add_space(4.0);
                    }

                    ui.add_space(10.0);
                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                        egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(sep_col.r(), sep_col.g(), sep_col.b(), (anim_t(0.14) * 120.0) as u8)));
                    ui.add_space(10.0);

                    // Lock on focus loss
                    ui.add_space(SLIDE_PX * (1.0 - anim_t(0.16)) * 0.4);
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Lock on Focus Loss").size(13.0).color(fc(c_title, anim_t(0.16))));
                            ui.label(egui::RichText::new("Lock when the application loses focus").size(11.0).color(fc(c_sub, anim_t(0.16))));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if draw_toggle(ui, ctx, "s_focus_loss", self.lock_on_focus_loss, accent) {
                                self.lock_on_focus_loss = !self.lock_on_focus_loss; save_settings(&self.to_settings());
                            }
                        });
                    });

                    ui.add_space(10.0);
                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                        egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(sep_col.r(), sep_col.g(), sep_col.b(), (anim_t(0.16) * 120.0) as u8)));
                    ui.add_space(10.0);

                    // Clipboard auto-clear
                    let cb_enabled = self.clipboard_timeout_secs.is_some();
                    ui.add_space(SLIDE_PX * (1.0 - anim_t(0.18)) * 0.4);
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Clipboard Auto-clear").size(13.0).color(fc(c_title, anim_t(0.18))));
                            ui.label(egui::RichText::new("Clear copied passwords after a timeout").size(11.0).color(fc(c_sub, anim_t(0.18))));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if draw_toggle(ui, ctx, "s_autoclear", cb_enabled, accent) {
                                self.clipboard_timeout_secs = if cb_enabled { None } else { Some(30) }; save_settings(&self.to_settings());
                            }
                        });
                    });
                    if cb_enabled {
                        ui.add_space(4.0);
                        let indent_bg = if dm { egui::Color32::from_rgb(18, 20, 30) } else { egui::Color32::from_rgb(245, 243, 252) };
                        egui::Frame::none().fill(indent_bg).rounding(10.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 10.0)).stroke(egui::Stroke::new(1.0, fc(c_border, anim_t(0.18))))
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("Timeout").size(12.5).color(c_title));
                                    ui.label(egui::RichText::new("seconds").size(11.0).color(c_sub));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let mut secs = self.clipboard_timeout_secs.unwrap_or(30) as f32;
                                        if ui.add(egui::Slider::new(&mut secs, 5.0..=120.0).suffix(" s").show_value(true).integer()).changed() {
                                            self.clipboard_timeout_secs = Some(secs as u64); save_settings(&self.to_settings());
                                        }
                                    });
                                });
                            });
                        ui.add_space(4.0);
                    }
                    ui.add_space(6.0);
                    }); // end security card
                    ui.add_space(20.0);

                    // ---- PASSWORD GENERATOR ----
                    section_hdr(ui, "🎲", "PASSWORD GENERATOR", anim_t(0.20));
                    ui.add_space(8.0);

                    let gen_card_bg = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::WHITE };
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgba_unmultiplied(gen_card_bg.r(), gen_card_bg.g(), gen_card_bg.b(), (anim_t(0.20) * 255.0) as u8))
                        .rounding(12.0)
                        .stroke(egui::Stroke::new(1.0, fc(c_border, anim_t(0.20))))
                        .inner_margin(egui::Margin::symmetric(18.0, 14.0))
                        .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                    ui.add_space(SLIDE_PX * (1.0 - anim_t(0.22)) * 0.4);
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("Default Length").size(13.0).color(fc(c_title, anim_t(0.22))));
                            ui.label(egui::RichText::new("Default character count for generated passwords").size(11.0).color(fc(c_sub, anim_t(0.22))));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let mut len = self.default_password_length as f32;
                            if ui.add(egui::Slider::new(&mut len, 8.0..=64.0).suffix(" chars").show_value(true).integer()).changed() {
                                self.default_password_length = len as u32; save_settings(&self.to_settings());
                            }
                        });
                    });

                    ui.add_space(10.0);
                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                        egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(sep_col.r(), sep_col.g(), sep_col.b(), (anim_t(0.22) * 120.0) as u8)));
                    ui.add_space(10.0);

                    let indent_bg = if dm { egui::Color32::from_rgb(18, 20, 30) } else { egui::Color32::from_rgb(245, 243, 252) };
                    egui::Frame::none().fill(indent_bg).rounding(10.0)
                        .inner_margin(egui::Margin::symmetric(14.0, 10.0)).stroke(egui::Stroke::new(1.0, fc(c_border, anim_t(0.24))))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            let rows: &[(&str, &str, &str, bool)] = &[
                                ("Uppercase", "A–Z",  "s_gen_upper", self.gen_use_uppercase),
                                ("Numbers",   "0–9",  "s_gen_nums",  self.gen_use_numbers),
                                ("Symbols",   "!@#…", "s_gen_syms",  self.gen_use_symbols),
                            ];
                            for &(label, desc, id, val) in rows {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new(label).size(12.5).color(c_title));
                                    ui.add_space(4.0);
                                    ui.label(egui::RichText::new(desc).size(11.0).color(c_sub));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if draw_toggle(ui, ctx, id, val, accent) {
                                            match id {
                                                "s_gen_upper" => self.gen_use_uppercase = !self.gen_use_uppercase,
                                                "s_gen_nums"  => self.gen_use_numbers   = !self.gen_use_numbers,
                                                _             => self.gen_use_symbols    = !self.gen_use_symbols,
                                            }
                                            save_settings(&self.to_settings());
                                        }
                                    });
                                });
                                ui.add_space(8.0);
                            }
                        });
                    ui.add_space(6.0);
                    }); // end generator card
                    ui.add_space(20.0);

                    // ---- PERFORMANCE ----
                    section_hdr(ui, "⚡", "PERFORMANCE", anim_t(0.26));
                    ui.add_space(8.0);

                    let perf_card_bg = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::WHITE };
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgba_unmultiplied(perf_card_bg.r(), perf_card_bg.g(), perf_card_bg.b(), (anim_t(0.26) * 255.0) as u8))
                        .rounding(12.0)
                        .stroke(egui::Stroke::new(1.0, fc(c_border, anim_t(0.26))))
                        .inner_margin(egui::Margin::symmetric(18.0, 14.0))
                        .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());

                    let t_vs = anim_t(0.28);
                    ui.add_space(SLIDE_PX * (1.0 - t_vs) * 0.4);
                    let mut vsync_changed_local = false;
                    ui.horizontal(|ui| {
                        ui.set_min_height(44.0);
                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new("VSync").size(13.0).color(fc(c_title, t_vs)));
                            ui.label(egui::RichText::new("Sync frame rate with display — restart required").size(11.0).color(fc(c_sub, t_vs)));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let was = self.vsync_enabled;
                            if draw_toggle(ui, ctx, "s_vsync", self.vsync_enabled, accent) { self.vsync_enabled = !self.vsync_enabled; }
                            if was != self.vsync_enabled { save_settings(&self.to_settings()); vsync_changed_local = true; }
                        });
                    });
                    if vsync_changed_local {
                        ui.add_space(6.0);
                        let note_bg = if dm { egui::Color32::from_rgb(36, 30, 12) } else { egui::Color32::from_rgb(255, 250, 232) };
                        egui::Frame::none().fill(note_bg).rounding(8.0)
                            .inner_margin(egui::Margin::symmetric(12.0, 9.0))
                            .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(150, 105, 18)))
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("ℹ️").size(12.0));
                                    ui.add_space(6.0);
                                    ui.label(egui::RichText::new("Restart required to apply this change.").size(12.0)
                                        .color(if dm { egui::Color32::from_rgb(220, 165, 50) } else { egui::Color32::from_rgb(115, 75, 5) }));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let rb = egui::Button::new(egui::RichText::new("Restart").size(11.5).color(egui::Color32::WHITE))
                                            .fill(egui::Color32::from_rgb(150, 105, 18)).rounding(7.0).min_size(egui::vec2(72.0, 26.0));
                                        if ui.add(rb).clicked() {
                                            save_settings(&self.to_settings());
                                            if let Ok(exe) = std::env::current_exe() { let _ = std::process::Command::new(exe).spawn(); }
                                            std::process::exit(0);
                                        }
                                    });
                                });
                            });
                    }
                    ui.add_space(6.0);
                    }); // end performance card
                    ui.add_space(32.0);

                    // ---- DANGER ZONE ----
                    let t5 = anim_t(0.30);
                    let red_col = if dm { egui::Color32::from_rgb(200, 90, 90) } else { egui::Color32::from_rgb(180, 50, 50) };
                    let danger_bg     = if dm { egui::Color32::from_rgb(38, 20, 20) } else { egui::Color32::from_rgb(255, 244, 244) };
                    let danger_border = egui::Color32::from_rgb(140, 50, 50);
                    ui.add_space(SLIDE_PX * (1.0 - t5));
                    egui::Frame::none()
                        .fill(egui::Color32::from_rgba_unmultiplied(danger_bg.r(), danger_bg.g(), danger_bg.b(), (t5 * 255.0) as u8))
                        .rounding(12.0)
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(danger_border.r(), danger_border.g(), danger_border.b(), (t5 * 255.0) as u8)))
                        .inner_margin(egui::Margin::symmetric(18.0, 14.0))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.vertical(|ui| {
                                    ui.label(egui::RichText::new("Danger Zone").size(13.0).strong()
                                        .color(egui::Color32::from_rgba_unmultiplied(red_col.r(), red_col.g(), red_col.b(), (t5 * 255.0) as u8)));
                                    ui.add_space(2.0);
                                    ui.label(egui::RichText::new("Change master password or permanently delete the vault.")
                                        .size(11.0).color(fc(c_sub, t5)));
                                });
                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                    let del_btn = egui::Button::new(
                                        egui::RichText::new("🗑  Delete Vault").size(12.0).color(egui::Color32::WHITE)
                                    ).fill(egui::Color32::from_rgba_unmultiplied(160, 40, 40, (t5 * 255.0) as u8))
                                    .rounding(8.0).min_size(egui::vec2(120.0, 30.0));
                                    if ui.add(del_btn).clicked() {
                                        self.modal = Modal::DeleteVault { confirmation: String::new() };
                                    }
                                    ui.add_space(8.0);
                                    let pw_btn = egui::Button::new(
                                        egui::RichText::new("🔑  Change Password").size(12.0)
                                            .color(egui::Color32::from_rgba_unmultiplied(red_col.r(), red_col.g(), red_col.b(), (t5 * 255.0) as u8))
                                    ).fill(egui::Color32::TRANSPARENT)
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(red_col.r(), red_col.g(), red_col.b(), (t5 * 200.0) as u8)))
                                    .rounding(8.0).min_size(egui::vec2(140.0, 30.0));
                                    if ui.add(pw_btn).clicked() {
                                        self.modal = Modal::ChangePassword { old: String::new(), new: String::new(), confirm: String::new() };
                                    }
                                });
                            });
                        });

                    ui.add_space(24.0);
                }); // inner frame
        }); // scroll area
    }

    fn draw_known_bugs_view(&mut self, ui: &mut egui::Ui) {
        let dm = self.dark_mode;
        let accent    = egui::Color32::from_rgb(99, 111, 245);
        let c_title   = if dm { egui::Color32::from_rgb(225, 225, 240) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub     = if dm { egui::Color32::from_rgb(148, 151, 175) } else { egui::Color32::from_rgb(90, 86, 100) };
        let c_card    = if dm { egui::Color32::from_rgb(26, 28, 42) } else { egui::Color32::WHITE };
        let c_border  = if dm { egui::Color32::from_rgb(55, 60, 88) } else { egui::Color32::from_rgb(210, 205, 225) };
        let c_row     = if dm { egui::Color32::from_rgb(20, 22, 34) } else { egui::Color32::from_rgb(243, 241, 250) };
        let green     = egui::Color32::from_rgb(72, 199, 116);
        let green_bg  = if dm { egui::Color32::from_rgb(14, 38, 22) } else { egui::Color32::from_rgb(236, 255, 244) };
        let green_bdr = egui::Color32::from_rgb(45, 148, 76);
        let discord   = egui::Color32::from_rgb(110, 132, 215);

        let card_margin   = egui::Margin::symmetric(20.0, 16.0);
        let card_rounding = 12.0_f32;

        // - - - Animation setup - - -
        // - - - Each element (title, card1, card2) has its own stagger delay. - - -
        // - - - t goes 0→1 over ANIM_DUR seconds; ease = smooth-step. - - -
        const ANIM_DUR: f32 = 0.45;
        const SLIDE_PX: f32 = 28.0;
        let elapsed = self.info_page_opened
            .map(|t| t.elapsed().as_secs_f32())
            .unwrap_or(f32::MAX);

        // - - - smooth-step: 3t²-2t³ - - -
        let smooth = |t: f32| -> f32 {
            let t = t.clamp(0.0, 1.0);
            t * t * (3.0 - 2.0 * t)
        };

        // - - - t for each layer given a stagger delay in seconds - - -
        let anim_t = |delay: f32| -> f32 {
            smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0))
        };

        // - - - If any animation is still running, keep repainting - - -
        if elapsed < ANIM_DUR + 0.25 {
            ui.ctx().request_repaint();
        }

        // - - - Helper: apply vertical offset + alpha fade by drawing into a child ui - - -
        // - - - We do this by offsetting the ui cursor with add_space and using painter alpha. - - -
        // - - - egui doesn't have a built-in opacity node, so we animate via a vertical - - -
        // - - - layout shift and blend text colors toward the background manually. - - -
        // - - - For a clean approach: use ui.add_space for slide, and color alpha for fade. - - -
        let fade_color = |base: egui::Color32, t: f32| -> egui::Color32 {
            let a = (t * 255.0) as u8;
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), a)
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Frame::none()
                .inner_margin(egui::Margin { left: 32.0, right: 32.0, top: 20.0, bottom: 32.0 })
                .show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_max_width(480.0);

                // - - - Title block ── (delay 0.0) - - -
                {
                    let t0 = anim_t(0.0);
                    let offset = SLIDE_PX * (1.0 - t0);
                    ui.add_space(24.0 + offset);
                    ui.label(
                        egui::RichText::new("Info & Support")
                            .size(20.0)
                            .strong()
                            .color(fade_color(c_title, t0)),
                    );
                    ui.add_space(4.0);
                    ui.label(
                        egui::RichText::new("Updates ship via GitHub. Support is on Discord.")
                            .size(13.0)
                            .color(fade_color(c_sub, t0)),
                    );
                    ui.add_space(20.0);
                }

                // - - - Version card ── (delay 0.08) - - -
                {
                    let t1 = anim_t(0.08);
                    let offset = SLIDE_PX * (1.0 - t1);
                    ui.add_space(offset);

                    let border_col = egui::Color32::from_rgba_unmultiplied(
                        c_border.r(), c_border.g(), c_border.b(), (t1 * 255.0) as u8,
                    );
                    let card_col = egui::Color32::from_rgba_unmultiplied(
                        c_card.r(), c_card.g(), c_card.b(), (t1 * 255.0) as u8,
                    );

                    egui::Frame::none()
                        .fill(card_col)
                        .rounding(card_rounding)
                        .inner_margin(card_margin)
                        .stroke(egui::Stroke::new(1.0, border_col))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());

                            // - - - Live update-check status — reflects self.update_status, - - -
                            // - - - which is populated on a background thread by check_for_updates(). - - -
                            {
                                let (icon, headline, detail, banner_bg, banner_bdr, banner_fg, action): (&str, String, String, egui::Color32, egui::Color32, egui::Color32, Option<(String, String)>) =
                                    match &self.update_status {
                                        UpdateStatus::Unknown => (
                                            "⏳", "Checking for updates…".to_string(), String::new(),
                                            if dm { egui::Color32::from_rgb(28, 30, 44) } else { egui::Color32::from_rgb(244, 243, 250) },
                                            c_border, c_sub, None,
                                        ),
                                        UpdateStatus::UpToDate => (
                                            "✓", "You're up to date".to_string(), format!("Running the latest version (v{APP_VERSION})."),
                                            green_bg, green_bdr, green, None,
                                        ),
                                        UpdateStatus::StableAvailable { version, url } => (
                                            "🚀", format!("Update available — v{version}"), "A new stable release is ready to install.".to_string(),
                                            if dm { egui::Color32::from_rgb(16, 38, 56) } else { egui::Color32::from_rgb(232, 244, 255) },
                                            egui::Color32::from_rgb(60, 130, 200),
                                            if dm { egui::Color32::from_rgb(110, 175, 235) } else { egui::Color32::from_rgb(30, 95, 160) },
                                            Some(("View release  ↗".to_string(), url.clone())),
                                        ),
                                        UpdateStatus::BetaAvailable { version, url } => (
                                            "🧪", format!("Beta update available — v{version}"), "A newer pre-release build is ready to try.".to_string(),
                                            if dm { egui::Color32::from_rgb(40, 33, 16) } else { egui::Color32::from_rgb(255, 248, 235) },
                                            egui::Color32::from_rgb(200, 150, 40),
                                            if dm { egui::Color32::from_rgb(230, 180, 80) } else { egui::Color32::from_rgb(150, 105, 10) },
                                            Some(("View pre-release  ↗".to_string(), url.clone())),
                                        ),
                                        UpdateStatus::CheckFailed(_) => (
                                            "⚠️", "Couldn't check for updates".to_string(), "Check your connection and try again.".to_string(),
                                            if dm { egui::Color32::from_rgb(38, 20, 20) } else { egui::Color32::from_rgb(255, 244, 244) },
                                            egui::Color32::from_rgb(140, 50, 50),
                                            if dm { egui::Color32::from_rgb(225, 130, 130) } else { egui::Color32::from_rgb(170, 50, 50) },
                                            None,
                                        ),
                                    };

                                let bg = egui::Color32::from_rgba_unmultiplied(banner_bg.r(), banner_bg.g(), banner_bg.b(), (t1 * 255.0) as u8);
                                let bdr = egui::Color32::from_rgba_unmultiplied(banner_bdr.r(), banner_bdr.g(), banner_bdr.b(), (t1 * 255.0) as u8);
                                egui::Frame::none()
                                    .fill(bg)
                                    .rounding(8.0)
                                    .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                                    .stroke(egui::Stroke::new(1.0, bdr))
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new(icon).size(15.0));
                                            ui.add_space(8.0);
                                            ui.vertical(|ui| {
                                                ui.label(egui::RichText::new(&headline).size(12.5).strong().color(fade_color(banner_fg, t1)));
                                                if !detail.is_empty() {
                                                    ui.add_space(2.0);
                                                    ui.label(egui::RichText::new(&detail).size(11.0).color(fade_color(c_sub, t1)));
                                                }
                                            });
                                        });
                                        if let Some((label, url)) = &action {
                                            ui.add_space(8.0);
                                            let btn = egui::Button::new(
                                                egui::RichText::new(label.as_str()).size(12.0).color(egui::Color32::WHITE)
                                            )
                                            .fill(egui::Color32::from_rgba_unmultiplied(banner_bdr.r(), banner_bdr.g(), banner_bdr.b(), (t1 * 255.0) as u8))
                                            .rounding(7.0)
                                            .min_size(egui::vec2(ui.available_width(), 30.0));
                                            if ui.add(btn).clicked() {
                                                ui.ctx().open_url(egui::OpenUrl::new_tab(url));
                                            }
                                        }
                                    });

                                ui.add_space(8.0);

                                // - - - Manual recheck — disabled while a check is already in flight - - -
                                let checking = self.update_check_receiver.is_some();
                                let recheck_label = if checking { "Checking…" } else { "Check for updates" };
                                let recheck_btn = egui::Button::new(
                                    egui::RichText::new(recheck_label).size(12.0).color(fade_color(c_sub, t1))
                                )
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(c_border.r(), c_border.g(), c_border.b(), (t1 * 255.0) as u8)))
                                .rounding(7.0)
                                .min_size(egui::vec2(ui.available_width(), 28.0));
                                if ui.add_enabled(!checking, recheck_btn).clicked() {
                                    self.update_status = UpdateStatus::Unknown;
                                    self.check_for_updates_async();
                                }
                            }

                            ui.add_space(12.0);

                            // - - - "What's new" highlights ── replaces the old empty banner - - -
                            let gbg = egui::Color32::from_rgba_unmultiplied(
                                green_bg.r(), green_bg.g(), green_bg.b(), (t1 * 255.0) as u8,
                            );
                            let gbdr = egui::Color32::from_rgba_unmultiplied(
                                green_bdr.r(), green_bdr.g(), green_bdr.b(), (t1 * 255.0) as u8,
                            );
                            egui::Frame::none()
                                .fill(gbg)
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                                .stroke(egui::Stroke::new(1.0, gbdr))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());

                                    ui.label(
                                        egui::RichText::new("WHAT'S NEW")
                                            .size(10.0)
                                            .strong()
                                            .color(fade_color(green, t1)),
                                    );
                                    ui.add_space(6.0);

                                    for (i, item) in [
                                        "Audio chime on vault unlock",
                                        "Encrypted vault import & export",
                                        "Full color system redesign",
                                    ].iter().enumerate() {
                                        if i > 0 { ui.add_space(6.0); }
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new("✓")
                                                    .size(13.0)
                                                    .strong()
                                                    .color(fade_color(green, t1)),
                                            );
                                            ui.add_space(8.0);
                                            ui.label(
                                                egui::RichText::new(*item)
                                                    .size(13.0)
                                                    .color(fade_color(c_title, t1)),
                                            );
                                        });
                                    }
                                });

                            ui.add_space(12.0);

                            // - - - GitHub button — fades in with card - - -
                            let btn_col = egui::Color32::from_rgba_unmultiplied(99, 111, 245, (t1 * 255.0) as u8);
                            let gh_btn = egui::Button::new(
                                egui::RichText::new("View releases on GitHub  ↗")
                                    .size(13.0)
                                    .color(fade_color(egui::Color32::WHITE, t1)),
                            )
                            .fill(btn_col)
                            .rounding(8.0)
                            .min_size(egui::vec2(ui.available_width(), 34.0));

                            if ui.add(gh_btn).clicked() {
                                ui.ctx().open_url(egui::OpenUrl::new_tab("https://github.com/makke08/ZeroPass/releases"));
                            }
                        });

                    ui.add_space(12.0);
                }

                // - - - Support card ── (delay 0.18) - - -
                {
                    let t2 = anim_t(0.18);
                    let offset = SLIDE_PX * (1.0 - t2);
                    ui.add_space(offset);

                    let border_col = egui::Color32::from_rgba_unmultiplied(
                        c_border.r(), c_border.g(), c_border.b(), (t2 * 255.0) as u8,
                    );
                    let card_col = egui::Color32::from_rgba_unmultiplied(
                        c_card.r(), c_card.g(), c_card.b(), (t2 * 255.0) as u8,
                    );

                    egui::Frame::none()
                        .fill(card_col)
                        .rounding(card_rounding)
                        .inner_margin(card_margin)
                        .stroke(egui::Stroke::new(1.0, border_col))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());

                            ui.label(
                                egui::RichText::new("Support")
                                    .size(11.0)
                                    .color(fade_color(c_sub, t2)),
                            );
                            ui.add_space(8.0);

                            ui.label(
                                egui::RichText::new("Got a bug or a question? Reach out on Discord.")
                                    .size(13.0)
                                    .color(fade_color(c_title, t2)),
                            );
                            ui.add_space(4.0);
                            ui.label(
                                egui::RichText::new("macke.0")
                                    .size(13.0)
                                    .strong()
                                    .color(fade_color(discord, t2)),
                            );

                            ui.add_space(10.0);

                            let discord_btn_fill = egui::Color32::from_rgba_unmultiplied(88, 101, 222, (t2 * 255.0) as u8);
                            let discord_btn = egui::Button::new(
                                egui::RichText::new("Join Discord  ↗")
                                    .size(13.0)
                                    .color(fade_color(egui::Color32::WHITE, t2)),
                            )
                            .fill(discord_btn_fill)
                            .rounding(8.0)
                            .min_size(egui::vec2(ui.available_width(), 34.0));
                            if ui.add(discord_btn).clicked() {
                                ui.ctx().open_url(egui::OpenUrl::new_tab("https://discord.gg/NyFf8DWmVs"));
                            }

                            ui.add_space(12.0);

                            let sep = egui::Color32::from_rgba_unmultiplied(
                                if dm { 50 } else { 218 },
                                if dm { 54 } else { 218 },
                                if dm { 78 } else { 235 },
                                (t2 * 255.0) as u8,
                            );
                            ui.painter().hline(
                                ui.available_rect_before_wrap().x_range(),
                                ui.cursor().top(),
                                egui::Stroke::new(1.0, sep),
                            );
                            ui.add_space(12.0);

                            for (icon, label, detail) in [
                                ("🐛", "Bug reports", "DM macke.0 or post in #bugs"),
                                ("💡", "Feature requests", "Post in #feature-requests"),
                            ] {
                                let row_col = egui::Color32::from_rgba_unmultiplied(
                                    c_row.r(), c_row.g(), c_row.b(), (t2 * 255.0) as u8,
                                );
                                egui::Frame::none()
                                    .fill(row_col)
                                    .rounding(8.0)
                                    .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                                    .stroke(egui::Stroke::new(1.0, border_col))
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.horizontal(|ui| {
                                            ui.label(
                                                egui::RichText::new(icon)
                                                    .size(14.0)
                                                    .color(fade_color(egui::Color32::WHITE, t2)),
                                            );
                                            ui.add_space(8.0);
                                            ui.vertical(|ui| {
                                                ui.label(
                                                    egui::RichText::new(label)
                                                        .size(13.0)
                                                        .strong()
                                                        .color(fade_color(c_title, t2)),
                                                );
                                                ui.label(
                                                    egui::RichText::new(detail)
                                                        .size(12.0)
                                                        .color(fade_color(c_sub, t2)),
                                                );
                                            });
                                        });
                                    });
                                ui.add_space(6.0);
                            }
                        });

                    ui.add_space(12.0);
                }

                // - - - Vault Location card ── (delay 0.26) - - -
                {
                    let t3 = anim_t(0.26);
                    let offset = SLIDE_PX * (1.0 - t3);
                    ui.add_space(offset);

                    let border_col = egui::Color32::from_rgba_unmultiplied(
                        c_border.r(), c_border.g(), c_border.b(), (t3 * 255.0) as u8,
                    );
                    let card_col = egui::Color32::from_rgba_unmultiplied(
                        c_card.r(), c_card.g(), c_card.b(), (t3 * 255.0) as u8,
                    );

                    egui::Frame::none()
                        .fill(card_col)
                        .rounding(card_rounding)
                        .inner_margin(card_margin)
                        .stroke(egui::Stroke::new(1.0, border_col))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());

                            ui.label(
                                egui::RichText::new("Vault storage")
                                    .size(11.0)
                                    .color(fade_color(c_sub, t3)),
                            );
                            ui.add_space(8.0);

                            ui.label(
                                egui::RichText::new("Your vault is stored as an encrypted file on this computer. To move it to another device, copy the vault file from the path below.")
                                    .size(13.0)
                                    .color(fade_color(c_title, t3)),
                            );
                            ui.add_space(10.0);

                            // - - - Path display box - - -
                            let path_str = self.vault_path.to_string_lossy().to_string();
                            let path_bg = if dm {
                                egui::Color32::from_rgba_unmultiplied(13, 14, 21, (t3 * 255.0) as u8)
                            } else {
                                egui::Color32::from_rgba_unmultiplied(242, 240, 236, (t3 * 255.0) as u8)
                            };
                            let path_border = egui::Color32::from_rgba_unmultiplied(
                                c_border.r(), c_border.g(), c_border.b(), (t3 * 200.0) as u8,
                            );
                            egui::Frame::none()
                                .fill(path_bg)
                                .rounding(7.0)
                                .inner_margin(egui::Margin::symmetric(10.0, 8.0))
                                .stroke(egui::Stroke::new(1.0, path_border))
                                .show(ui, |ui| {
                                    ui.label(
                                        egui::RichText::new(&path_str)
                                            .size(11.0)
                                            .monospace()
                                            .color(fade_color(c_sub, t3)),
                                    );
                                });

                            ui.add_space(10.0);

                            // - - - "Open folder" + "Copy path" buttons, side by side - - -
                            let btn_col = egui::Color32::from_rgba_unmultiplied(
                                if dm { 36 } else { 240 },
                                if dm { 40 } else { 240 },
                                if dm { 62 } else { 252 },
                                (t3 * 255.0) as u8,
                            );
                            let btn_border = egui::Color32::from_rgba_unmultiplied(99, 111, 245, (t3 * 200.0) as u8);
                            let btn_text_col = if dm {
                                fade_color(egui::Color32::from_rgb(180, 188, 255), t3)
                            } else {
                                fade_color(accent, t3)
                            };
                            let half_w = (ui.available_width() - 8.0) / 2.0;

                            ui.horizontal(|ui| {
                                let open_btn = egui::Button::new(
                                    egui::RichText::new("📂  Open folder")
                                        .size(12.0)
                                        .color(btn_text_col),
                                )
                                .fill(btn_col)
                                .stroke(egui::Stroke::new(1.0, btn_border))
                                .rounding(8.0)
                                .min_size(egui::vec2(half_w, 32.0));

                                if ui.add(open_btn).clicked() {
                                    // - - - Open the parent directory in the OS file manager - - -
                                    if let Some(parent) = self.vault_path.parent() {
                                        #[cfg(target_os = "windows")]
                                        { let _ = std::process::Command::new("explorer").arg(parent).spawn(); }
                                        #[cfg(target_os = "macos")]
                                        { let _ = std::process::Command::new("open").arg(parent).spawn(); }
                                        #[cfg(target_os = "linux")]
                                        { let _ = std::process::Command::new("xdg-open").arg(parent).spawn(); }
                                    }
                                }

                                ui.add_space(8.0);

                                let copy_btn = egui::Button::new(
                                    egui::RichText::new("📋  Copy path")
                                        .size(12.0)
                                        .color(btn_text_col),
                                )
                                .fill(btn_col)
                                .stroke(egui::Stroke::new(1.0, btn_border))
                                .rounding(8.0)
                                .min_size(egui::vec2(half_w, 32.0));

                                if ui.add(copy_btn).clicked() {
                                    if let Ok(mut cb) = Clipboard::new() {
                                        let _ = cb.set_text(path_str.clone());
                                        self.push_toast("Vault path copied to clipboard.".into(), ToastKind::Success);
                                    }
                                }
                            });
                        });

                    ui.add_space(24.0);
                }
            });
                });
        });
    }
    
    fn draw_toasts(&mut self, ctx: &egui::Context) {
        let dm = self.dark_mode;
        let now = Instant::now();

        // - - - Expire old toasts - - -
        self.toasts.retain(|t| now.duration_since(t.spawned).as_secs_f32() < TOAST_TOTAL_SECS);

        let screen_rect = ctx.screen_rect();
        let toast_w = 300.0_f32;
        // - - - Anchored Top-Right layout - - -
        let toast_x = screen_rect.width() - toast_w - 16.0;  
        let base_y  = 16.0_f32;  // - - - top margin - - -

        // - - - Collect render info first to avoid borrow issues - - -
        let renders: Vec<(String, ToastKind, f32, f32)> = self.toasts.iter().enumerate().map(|(i, t)| {
            let elapsed = now.duration_since(t.spawned).as_secs_f32();
            // - - - y offset: fly in from above (negative → 0), fly out upward (0 → negative) - - -
            let y_offset = if elapsed < TOAST_ENTER_SECS {
                // - - - entering: fly down from -60 - - -
                let p = elapsed / TOAST_ENTER_SECS;
                let p = 1.0 - (1.0 - p) * (1.0 - p);  // - - - ease-out quad - - -
                -60.0 * (1.0 - p)
            } else if elapsed > TOAST_ENTER_SECS + TOAST_HOLD_SECS {
                // - - - exiting: fly up - - -
                let p = (elapsed - TOAST_ENTER_SECS - TOAST_HOLD_SECS) / TOAST_EXIT_SECS;
                let p = p * p;  // - - - ease-in quad - - -
                -70.0 * p
            } else {
                0.0
            };

            let alpha = if elapsed < TOAST_ENTER_SECS {
                elapsed / TOAST_ENTER_SECS
            } else if elapsed > TOAST_ENTER_SECS + TOAST_HOLD_SECS {
                1.0 - (elapsed - TOAST_ENTER_SECS - TOAST_HOLD_SECS) / TOAST_EXIT_SECS
            } else {
                1.0
            }.clamp(0.0, 1.0);

            let stack_y = base_y + (i as f32) * 62.0 + y_offset;
            (t.message.clone(), t.kind.clone(), stack_y, alpha)
        }).collect();

        if renders.is_empty() { return; }

        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Foreground,
            egui::Id::new("toasts_layer"),
        ));

        for (message, kind, y, alpha) in renders {
            let rect = egui::Rect::from_min_size(
                egui::pos2(toast_x, y),
                egui::vec2(toast_w, 48.0),
            );

            let (bg, border, icon, text_col) = match kind {
                ToastKind::Success => (
                    if dm { egui::Color32::from_rgb(18, 44, 28) } else { egui::Color32::from_rgb(226, 244, 234) },
                    egui::Color32::from_rgb(55, 160, 88),
                    "✅",
                    egui::Color32::from_rgb(100, 210, 140),
                ),
                ToastKind::Error => (
                    if dm { egui::Color32::from_rgb(52, 22, 22) } else { egui::Color32::from_rgb(255, 236, 236) },
                    egui::Color32::from_rgb(180, 55, 55),
                    "❌",
                    egui::Color32::from_rgb(255, 120, 120),
                ),
                ToastKind::Info => (
                    if dm { egui::Color32::from_rgb(22, 26, 52) } else { egui::Color32::from_rgb(238, 236, 252) },
                    egui::Color32::from_rgb(88, 101, 242),
                    "ℹ️",
                    egui::Color32::from_rgb(140, 170, 255),
                ),
            };

            fn with_alpha(c: egui::Color32, a: f32) -> egui::Color32 {
                let a8 = (a * 255.0) as u8;
                egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a8)
            }

            // - - - Shadow - - -
            painter.rect_filled(
                rect.translate(egui::vec2(2.0, 2.0)),
                10.0,
                with_alpha(egui::Color32::from_rgb(0, 0, 0), alpha * 0.25),
            );
            // - - - Background - - -
            painter.rect_filled(rect, 10.0, with_alpha(bg, alpha));
            // - - - Border - - -
            painter.rect_stroke(rect, 10.0, egui::Stroke::new(1.0, with_alpha(border, alpha)));

            // - - - Icon - - -
            let icon_pos = egui::pos2(rect.left() + 14.0, rect.center().y);
            painter.text(
                icon_pos,
                egui::Align2::LEFT_CENTER,
                icon,
                egui::FontId::proportional(13.0),
                with_alpha(egui::Color32::WHITE, alpha),
            );

            // - - - Message (truncate if too long) - - -
            let max_chars = 38;
            let display_msg = if message.len() > max_chars {
                format!("{}…", &message[..max_chars])
            } else {
                message
            };
            painter.text(
                egui::pos2(rect.left() + 34.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                display_msg,
                egui::FontId::proportional(12.0),
                with_alpha(text_col, alpha),
            );
        }

        // - - - Keep repainting while toasts are animating - - -
        if !self.toasts.is_empty() {
            ctx.request_repaint();
        }
    }

    fn draw_modals(&mut self, ctx: &egui::Context) {
        let mut current_modal = std::mem::take(&mut self.modal);
        let mut modal_is_open = true;
        let mut close_on_action = false;

        let dm = self.dark_mode;
        let accent    = egui::Color32::from_rgb(99, 111, 245);
        let green     = egui::Color32::from_rgb(66, 153, 54);
        let c_title   = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(14, 12, 20) };
        let c_sub     = if dm { egui::Color32::from_rgb(160, 162, 185) } else { egui::Color32::from_rgb(90, 86, 100) };
        // - - - Modal window: clearly lighter than panel (18,20,28) - - -
        let c_win     = if dm { egui::Color32::from_rgb(28, 31, 44)  } else { egui::Color32::WHITE };
        // - - - Input: clearly darker than modal window — deep inset look - - -
        let c_input   = if dm { egui::Color32::from_rgb(13, 14, 21)  } else { egui::Color32::from_rgb(243, 241, 250) };
        // - - - Border: well above both fills - - -
        let c_border  = if dm { egui::Color32::from_rgb(62, 68, 95)  } else { egui::Color32::from_rgb(210, 205, 225) };
        // - - - Field labels: bright enough to read easily - - -
        let c_lbl     = if dm { egui::Color32::from_rgb(188, 190, 215) } else { egui::Color32::from_rgb(60, 55, 75) };
        // - - - Cancel button: clearly visible, not overpowering - - -
        let c_cancel  = if dm { egui::Color32::from_rgb(45, 50, 70)  } else { egui::Color32::from_rgb(235, 232, 242) };

        // - - - Helper to make a styled input field frame - - -
        let input_field = |_ui: &mut egui::Ui, fill: egui::Color32, stroke: egui::Stroke| {
            egui::Frame::none().fill(fill).rounding(9.0)
                .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(stroke)
        };

        match &mut current_modal {
            Modal::None => return,

            // - - -  - - -
            // - - - BETA SOFTWARE WARNING (shown on first launch) - - -
            // - - -  - - -
            Modal::BetaWarning => {
                let amber = egui::Color32::from_rgb(240, 160, 50);
                egui::Window::new("beta_warning_modal")
                    .resizable(false).collapsible(false)
                    .default_width(460.0)
                    .title_bar(false)
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(c_win)
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.5, c_border))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        // - - - Header - - -
                        let header_bg = if dm { egui::Color32::from_rgb(40, 33, 16) } else { egui::Color32::from_rgb(255, 248, 235) };
                        egui::Frame::none()
                            .fill(header_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(60, 48, 18) } else { egui::Color32::from_rgb(255, 235, 195) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("⚠️").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Beta Software Warning").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                            egui::Stroke::new(1.0, c_border));

                        // - - - Body - - -
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("ZeroPass is currently in beta.").size(13.5).strong().color(c_title));
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new("While extensive effort has been made to ensure reliability and security, this software has not yet undergone extensive public testing or a formal security audit. Unexpected bugs, crashes, or data corruption may occur.")
                                        .size(13.0).color(c_sub)
                                );
                                ui.add_space(14.0);

                                // - - - Backup advice callout - - -
                                egui::Frame::none()
                                    .fill(if dm { egui::Color32::from_rgb(40, 33, 16) } else { egui::Color32::from_rgb(255, 248, 235) })
                                    .rounding(10.0)
                                    .inner_margin(egui::Margin::symmetric(14.0, 12.0))
                                    .stroke(egui::Stroke::new(1.0, amber))
                                    .show(ui, |ui| {
                                        ui.set_min_width(ui.available_width());
                                        ui.label(
                                            egui::RichText::new("Please do not rely on ZeroPass as your only source of stored credentials. We strongly recommend regularly creating encrypted backups of your vault and keeping additional copies in a safe location.")
                                                .size(13.0).color(c_title)
                                        );
                                    });

                                ui.add_space(14.0);
                                ui.label(
                                    egui::RichText::new("By continuing, you acknowledge that you are using beta software and accept the associated risks.")
                                        .size(11.5).italics().color(c_sub)
                                );
                            });

                        // - - - Footer - - -
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                            egui::Stroke::new(1.0, c_border));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                let btn = egui::Button::new(
                                    egui::RichText::new("I Understand").size(13.5).strong().color(egui::Color32::WHITE)
                                ).fill(accent).rounding(9.0).min_size(egui::vec2(ui.available_width(), 36.0));
                                if ui.add(btn).clicked() {
                                    self.has_seen_beta_warning = true;
                                    save_settings(&self.to_settings());
                                    close_on_action = true;
                                }
                            });
                    });
            }

            // - - -  - - -
            // - - - ADD ENTRY - - -
            // - - -  - - -
            Modal::AddEntry { service, username, password, password_length, totp_secret, totp_open, category, tags } => {
                egui::Window::new("➕  Add New Entry")
                    .resizable(false).collapsible(false)
                    .default_width(460.0)
                    .title_bar(false)
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(c_win)
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.0, c_border))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        // - - - Title bar - - -
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("➕").size(13.0).color(if dm { egui::Color32::from_rgb(90, 190, 120) } else { egui::Color32::from_rgb(32, 128, 60) })); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Add New Entry").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));

                        // - - - Scrollable form body - - -
                        egui::ScrollArea::vertical()
                            .max_height(340.0)
                            .show(ui, |ui| {
                            egui::Frame::none()
                                .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 10.0 })
                                .show(ui, |ui| {
                                // - - - Sub-header - - -
                                ui.label(egui::RichText::new("Fill in the details for the new entry.").size(12.0).color(c_sub));
                                ui.add_space(12.0);

                                // - - - Section label: Credentials - - -
                                {
                                    let pill_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                    let pill_txt = if dm { egui::Color32::from_rgb(90, 190, 120) } else { egui::Color32::from_rgb(32, 128, 60) };
                                    ui.horizontal(|ui| {
                                        egui::Frame::none().fill(pill_bg).rounding(6.0)
                                            .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                            .show(ui, |ui| {
                                                ui.label(egui::RichText::new("🔐").size(11.0).color(pill_txt));
                                            });
                                        ui.add_space(6.0);
                                        ui.label(egui::RichText::new("CREDENTIALS").size(10.5).strong().color(c_sub));
                                    });
                                    let sep = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(215, 210, 228) };
                                    ui.add_space(2.0);
                                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, sep));
                                }
                                ui.add_space(10.0);

                                let field_stroke = egui::Stroke::new(1.0, c_border);

                                // - - - Service - - -
                                ui.label(egui::RichText::new("🌐  Service").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(service)
                                .hint_text("e.g. GitHub, Gmail, Netflix")
                                .char_limit(60)
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(10.0);

                        // - - - Username - - -
                        ui.label(egui::RichText::new("👤  Username / Email").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(username)
                                .hint_text("Username or email address")
                                .char_limit(100)
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(10.0);

                        // - - - Password - - -
                        ui.label(egui::RichText::new("🔐  Password").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(password)
                                .password(true)
                                .hint_text("Enter or generate a password")
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(6.0);

                        // - - - Inline quick-generate button - - -
                        ui.horizontal(|ui| {
                            let gen_btn = egui::Button::new(
                                egui::RichText::new("🎲  Generate").size(11.5).color(egui::Color32::WHITE)
                            ).fill(accent).rounding(7.0).min_size(egui::vec2(110.0, 26.0));
                            if ui.add(gen_btn).clicked() {
                                *password = generate_password(
                                    *password_length as usize,
                                    self.gen_use_uppercase,
                                    self.gen_use_numbers,
                                    self.gen_use_symbols
                                );
                            }
                            ui.add_space(8.0);
                            ui.label(egui::RichText::new("or use the").size(11.0).color(c_sub));
                            ui.add_space(2.0);
                            if ui.add(egui::Button::new(
                                egui::RichText::new("Generator tab").size(11.0).color(accent)
                            ).fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE).rounding(3.0)).clicked() {
                                self.state = AppState::GeneratorView;
                                self.generator_page_opened = Some(Instant::now());
                            }
                        });

                        ui.add_space(14.0);

                        // - - - Metadata section header - - -
                        {
                            let pill_bg = if dm { egui::Color32::from_rgb(28, 35, 55) } else { egui::Color32::from_rgb(228, 225, 248) };
                            let pill_txt = if dm { egui::Color32::from_rgb(145, 155, 235) } else { egui::Color32::from_rgb(80, 72, 200) };
                            ui.horizontal(|ui| {
                                egui::Frame::none().fill(pill_bg).rounding(6.0)
                                    .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                    .show(ui, |ui| {
                                        ui.label(egui::RichText::new("📁").size(11.0).color(pill_txt));
                                    });
                                ui.add_space(6.0);
                                ui.label(egui::RichText::new("METADATA  (optional)").size(10.5).strong().color(c_sub));
                            });
                            let sep = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(215, 210, 228) };
                            ui.add_space(2.0);
                            ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, sep));
                        }
                        ui.add_space(10.0);

                        // - - - Category - - -
                        ui.label(egui::RichText::new("📁  Category").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(category)
                                .hint_text("e.g. Work, Finance, Social")
                                .char_limit(30)
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(10.0);

                        // - - - Tags - - -
                        ui.label(egui::RichText::new("🏷  Tags").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(tags)
                                .hint_text("e.g. personal, 2fa, important  (comma separated)")
                                .char_limit(150)
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(18.0);

                        // - - - TOTP secret dropdown - - -
                        {
                            let has_secret = !totp_secret.is_empty();
                            // - - - animate_bool_with_time gives a smooth 0→1 float tied to the toggle state - - -
                            let t = ctx.animate_bool_with_time(egui::Id::new("add_totp_open"), *totp_open, 0.20);
                            if t > 0.0 && t < 1.0 { ui.ctx().request_repaint(); }

                            // - - - Interpolate header colors between closed and open - - -
                            let lerp_color = |a: egui::Color32, b: egui::Color32, t: f32| -> egui::Color32 {
                                egui::Color32::from_rgb(
                                    (a.r() as f32 + (b.r() as f32 - a.r() as f32) * t) as u8,
                                    (a.g() as f32 + (b.g() as f32 - a.g() as f32) * t) as u8,
                                    (a.b() as f32 + (b.b() as f32 - a.b() as f32) * t) as u8,
                                )
                            };
                            let bg_closed = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::from_rgb(244, 242, 238) };
                            let bg_open   = if dm { egui::Color32::from_rgb(28, 32, 52) } else { egui::Color32::from_rgb(235, 232, 252) };
                            let header_bg = lerp_color(bg_closed, bg_open, t);
                            let stroke_col = lerp_color(c_border, accent, t);
                            let header_stroke = egui::Stroke::new(1.0, stroke_col);
                            let lbl_col = lerp_color(c_lbl, accent, t);

                            // - - - Bottom corners stay sharp while open (body panel attached below) - - -
                            let bot_r = (1.0 - t) * 9.0;
                            let rounding = egui::Rounding { nw: 9.0, ne: 9.0, sw: bot_r, se: bot_r };

                            // - - - Rotate the arrow: 0° closed, 180° open - - -
                            let arrow_angle = t * std::f32::consts::PI;

                            let header_resp = egui::Frame::none()
                                .fill(header_bg)
                                .rounding(rounding)
                                .inner_margin(egui::Margin { left: 12.0, right: 10.0, top: 9.0, bottom: 9.0 })
                                .stroke(header_stroke)
                                .show(ui, |ui| {
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("🔑").size(13.0));
                                        ui.add_space(6.0);
                                        ui.label(egui::RichText::new("TOTP Secret  (optional)").size(12.0).color(lbl_col));
                                        if has_secret {
                                            ui.add_space(6.0);
                                            let badge_bg = if dm { egui::Color32::from_rgb(36, 55, 36) } else { egui::Color32::from_rgb(220, 245, 225) };
                                            egui::Frame::none().fill(badge_bg).rounding(6.0)
                                                .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                                .show(ui, |ui| {
                                                    ui.label(egui::RichText::new("set").size(10.0).color(egui::Color32::from_rgb(72, 199, 116)));
                                                });
                                        }
                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                            // - - - Draw a rotated chevron using the painter - - -
                                            let (arrow_rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
                                            let c = arrow_rect.center();
                                            let painter = ui.painter();
                                            let hw = 4.5_f32; // - - - half-width of chevron arms - - -
                                            let hh = 2.8_f32;
                                            // - - - Chevron points: left tip, center bottom, right tip - - -
                                            // - - - At angle=0 it points down (▼), at angle=PI it points up (▲) - - -
                                            let pts_local = [
                                                egui::vec2(-hw, -hh),
                                                egui::vec2(0.0,  hh),
                                                egui::vec2( hw, -hh),
                                            ];
                                            let cos_a = arrow_angle.cos();
                                            let sin_a = arrow_angle.sin();
                                            let rot = |v: egui::Vec2| egui::vec2(
                                                v.x * cos_a - v.y * sin_a,
                                                v.x * sin_a + v.y * cos_a,
                                            );
                                            let p: Vec<egui::Pos2> = pts_local.iter().map(|&v| c + rot(v)).collect();
                                            let arrow_col = egui::Color32::from_rgba_unmultiplied(
                                                c_sub.r(), c_sub.g(), c_sub.b(),
                                                (128.0 + 127.0 * t) as u8,
                                            );
                                            painter.line_segment([p[0], p[1]], egui::Stroke::new(1.8, arrow_col));
                                            painter.line_segment([p[1], p[2]], egui::Stroke::new(1.8, arrow_col));
                                        });
                                    });
                                });
                            if header_resp.response.interact(egui::Sense::click()).clicked() {
                                *totp_open = !*totp_open;
                                // - - - Do NOT clear the secret — user may just be collapsing to save space - - -
                            }

                            // - - - Clip the body to t * full_height so it slides open/shut - - -
                            if t > 0.0 {
                                let body_bg = if dm { egui::Color32::from_rgb(15, 16, 26) } else { egui::Color32::from_rgb(248, 246, 255) };
                                let body_stroke_col = egui::Color32::from_rgba_unmultiplied(
                                    accent.r(), accent.g(), accent.b(), (t * 255.0) as u8,
                                );
                                // - - - Measure the full body height first, then clip via max_rect - - -
                                let full_body_height = 120.0_f32; // - - - generous max; clipped anyway - - -
                                let clip_height = t * full_body_height;
                                let avail = ui.available_rect_before_wrap();
                                let clip_rect = egui::Rect::from_min_size(
                                    avail.min,
                                    egui::vec2(avail.width(), clip_height),
                                );
                                let mut child_ui = ui.child_ui(clip_rect, egui::Layout::top_down(egui::Align::Min), None);
                                egui::Frame::none()
                                    .fill(body_bg)
                                    .rounding(egui::Rounding { nw: 0.0, ne: 0.0, sw: 9.0, se: 9.0 })
                                    .inner_margin(egui::Margin { left: 12.0, right: 12.0, top: 10.0, bottom: 10.0 })
                                    .stroke(egui::Stroke::new(1.0, body_stroke_col))
                                    .show(&mut child_ui, |ui| {
                                        let totp_valid = totp_secret.is_empty() || totp_base32_decode(totp_secret).is_some();
                                        let field_stroke = if totp_valid {
                                            egui::Stroke::new(1.0, c_border)
                                        } else {
                                            egui::Stroke::new(1.5, egui::Color32::from_rgb(210, 60, 60))
                                        };
                                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                            ui.add(egui::TextEdit::singleline(totp_secret)
                                                .hint_text("Base32 secret from QR code (e.g. JBSWY3DPEHPK3PXP)")
                                                .desired_width(ui.available_width()).frame(false));
                                        });
                                        if !totp_secret.is_empty() {
                                            ui.add_space(6.0);
                                            if let Some((code, secs)) = totp_now(totp_secret) {
                                                let totp_bg = if dm { egui::Color32::from_rgb(18, 22, 42) } else { egui::Color32::from_rgb(235, 232, 252) };
                                                egui::Frame::none().fill(totp_bg).rounding(8.0)
                                                    .inner_margin(egui::Margin::symmetric(12.0, 7.0))
                                                    .stroke(egui::Stroke::new(1.0, accent))
                                                    .show(ui, |ui| {
                                                        ui.horizontal(|ui| {
                                                            ui.label(egui::RichText::new("🔒").size(13.0));
                                                            ui.add_space(6.0);
                                                            ui.label(egui::RichText::new(&code).size(18.0).strong().monospace().color(accent));
                                                            ui.add_space(8.0);
                                                            ui.label(egui::RichText::new(format!("{}s", secs)).size(11.5).color(c_sub));
                                                        });
                                                    });
                                                ui.ctx().request_repaint_after(Duration::from_secs(1));
                                            } else {
                                                ui.label(egui::RichText::new("⚠  Invalid base32 secret").size(11.5)
                                                    .color(egui::Color32::from_rgb(210, 80, 80)));
                                            }
                                        }
                                    });
                                // - - - Advance the cursor by clip_height so layout below isn't affected - - -
                                ui.advance_cursor_after_rect(egui::Rect::from_min_size(avail.min, egui::vec2(avail.width(), clip_height)));
                            }
                        }

                        ui.add_space(10.0);

                        }); // - - - inner frame - - -
                        }); // - - - scroll area - - -

                        // - - - Sticky footer: always visible action buttons - - -
                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let can_add = !service.is_empty() && !username.is_empty();
                                    let add_fill = if can_add { green } else {
                                        if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(194, 189, 180) }
                                    };
                                    let add_btn = egui::Button::new(
                                        egui::RichText::new("➕  Add Entry").size(13.5).color(egui::Color32::WHITE)
                                    ).fill(add_fill).rounding(9.0).min_size(egui::vec2(130.0, 36.0));
                                    if ui.add_enabled(can_add, add_btn).clicked() {
                                        let secret = if totp_secret.is_empty() { None } else { Some(totp_secret.trim().to_uppercase().replace([' ', '-'], "")) };
                                        let cat = if category.trim().is_empty() { None } else { Some(category.trim().to_string()) };
                                        let parsed_tags: Vec<String> = tags.split(',')
                                            .map(|t| t.trim().to_lowercase())
                                            .filter(|t| !t.is_empty())
                                            .collect();
                                        self.add_entry_and_save(service.clone(), username.clone(), password.clone(), secret, cat, parsed_tags);
                                        close_on_action = true;
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            });
                    });
            }
            // - - -  - - -
            // - - - EDIT ENTRY - - -
            // - - -  - - -
            Modal::EditEntry { original_id, service, username, password, totp_secret, totp_open, category, tags } => {
                egui::Window::new("edit_entry_modal")
                    .resizable(false).collapsible(false)
                    .default_width(460.0)
                    .title_bar(false)
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(c_win)
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.0, c_border))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        // - - - Title bar - - -
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(28, 35, 55) } else { egui::Color32::from_rgb(228, 225, 248) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("✏️").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Edit Entry").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));

                        // - - - Scrollable form body - - -
                        egui::ScrollArea::vertical()
                            .max_height(340.0)
                            .show(ui, |ui| {
                            egui::Frame::none()
                                .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 10.0 })
                                .show(ui, |ui| {
                                let field_stroke = egui::Stroke::new(1.0, c_border);

                                // - - - Credentials section header - - -
                                {
                                    let pill_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                    let pill_txt = if dm { egui::Color32::from_rgb(90, 190, 120) } else { egui::Color32::from_rgb(32, 128, 60) };
                                    ui.horizontal(|ui| {
                                        egui::Frame::none().fill(pill_bg).rounding(6.0)
                                            .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                            .show(ui, |ui| {
                                                ui.label(egui::RichText::new("🔐").size(11.0).color(pill_txt));
                                            });
                                        ui.add_space(6.0);
                                        ui.label(egui::RichText::new("CREDENTIALS").size(10.5).strong().color(c_sub));
                                    });
                                    let sep = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(215, 210, 228) };
                                    ui.add_space(2.0);
                                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, sep));
                                }
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("🌐  Service").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(service).char_limit(60).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("👤  Username / Email").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(username).char_limit(100).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("🔐  Password").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(password).password(true).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                // - - - TOTP secret dropdown - - -
                                {
                                    let has_secret = !totp_secret.is_empty();
                                    let t = ctx.animate_bool_with_time(egui::Id::new("edit_totp_open"), *totp_open, 0.20);
                                    if t > 0.0 && t < 1.0 { ui.ctx().request_repaint(); }

                                    let lerp_color = |a: egui::Color32, b: egui::Color32, t: f32| -> egui::Color32 {
                                        egui::Color32::from_rgb(
                                            (a.r() as f32 + (b.r() as f32 - a.r() as f32) * t) as u8,
                                            (a.g() as f32 + (b.g() as f32 - a.g() as f32) * t) as u8,
                                            (a.b() as f32 + (b.b() as f32 - a.b() as f32) * t) as u8,
                                        )
                                    };
                                    let bg_closed = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::from_rgb(244, 242, 238) };
                                    let bg_open   = if dm { egui::Color32::from_rgb(28, 32, 52) } else { egui::Color32::from_rgb(235, 232, 252) };
                                    let header_bg = lerp_color(bg_closed, bg_open, t);
                                    let stroke_col = lerp_color(c_border, accent, t);
                                    let header_stroke = egui::Stroke::new(1.0, stroke_col);
                                    let lbl_col = lerp_color(c_lbl, accent, t);

                                    let bot_r = (1.0 - t) * 9.0;
                                    let rounding = egui::Rounding { nw: 9.0, ne: 9.0, sw: bot_r, se: bot_r };

                                    let arrow_angle = t * std::f32::consts::PI;

                                    let header_resp = egui::Frame::none()
                                        .fill(header_bg)
                                        .rounding(rounding)
                                        .inner_margin(egui::Margin { left: 12.0, right: 10.0, top: 9.0, bottom: 9.0 })
                                        .stroke(header_stroke)
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(egui::RichText::new("🔑").size(13.0));
                                                ui.add_space(6.0);
                                                ui.label(egui::RichText::new("TOTP Secret").size(12.0).color(lbl_col));
                                                if has_secret {
                                                    ui.add_space(6.0);
                                                    let badge_bg = if dm { egui::Color32::from_rgb(36, 55, 36) } else { egui::Color32::from_rgb(220, 245, 225) };
                                                    egui::Frame::none().fill(badge_bg).rounding(6.0)
                                                        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
                                                        .show(ui, |ui| {
                                                            ui.label(egui::RichText::new("set").size(10.0).color(egui::Color32::from_rgb(72, 199, 116)));
                                                        });
                                                }
                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    let (arrow_rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
                                                    let c = arrow_rect.center();
                                                    let painter = ui.painter();
                                                    let hw = 4.5_f32;
                                                    let hh = 2.8_f32;
                                                    let pts_local = [
                                                        egui::vec2(-hw, -hh),
                                                        egui::vec2(0.0,  hh),
                                                        egui::vec2( hw, -hh),
                                                    ];
                                                    let cos_a = arrow_angle.cos();
                                                    let sin_a = arrow_angle.sin();
                                                    let rot = |v: egui::Vec2| egui::vec2(
                                                        v.x * cos_a - v.y * sin_a,
                                                        v.x * sin_a + v.y * cos_a,
                                                    );
                                                    let p: Vec<egui::Pos2> = pts_local.iter().map(|&v| c + rot(v)).collect();
                                                    let arrow_col = egui::Color32::from_rgba_unmultiplied(
                                                        c_sub.r(), c_sub.g(), c_sub.b(),
                                                        (128.0 + 127.0 * t) as u8,
                                                    );
                                                    painter.line_segment([p[0], p[1]], egui::Stroke::new(1.8, arrow_col));
                                                    painter.line_segment([p[1], p[2]], egui::Stroke::new(1.8, arrow_col));
                                                });
                                            });
                                        });
                                    if header_resp.response.interact(egui::Sense::click()).clicked() {
                                        *totp_open = !*totp_open;
                                        // - - - Do NOT clear the secret on collapse - - -
                                    }

                                    if t > 0.0 {
                                        let body_bg = if dm { egui::Color32::from_rgb(15, 16, 26) } else { egui::Color32::from_rgb(248, 246, 255) };
                                        let body_stroke_col = egui::Color32::from_rgba_unmultiplied(
                                            accent.r(), accent.g(), accent.b(), (t * 255.0) as u8,
                                        );
                                        let full_body_height = 120.0_f32;
                                        let clip_height = t * full_body_height;
                                        let avail = ui.available_rect_before_wrap();
                                        let clip_rect = egui::Rect::from_min_size(
                                            avail.min,
                                            egui::vec2(avail.width(), clip_height),
                                        );
                                        let mut child_ui = ui.child_ui(clip_rect, egui::Layout::top_down(egui::Align::Min), None);
                                        egui::Frame::none()
                                            .fill(body_bg)
                                            .rounding(egui::Rounding { nw: 0.0, ne: 0.0, sw: 9.0, se: 9.0 })
                                            .inner_margin(egui::Margin { left: 12.0, right: 12.0, top: 10.0, bottom: 10.0 })
                                            .stroke(egui::Stroke::new(1.0, body_stroke_col))
                                            .show(&mut child_ui, |ui| {
                                                let totp_valid = totp_secret.is_empty() || totp_base32_decode(totp_secret).is_some();
                                                let totp_stroke = if totp_valid { field_stroke } else {
                                                    egui::Stroke::new(1.5, egui::Color32::from_rgb(210, 60, 60))
                                                };
                                                input_field(ui, c_input, totp_stroke).show(ui, |ui| {
                                                    ui.add(egui::TextEdit::singleline(totp_secret)
                                                        .hint_text("Base32 secret — leave blank to remove")
                                                        .desired_width(ui.available_width()).frame(false));
                                                });
                                                if !totp_secret.is_empty() {
                                                    ui.add_space(6.0);
                                                    if let Some((code, secs)) = totp_now(totp_secret) {
                                                        let totp_bg = if dm { egui::Color32::from_rgb(18, 22, 42) } else { egui::Color32::from_rgb(235, 232, 252) };
                                                        egui::Frame::none().fill(totp_bg).rounding(8.0)
                                                            .inner_margin(egui::Margin::symmetric(12.0, 7.0))
                                                            .stroke(egui::Stroke::new(1.0, accent))
                                                            .show(ui, |ui| {
                                                                ui.horizontal(|ui| {
                                                                    ui.label(egui::RichText::new("🔒").size(13.0));
                                                                    ui.add_space(6.0);
                                                                    ui.label(egui::RichText::new(&code).size(18.0).strong().monospace().color(accent));
                                                                    ui.add_space(8.0);
                                                                    ui.label(egui::RichText::new(format!("{}s", secs)).size(11.5).color(c_sub));
                                                                });
                                                            });
                                                        ui.ctx().request_repaint_after(Duration::from_secs(1));
                                                    } else {
                                                        ui.label(egui::RichText::new("⚠  Invalid base32 secret").size(11.5)
                                                            .color(egui::Color32::from_rgb(210, 80, 80)));
                                                    }
                                                }
                                            });
                                        ui.advance_cursor_after_rect(egui::Rect::from_min_size(avail.min, egui::vec2(avail.width(), clip_height)));
                                    }
                                }

                                ui.add_space(18.0);

                                // - - - Metadata section header - - -
                                {
                                    let pill_bg = if dm { egui::Color32::from_rgb(28, 35, 55) } else { egui::Color32::from_rgb(228, 225, 248) };
                                    let pill_txt = if dm { egui::Color32::from_rgb(145, 155, 235) } else { egui::Color32::from_rgb(80, 72, 200) };
                                    ui.horizontal(|ui| {
                                        egui::Frame::none().fill(pill_bg).rounding(6.0)
                                            .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                                            .show(ui, |ui| {
                                                ui.label(egui::RichText::new("📁").size(11.0).color(pill_txt));
                                            });
                                        ui.add_space(6.0);
                                        ui.label(egui::RichText::new("METADATA  (optional)").size(10.5).strong().color(c_sub));
                                    });
                                    let sep = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(215, 210, 228) };
                                    ui.add_space(2.0);
                                    ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, sep));
                                }
                                ui.add_space(10.0);

                                // - - - Category - - -
                                ui.label(egui::RichText::new("📁  Category").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(category)
                                        .hint_text("e.g. Work, Finance, Social")
                                        .char_limit(30)
                                        .desired_width(ui.available_width()).frame(false));
                                });

                                ui.add_space(10.0);

                                // - - - Tags - - -
                                ui.label(egui::RichText::new("🏷  Tags").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(tags)
                                        .hint_text("e.g. personal, 2fa, important  (comma separated)")
                                        .char_limit(150)
                                        .desired_width(ui.available_width()).frame(false));
                                });

                                ui.add_space(6.0);

                                }); // - - - inner frame - - -
                            }); // - - - scroll area - - -

                        // - - - Sticky footer: always visible action buttons - - -
                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let save_btn = egui::Button::new(
                                        egui::RichText::new("💾  Save Changes").size(13.5).color(egui::Color32::WHITE)
                                    ).fill(accent).rounding(9.0).min_size(egui::vec2(140.0, 36.0));
                                    if ui.add(save_btn).clicked() {
                                        if let Some(entry) = self.vault.entries.iter_mut().find(|e| &e.id == original_id) {
                                            // - - - Record the outgoing password in history before overwriting it - - -
                                            if &entry.password != password && !entry.password.is_empty() {
                                                let changed_at = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default().as_secs();
                                                entry.password_history.insert(0, PasswordHistoryEntry {
                                                    password: entry.password.clone(),
                                                    changed_at,
                                                });
                                                entry.password_history.truncate(20); // - - - cap history length - - -
                                            }
                                            entry.service = service.clone();
                                            entry.username = username.clone();
                                            entry.password = password.clone();
                                            entry.totp_secret = if totp_secret.is_empty() { None } else {
                                                Some(totp_secret.trim().to_uppercase().replace([' ', '-'], ""))
                                            };
                                            entry.category = if category.trim().is_empty() { None } else {
                                                Some(category.trim().to_string())
                                            };
                                            entry.tags = tags.split(',')
                                                .map(|t| t.trim().to_lowercase())
                                                .filter(|t| !t.is_empty())
                                                .collect();
                                            self.save_after_change();
                                        }
                                        close_on_action = true;
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            });
                    });
            }

            // - - -  - - -
            // - - - PASSWORD HISTORY - - -
            // - - -  - - -
            Modal::PasswordHistory { entry_id } => {
                let entry_label = self.vault.entries.iter()
                    .find(|e| &e.id == entry_id)
                    .map(|e| e.service.clone())
                    .unwrap_or_else(|| "Entry".to_string());
                let history_snapshot: Vec<PasswordHistoryEntry> = self.vault.entries.iter()
                    .find(|e| &e.id == entry_id)
                    .map(|e| e.password_history.clone())
                    .unwrap_or_default();

                let mut copy_request: Option<String> = None;
                let mut clear_requested = false;
                let mut remove_idx: Option<usize> = None;

                egui::Window::new("password_history_modal")
                    .resizable(false).collapsible(false)
                    .default_width(440.0)
                    .title_bar(false)
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(c_win)
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.0, c_border))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(40, 36, 58) } else { egui::Color32::from_rgb(230, 227, 218) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("🕘").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new(format!("Password History — {}", entry_label)).size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));

                        egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                            egui::Frame::none()
                                .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 10.0 })
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    if history_snapshot.is_empty() {
                                        ui.vertical_centered(|ui| {
                                            ui.add_space(20.0);
                                            ui.label(egui::RichText::new("🕘").size(28.0).color(c_sub));
                                            ui.add_space(8.0);
                                            ui.label(egui::RichText::new("No previous passwords recorded yet.").size(12.5).color(c_sub));
                                            ui.add_space(20.0);
                                        });
                                    } else {
                                        ui.label(egui::RichText::new("Previous passwords for this entry, most recent first.").size(12.0).color(c_sub));
                                        ui.add_space(10.0);
                                        for (idx, hist) in history_snapshot.iter().enumerate() {
                                            let row_bg = if dm { egui::Color32::from_rgb(22, 24, 36) } else { egui::Color32::from_rgb(247, 246, 251) };
                                            egui::Frame::none()
                                                .fill(row_bg)
                                                .rounding(9.0)
                                                .inner_margin(egui::Margin::symmetric(12.0, 9.0))
                                                .stroke(egui::Stroke::new(1.0, c_border))
                                                .show(ui, |ui| {
                                                    ui.set_min_width(ui.available_width());
                                                    ui.horizontal(|ui| {
                                                        ui.vertical(|ui| {
                                                            ui.label(egui::RichText::new(&hist.password).size(12.5).monospace().color(c_title));
                                                            ui.add_space(2.0);
                                                            ui.label(egui::RichText::new(format_timestamp_ago(hist.changed_at)).size(10.5).color(c_sub));
                                                        });
                                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                            let del_col = if dm { egui::Color32::from_rgb(215, 80, 80) } else { egui::Color32::from_rgb(190, 50, 50) };
                                                            let del_btn = egui::Button::new(egui::RichText::new("🗑").size(11.5).color(del_col))
                                                                .fill(egui::Color32::TRANSPARENT).stroke(egui::Stroke::NONE)
                                                                .rounding(6.0).min_size(egui::vec2(26.0, 26.0));
                                                            if ui.add(del_btn).on_hover_text("Remove this entry").clicked() {
                                                                remove_idx = Some(idx);
                                                            }
                                                            ui.add_space(4.0);
                                                            let copy_btn = egui::Button::new(egui::RichText::new("Copy").size(11.0).color(accent))
                                                                .fill(if dm { egui::Color32::from_rgba_unmultiplied(99, 111, 245, 30) } else { egui::Color32::from_rgba_unmultiplied(99, 111, 245, 18) })
                                                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(99, 111, 245, 60)))
                                                                .rounding(7.0).min_size(egui::vec2(48.0, 26.0));
                                                            if ui.add(copy_btn).on_hover_text("Copy this password").clicked() {
                                                                copy_request = Some(hist.password.clone());
                                                            }
                                                        });
                                                    });
                                                });
                                            ui.add_space(6.0);
                                        }
                                    }
                                });
                        });

                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if !history_snapshot.is_empty() {
                                        let clear_btn = egui::Button::new(
                                            egui::RichText::new("Clear History").size(13.0).color(
                                                if dm { egui::Color32::from_rgb(215, 80, 80) } else { egui::Color32::from_rgb(190, 50, 50) }
                                            )
                                        ).fill(egui::Color32::TRANSPARENT)
                                         .stroke(egui::Stroke::new(1.0, if dm { egui::Color32::from_rgb(120, 50, 50) } else { egui::Color32::from_rgb(210, 160, 160) }))
                                         .rounding(9.0).min_size(egui::vec2(110.0, 36.0));
                                        if ui.add(clear_btn).clicked() { clear_requested = true; }
                                    }
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let close_btn = egui::Button::new(
                                            egui::RichText::new("Close").size(13.0).color(c_title)
                                        ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                        if ui.add(close_btn).clicked() { close_on_action = true; }
                                    });
                                });
                            });
                    });

                if let Some(pw) = copy_request {
                    self.copy_to_clipboard(pw, entry_label.clone());
                }
                if clear_requested {
                    if let Some(e) = self.vault.entries.iter_mut().find(|e| &e.id == entry_id) {
                        e.password_history.clear();
                    }
                    self.save_after_change();
                    close_on_action = true;
                } else if let Some(idx) = remove_idx {
                    if let Some(e) = self.vault.entries.iter_mut().find(|e| &e.id == entry_id) {
                        if idx < e.password_history.len() {
                            e.password_history.remove(idx);
                        }
                    }
                    self.save_after_change();
                }
            }

            // - - -  - - -
            // - - - CHANGE MASTER PASSWORD - - -
            // - - -  - - -
            Modal::ChangePassword { old, new, confirm } => {
                egui::Window::new("change_pw_modal")
                    .resizable(false).collapsible(false)
                    .default_width(460.0)
                    .title_bar(false)
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(c_win)
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.0, c_border))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(40, 36, 58) } else { egui::Color32::from_rgb(230, 227, 218) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("🔑").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Change Master Password").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Re-encrypts your vault with the new password.").size(12.0).color(c_sub));
                                ui.add_space(14.0);

                                let field_stroke = egui::Stroke::new(1.0, c_border);

                                ui.label(egui::RichText::new("🔒  Current Password").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(old).password(true).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("🔑  New Password").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(new).password(true).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                let mismatch = !new.is_empty() && !confirm.is_empty() && new != confirm;
                                let too_short = !new.is_empty() && new.len() < 8;
                                let confirm_stroke = if mismatch {
                                    egui::Stroke::new(1.5, egui::Color32::from_rgb(210, 60, 60))
                                } else { field_stroke };
                                ui.label(egui::RichText::new("✅  Confirm New Password").size(12.0).color(
                                    if mismatch { egui::Color32::from_rgb(210, 60, 60) } else { c_lbl }
                                ));
                                ui.add_space(4.0);
                                input_field(ui, c_input, confirm_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(confirm).password(true).desired_width(ui.available_width()).frame(false));
                                });

                                if too_short {
                                    ui.add_space(6.0);
                                    let warn_frame = egui::Frame::none()
                                        .fill(if dm { egui::Color32::from_rgb(50, 18, 18) } else { egui::Color32::from_rgb(255, 236, 236) })
                                        .rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(155, 45, 45)));
                                    warn_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("⚠️").size(13.0));
                                            ui.add_space(6.0);
                                            ui.label(egui::RichText::new("Use at least 8 characters").size(12.0)
                                                .color(if dm { egui::Color32::from_rgb(240, 120, 120) } else { egui::Color32::from_rgb(185, 45, 45) }));
                                        });
                                    });
                                } else if mismatch {
                                    ui.add_space(6.0);
                                    let warn_frame = egui::Frame::none()
                                        .fill(if dm { egui::Color32::from_rgb(50, 18, 18) } else { egui::Color32::from_rgb(255, 236, 236) })
                                        .rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(155, 45, 45)));
                                    warn_frame.show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(egui::RichText::new("⚠️").size(13.0));
                                            ui.add_space(6.0);
                                            ui.label(egui::RichText::new("Passwords don't match").size(12.0)
                                                .color(if dm { egui::Color32::from_rgb(240, 120, 120) } else { egui::Color32::from_rgb(185, 45, 45) }));
                                        });
                                    });
                                }
                            }); // - - - inner frame - - -

                        // - - - Sticky footer - - -
                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let can_change = !old.is_empty() && new.len() >= 8 && new == confirm;
                                    let btn_fill = if can_change { accent } else {
                                        if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(194, 189, 180) }
                                    };
                                    let change_btn = egui::Button::new(
                                        egui::RichText::new("💾  Change Password").size(13.5).color(egui::Color32::WHITE)
                                    ).fill(btn_fill).rounding(9.0).min_size(egui::vec2(160.0, 36.0));
                                    if ui.add_enabled(can_change, change_btn).clicked() {
                                        if old != &self.master_password {
                                            self.push_toast("Incorrect current password.".to_string(), ToastKind::Error);
                                        } else {
                                            match save_vault_file(&self.vault_path, &self.vault, new) {
                                                Ok(_) => {
                                                    self.master_password.zeroize();
                                                    self.master_password = new.clone();
                                                    self.handle_success("Master password changed.");
                                                    close_on_action = true;
                                                }
                                                Err(e) => self.handle_error(e),
                                            }
                                        }
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            });
                    });
            }

            // - - -  - - -
            // - - - DELETE VAULT - - -
            // - - -  - - -
            Modal::DeleteVault { confirmation } => {
                egui::Window::new("delete_vault_modal")
                    .resizable(false).collapsible(false)
                    .default_width(460.0)
                    .title_bar(false)
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(c_win)
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.5, egui::Color32::from_rgb(155, 45, 45)))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        let title_bg = if dm { egui::Color32::from_rgb(42, 16, 16) } else { egui::Color32::from_rgb(255, 242, 242) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(70, 22, 22) } else { egui::Color32::from_rgb(255, 220, 220) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("🗑️").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Delete Vault").size(14.0).strong()
                                        .color(if dm { egui::Color32::from_rgb(240, 115, 115) } else { egui::Color32::from_rgb(175, 40, 40) }));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(120, 42, 42)));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                // - - - Warning banner - - -
                                let warn_frame = egui::Frame::none()
                                    .fill(if dm { egui::Color32::from_rgb(50, 18, 18) } else { egui::Color32::from_rgb(255, 238, 238) })
                                    .rounding(10.0)
                                    .inner_margin(egui::Margin::symmetric(14.0, 12.0))
                                    .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(155, 45, 45)));
                                warn_frame.show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(egui::RichText::new("⚠️").size(20.0));
                                        ui.add_space(8.0);
                                        ui.vertical(|ui| {
                                            ui.label(egui::RichText::new("This action is irreversible!").size(13.0).strong()
                                                .color(if dm { egui::Color32::from_rgb(240, 115, 115) } else { egui::Color32::from_rgb(175, 40, 40) }));
                                            ui.add_space(2.0);
                                            ui.label(egui::RichText::new("Your entire vault and all saved passwords will be permanently deleted.").size(12.0)
                                                .color(if dm { egui::Color32::from_rgb(200, 155, 155) } else { egui::Color32::from_rgb(145, 68, 68) }));
                                        });
                                    });
                                });

                                ui.add_space(16.0);

                                ui.label(egui::RichText::new("🔒  Enter master password to confirm").size(12.0).color(c_lbl));
                                ui.add_space(6.0);
                                let field_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(140, 55, 55));
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(confirmation).password(true).desired_width(ui.available_width()).frame(false));
                                });
                            }); // - - - inner frame - - -

                        // - - - Sticky footer - - -
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(),
                            egui::Stroke::new(1.0, egui::Color32::from_rgb(90, 32, 32)));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let enabled = !confirmation.is_empty();
                                    let del_fill = if enabled { egui::Color32::from_rgb(200, 55, 55) } else {
                                        if dm { egui::Color32::from_rgb(60, 40, 40) } else { egui::Color32::from_rgb(210, 190, 190) }
                                    };
                                    let del_btn = egui::Button::new(
                                        egui::RichText::new("🗑️  Delete Vault").size(13.5).color(egui::Color32::WHITE)
                                    ).fill(del_fill).rounding(9.0).min_size(egui::vec2(140.0, 36.0));
                                    if ui.add_enabled(enabled, del_btn).clicked() {
                                        match read_enc_file(&self.vault_path).and_then(|enc| decrypt_vault(&enc, confirmation)) {
                                            Ok(_) => {
                                                if let Err(e) = fs::remove_file(&self.vault_path) {
                                                    self.handle_error(VaultError::Io(e));
                                                } else {
                                                    self.handle_success("Vault deleted successfully.");
                                                    self.lock_vault();
                                                    close_on_action = true;
                                                }
                                            }
                                            Err(_) => self.push_toast("Incorrect password. Vault not deleted.".to_string(), ToastKind::Error),
                                        }
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            });
                    });
            }


            // - - -  - - -
            // - - - SETTINGS  (simple single-panel) - - -
            // - - -  - - -
            // ─── CREATE VAULT MODAL ──────────────────────────────────────────────────
            Modal::CreateVault { name, path_input, password, confirm } => {
                egui::Window::new("create_vault_modal")
                    .resizable(false).collapsible(false)
                    .default_width(480.0).title_bar(false)
                    .frame(egui::Frame::window(&ctx.style()).fill(c_win).rounding(14.0)
                        .stroke(egui::Stroke::new(1.0, c_border)).inner_margin(egui::Margin::same(0.0)))
                    .show(ctx, |ui| {
                        let title_bg = if dm { egui::Color32::from_rgb(20,22,32) } else { egui::Color32::from_rgb(247,246,243) };
                        egui::Frame::none().fill(title_bg)
                            .rounding(egui::Rounding { nw:14.0,ne:14.0,sw:0.0,se:0.0 })
                            .inner_margin(egui::Margin { left:18.0,right:18.0,top:14.0,bottom:14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(22,48,32) } else { egui::Color32::from_rgb(220,248,228) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0,5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("🗂").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Create New Vault").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));
                        egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                        egui::Frame::none().inner_margin(egui::Margin { left:18.0,right:18.0,top:14.0,bottom:10.0 }).show(ui, |ui| {
                            ui.set_min_width(440.0);
                            let field_stroke = egui::Stroke::new(1.0, c_border);
                            ui.label(egui::RichText::new("Vault Name").size(12.0).color(c_lbl));
                            ui.add_space(4.0);
                            input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                ui.add(egui::TextEdit::singleline(name).hint_text("e.g. Work, Personal…").desired_width(ui.available_width()).frame(false));
                            });
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("File Path (leave blank for default)").size(12.0).color(c_lbl));
                            ui.add_space(4.0);
                            input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                ui.add(egui::TextEdit::singleline(path_input).hint_text("Optional custom path…").desired_width(ui.available_width()).frame(false));
                            });
                            ui.add_space(10.0);
                            ui.label(egui::RichText::new("Master Password").size(12.0).color(c_lbl));
                            ui.add_space(4.0);
                            let pw_stroke = if !password.is_empty() { egui::Stroke::new(1.5, accent) } else { field_stroke };
                            input_field(ui, c_input, pw_stroke).show(ui, |ui| {
                                ui.add(egui::TextEdit::singleline(password).password(true).hint_text("••••••••").desired_width(ui.available_width()).frame(false));
                            });
                            ui.add_space(10.0);
                            let mismatch = !confirm.is_empty() && !password.is_empty() && password != confirm;
                            let too_short = !password.is_empty() && password.len() < 8;
                            let cn_stroke = if mismatch { egui::Stroke::new(1.5, egui::Color32::from_rgb(210,60,60)) } else { field_stroke };
                            ui.label(egui::RichText::new("Confirm Password").size(12.0)
                                .color(if mismatch { egui::Color32::from_rgb(210,60,60) } else { c_lbl }));
                            ui.add_space(4.0);
                            input_field(ui, c_input, cn_stroke).show(ui, |ui| {
                                ui.add(egui::TextEdit::singleline(confirm).password(true).hint_text("••••••••").desired_width(ui.available_width()).frame(false));
                            });
                            if too_short {
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Use at least 8 characters").size(11.0).color(egui::Color32::from_rgb(210,60,60)));
                            } else if mismatch {
                                ui.add_space(4.0);
                                ui.label(egui::RichText::new("Passwords don't match").size(11.0).color(egui::Color32::from_rgb(210,60,60)));
                            }
                            ui.add_space(6.0);
                        });
                        });
                        let footer_sep = if dm { egui::Color32::from_rgb(38,42,58) } else { egui::Color32::from_rgb(215,211,204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none().inner_margin(egui::Margin { left:18.0,right:18.0,top:10.0,bottom:14.0 }).show(ui, |ui| {
                            ui.horizontal(|ui| {
                                let can = !name.is_empty() && password.len() >= 8 && password == confirm;
                                let btn_fill = if can { egui::Color32::from_rgb(46,153,54) } else {
                                    if dm { egui::Color32::from_rgb(44,48,62) } else { egui::Color32::from_rgb(194,189,180) }
                                };
                                let create_btn = egui::Button::new(egui::RichText::new("Create Vault").size(13.5).color(egui::Color32::WHITE))
                                    .fill(btn_fill).rounding(9.0).min_size(egui::vec2(130.0,36.0));
                                if ui.add_enabled(can, create_btn).clicked() {
                                    // - - - Resolve path - - -
                                    let resolved_path: PathBuf = if path_input.trim().is_empty() {
                                        if let Ok(dir) = data_dir() {
                                            let fname = format!("{}.enc", name.trim().to_lowercase().replace(' ', "_"));
                                            dir.join(fname)
                                        } else { PathBuf::from(format!("{}.enc", name.trim())) }
                                    } else { PathBuf::from(path_input.trim()) };

                                    if resolved_path.exists() {
                                        self.push_toast("A file already exists at that path.".into(), ToastKind::Error);
                                    } else {
                                        let vault_name = name.trim().to_string();
                                        let pw_clone   = password.clone();
                                        let path_clone = resolved_path.clone();
                                        match save_vault_file(&path_clone, &Vault::default(), &pw_clone) {
                                            Ok(_) => {
                                                let ts = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default().as_secs();
                                                self.vault_registry.vaults.push(VaultRecord {
                                                    name: vault_name.clone(),
                                                    path: path_clone.to_string_lossy().to_string(),
                                                    last_opened: ts,
                                                });
                                                save_registry(&self.vault_registry);
                                                self.push_toast(format!("Vault '{}' created!", vault_name), ToastKind::Success);
                                                close_on_action = true;
                                            }
                                            Err(e) => self.push_toast(format!("Failed: {}", e), ToastKind::Error),
                                        }
                                    }
                                }
                                ui.add_space(8.0);
                                let cancel_btn = egui::Button::new(egui::RichText::new("Cancel").size(13.0).color(c_title))
                                    .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0,36.0));
                                if ui.add(cancel_btn).clicked() { close_on_action = true; }
                            });
                        });
                    });
            }

            // ─── RENAME VAULT MODAL ───────────────────────────────────────────────────
            Modal::RenameVault { index, new_name } => {
                egui::Window::new("rename_vault_modal")
                    .resizable(false).collapsible(false)
                    .default_width(380.0).title_bar(false)
                    .frame(egui::Frame::window(&ctx.style()).fill(c_win).rounding(14.0)
                        .stroke(egui::Stroke::new(1.0, c_border)).inner_margin(egui::Margin::same(0.0)))
                    .show(ctx, |ui| {
                        let title_bg = if dm { egui::Color32::from_rgb(20,22,32) } else { egui::Color32::from_rgb(247,246,243) };
                        egui::Frame::none().fill(title_bg)
                            .rounding(egui::Rounding { nw:14.0,ne:14.0,sw:0.0,se:0.0 })
                            .inner_margin(egui::Margin { left:18.0,right:18.0,top:14.0,bottom:14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(egui::RichText::new("✏️  Rename Vault").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));
                        egui::Frame::none().inner_margin(egui::Margin { left:18.0,right:18.0,top:14.0,bottom:14.0 }).show(ui, |ui| {
                            ui.set_min_width(340.0);
                            ui.label(egui::RichText::new("New name").size(12.0).color(c_lbl));
                            ui.add_space(6.0);
                            input_field(ui, c_input, egui::Stroke::new(1.0, c_border)).show(ui, |ui| {
                                ui.add(egui::TextEdit::singleline(new_name).desired_width(ui.available_width()).frame(false));
                            });
                            ui.add_space(14.0);
                            ui.horizontal(|ui| {
                                let can = !new_name.is_empty();
                                let save_btn = egui::Button::new(egui::RichText::new("Save").size(13.5).color(egui::Color32::WHITE))
                                    .fill(if can { accent } else { if dm { egui::Color32::from_rgb(44,48,62) } else { egui::Color32::from_rgb(194,189,180) } })
                                    .rounding(9.0).min_size(egui::vec2(90.0,36.0));
                                if ui.add_enabled(can, save_btn).clicked() {
                                    if let Some(r) = self.vault_registry.vaults.get_mut(*index) {
                                        r.name = new_name.trim().to_string();
                                    }
                                    save_registry(&self.vault_registry);
                                    self.push_toast("Vault renamed.".into(), ToastKind::Success);
                                    close_on_action = true;
                                }
                                ui.add_space(8.0);
                                let cancel_btn = egui::Button::new(egui::RichText::new("Cancel").size(13.0).color(c_title))
                                    .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0,36.0));
                                if ui.add(cancel_btn).clicked() { close_on_action = true; }
                            });
                        });
                    });
            }

            // ─── DELETE VAULT RECORD MODAL ────────────────────────────────────────────
            Modal::DeleteVaultRecord { index, confirmation } => {
                let vault_name = self.vault_registry.vaults.get(*index)
                    .map(|r| r.name.clone()).unwrap_or_default();
                egui::Window::new("delete_vault_record_modal")
                    .resizable(false).collapsible(false)
                    .default_width(420.0).title_bar(false)
                    .frame(egui::Frame::window(&ctx.style()).fill(c_win).rounding(14.0)
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(120,42,42))).inner_margin(egui::Margin::same(0.0)))
                    .show(ctx, |ui| {
                        let title_bg = if dm { egui::Color32::from_rgb(32,18,18) } else { egui::Color32::from_rgb(255,244,244) };
                        egui::Frame::none().fill(title_bg)
                            .rounding(egui::Rounding { nw:14.0,ne:14.0,sw:0.0,se:0.0 })
                            .inner_margin(egui::Margin { left:18.0,right:18.0,top:14.0,bottom:14.0 })
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(format!("🗑  Delete \"{}\"?", vault_name)).size(14.0).strong()
                                    .color(egui::Color32::from_rgb(210,80,80)));
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, egui::Color32::from_rgb(120,42,42)));
                        egui::Frame::none().inner_margin(egui::Margin { left:18.0,right:18.0,top:14.0,bottom:14.0 }).show(ui, |ui| {
                            ui.set_min_width(380.0);
                            let warn_bg = if dm { egui::Color32::from_rgb(50,18,18) } else { egui::Color32::from_rgb(255,238,238) };
                            egui::Frame::none().fill(warn_bg).rounding(10.0)
                                .inner_margin(egui::Margin::symmetric(14.0,10.0))
                                .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(155,45,45)))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.label(egui::RichText::new("⚠️  This permanently deletes the encrypted vault file and all its data. This cannot be undone.")
                                        .size(12.0).color(if dm { egui::Color32::from_rgb(220,140,140) } else { egui::Color32::from_rgb(150,50,50) }));
                                });
                            ui.add_space(14.0);
                            ui.label(egui::RichText::new("Type the vault name to confirm:").size(12.0).color(c_lbl));
                            ui.add_space(6.0);
                            input_field(ui, c_input, egui::Stroke::new(1.0, egui::Color32::from_rgb(140,55,55))).show(ui, |ui| {
                                ui.add(egui::TextEdit::singleline(confirmation).desired_width(ui.available_width()).frame(false));
                            });
                            ui.add_space(14.0);
                            ui.horizontal(|ui| {
                                let confirmed = confirmation.trim() == vault_name;
                                let del_btn = egui::Button::new(egui::RichText::new("Delete Permanently").size(13.5).color(egui::Color32::WHITE))
                                    .fill(if confirmed { egui::Color32::from_rgb(200,55,55) } else { if dm { egui::Color32::from_rgb(60,40,40) } else { egui::Color32::from_rgb(210,190,190) } })
                                    .rounding(9.0).min_size(egui::vec2(160.0,36.0));
                                if ui.add_enabled(confirmed, del_btn).clicked() {
                                    let idx = *index;
                                    if let Some(record) = self.vault_registry.vaults.get(idx) {
                                        let _ = fs::remove_file(&record.path);
                                    }
                                    // - - - If deleting current vault, lock - - -
                                    let current_path = self.vault_path.to_string_lossy().to_string();
                                    if self.vault_registry.vaults.get(idx).map(|r| r.path == current_path).unwrap_or(false) {
                                        self.lock_vault();
                                    }
                                    self.vault_registry.vaults.remove(idx);
                                    // - - - Fix last_used_index - - -
                                    self.vault_registry.last_used_index = self.vault_registry.last_used_index.and_then(|i| {
                                        if i == idx { None } else if i > idx { Some(i - 1) } else { Some(i) }
                                    });
                                    save_registry(&self.vault_registry);
                                    self.push_toast("Vault deleted.".into(), ToastKind::Info);
                                    close_on_action = true;
                                }
                                ui.add_space(8.0);
                                let cancel_btn = egui::Button::new(egui::RichText::new("Cancel").size(13.0).color(c_title))
                                    .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0,36.0));
                                if ui.add(cancel_btn).clicked() { close_on_action = true; }
                            });
                        });
                    });
            }

            // - - -  - - -
            // - - - ADD NOTE - - -
            // - - -  - - -
            Modal::AddNote { title, content, category, tags } => {
                egui::Window::new("add_note_modal")
                    .resizable(false).collapsible(false)
                    .default_width(480.0)
                    .title_bar(false)
                    .frame(egui::Frame::window(&ctx.style()).fill(c_win).rounding(14.0)
                        .stroke(egui::Stroke::new(1.0, c_border)).inner_margin(egui::Margin::same(0.0)))
                    .show(ctx, |ui| {
                        // - - - Title bar - - -
                        let note_green = egui::Color32::from_rgb(66, 153, 54);
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none().fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("📝").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("New Secure Note").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));

                        // - - - Scrollable form body - - -
                        egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                            egui::Frame::none().inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 10.0 })
                                .show(ui, |ui| {
                                    ui.set_min_width(440.0);
                                    let field_stroke = egui::Stroke::new(1.0, c_border);
                                    let input_field_fn = |_ui: &mut egui::Ui, fill: egui::Color32, stroke: egui::Stroke| {
                                        egui::Frame::none().fill(fill).rounding(9.0)
                                            .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(stroke)
                                    };

                                    ui.label(egui::RichText::new("📝  Title").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    input_field_fn(ui, c_input, field_stroke).show(ui, |ui| {
                                        ui.add(egui::TextEdit::singleline(title).hint_text("Note title")
                                            .char_limit(60)
                                            .desired_width(ui.available_width()).frame(false));
                                    });
                                    ui.add_space(10.0);

                                    ui.label(egui::RichText::new("📄  Content").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    egui::Frame::none().fill(c_input).rounding(9.0)
                                        .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(field_stroke)
                                        .show(ui, |ui| {
                                            ui.add(egui::TextEdit::multiline(content)
                                                .hint_text("Write your note here…")
                                                .desired_width(ui.available_width())
                                                .desired_rows(8).frame(false));
                                        });
                                    ui.add_space(10.0);

                                    ui.label(egui::RichText::new("📁  Category").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    input_field_fn(ui, c_input, field_stroke).show(ui, |ui| {
                                        ui.add(egui::TextEdit::singleline(category).hint_text("e.g. Personal, Work")
                                            .char_limit(30)
                                            .desired_width(ui.available_width()).frame(false));
                                    });
                                    ui.add_space(10.0);

                                    ui.label(egui::RichText::new("🏷  Tags").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    input_field_fn(ui, c_input, field_stroke).show(ui, |ui| {
                                        ui.add(egui::TextEdit::singleline(tags).hint_text("comma separated")
                                            .char_limit(150)
                                            .desired_width(ui.available_width()).frame(false));
                                    });
                                    ui.add_space(6.0);
                                }); // - - - inner frame - - -
                        }); // - - - scroll area - - -

                        // - - - Sticky footer - - -
                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none().inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let can_save = !title.is_empty();
                                    let btn_fill = if can_save { note_green } else {
                                        if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(194, 189, 180) }
                                    };
                                    let save_btn = egui::Button::new(
                                        egui::RichText::new("💾  Save Note").size(13.5).color(egui::Color32::WHITE)
                                    ).fill(btn_fill).rounding(9.0).min_size(egui::vec2(130.0, 36.0));
                                    if ui.add_enabled(can_save, save_btn).clicked() {
                                        let tags_vec: Vec<String> = tags.split(',')
                                            .map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
                                        let cat = if category.trim().is_empty() { None } else { Some(category.trim().to_string()) };
                                        let t = title.clone(); let c = content.clone();
                                        self.add_note_and_save(t, c, cat, tags_vec);
                                        close_on_action = true;
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            });
                    });
            }

            // - - -  - - -
            // - - - EDIT NOTE - - -
            // - - -  - - -
            Modal::EditNote { original_id, title, content, category, tags } => {
                egui::Window::new("edit_note_modal")
                    .resizable(false).collapsible(false)
                    .default_width(480.0)
                    .title_bar(false)
                    .frame(egui::Frame::window(&ctx.style()).fill(c_win).rounding(14.0)
                        .stroke(egui::Stroke::new(1.0, c_border)).inner_margin(egui::Margin::same(0.0)))
                    .show(ctx, |ui| {
                        let note_green = egui::Color32::from_rgb(66, 153, 54);
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none().fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(22, 48, 32) } else { egui::Color32::from_rgb(220, 248, 228) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("✏️").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Edit Note").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));

                        // - - - Scrollable form body - - -
                        egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                            egui::Frame::none().inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 10.0 })
                                .show(ui, |ui| {
                                    ui.set_min_width(440.0);
                                    let field_stroke = egui::Stroke::new(1.0, c_border);
                                    let input_field_fn = |_ui: &mut egui::Ui, fill: egui::Color32, stroke: egui::Stroke| {
                                        egui::Frame::none().fill(fill).rounding(9.0)
                                            .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(stroke)
                                    };

                                    ui.label(egui::RichText::new("📝  Title").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    input_field_fn(ui, c_input, field_stroke).show(ui, |ui| {
                                        ui.add(egui::TextEdit::singleline(title).char_limit(60).desired_width(ui.available_width()).frame(false));
                                    });
                                    ui.add_space(10.0);

                                    ui.label(egui::RichText::new("📄  Content").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    egui::Frame::none().fill(c_input).rounding(9.0)
                                        .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(field_stroke)
                                        .show(ui, |ui| {
                                            ui.add(egui::TextEdit::multiline(content)
                                                .desired_width(ui.available_width())
                                                .desired_rows(8).frame(false));
                                        });
                                    ui.add_space(10.0);

                                    ui.label(egui::RichText::new("📁  Category").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    input_field_fn(ui, c_input, field_stroke).show(ui, |ui| {
                                        ui.add(egui::TextEdit::singleline(category).char_limit(30).desired_width(ui.available_width()).frame(false));
                                    });
                                    ui.add_space(10.0);

                                    ui.label(egui::RichText::new("🏷  Tags").size(12.0).color(c_lbl));
                                    ui.add_space(4.0);
                                    input_field_fn(ui, c_input, field_stroke).show(ui, |ui| {
                                        ui.add(egui::TextEdit::singleline(tags).char_limit(150).desired_width(ui.available_width()).frame(false));
                                    });
                                    ui.add_space(6.0);
                                }); // - - - inner frame - - -
                        }); // - - - scroll area - - -

                        // - - - Sticky footer - - -
                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none().inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let can_save = !title.is_empty();
                                    let btn_fill = if can_save { note_green } else {
                                        if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(194, 189, 180) }
                                    };
                                    let save_btn = egui::Button::new(
                                        egui::RichText::new("💾  Save Changes").size(13.5).color(egui::Color32::WHITE)
                                    ).fill(btn_fill).rounding(9.0).min_size(egui::vec2(140.0, 36.0));
                                    if ui.add_enabled(can_save, save_btn).clicked() {
                                        let tags_vec: Vec<String> = tags.split(',')
                                            .map(|t| t.trim().to_string()).filter(|t| !t.is_empty()).collect();
                                        let cat = if category.trim().is_empty() { None } else { Some(category.trim().to_string()) };
                                        let id = original_id.clone();
                                        if let Some(note) = self.vault.notes.iter_mut().find(|n| n.id == id) {
                                            note.title = title.trim().to_string();
                                            note.content = content.clone();
                                            note.category = cat;
                                            note.tags = tags_vec;
                                        }
                                        if let Err(e) = save_vault_file(&self.vault_path, &self.vault, &self.master_password) {
                                            self.handle_error(e);
                                        } else {
                                            self.push_toast("Note updated.".into(), ToastKind::Success);
                                        }
                                        close_on_action = true;
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 36.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            });
                    });
            }

            // - - -  - - -
            // - - - IMPORT / EXPORT - - -
            // - - -  - - -
            Modal::ImportExport { active_tab, import_text, export_preview, export_password, import_password, encrypted_export } => {
                egui::Window::new("import_export_modal")
                    .resizable(false).collapsible(false)
                    .default_width(520.0)
                    .title_bar(false)
                    .frame(egui::Frame::window(&ctx.style()).fill(c_win).rounding(14.0)
                        .stroke(egui::Stroke::new(1.0, c_border)).inner_margin(egui::Margin::same(0.0)))
                    .show(ctx, |ui| {
                        // - - - Title bar - - -
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(247, 246, 243) };
                        egui::Frame::none().fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(28, 35, 55) } else { egui::Color32::from_rgb(228, 225, 252) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("📤").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Import / Export").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));

                        // - - - Tab bar (always visible) - - -
                        egui::Frame::none().inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 12.0, bottom: 0.0 })
                            .show(ui, |ui| {
                                ui.set_min_width(484.0);
                                let tab_bg = if dm { egui::Color32::from_rgb(22, 24, 38) } else { egui::Color32::from_rgb(240, 238, 234) };
                                egui::Frame::none().fill(tab_bg).rounding(10.0)
                                    .inner_margin(egui::Margin::same(4.0))
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            for (i, label) in ["📤  Export", "📥  Import"].iter().enumerate() {
                                                let is_active = *active_tab == i as u8;
                                                let tab_fill = if is_active { accent } else { egui::Color32::TRANSPARENT };
                                                let tab_txt = if is_active { egui::Color32::WHITE }
                                                    else { if dm { egui::Color32::from_rgb(145, 148, 172) } else { egui::Color32::from_rgb(100, 94, 82) } };
                                                let tab_btn = egui::Button::new(egui::RichText::new(*label).size(12.5).color(tab_txt))
                                                    .fill(tab_fill).rounding(7.0).min_size(egui::vec2(120.0, 28.0));
                                                if ui.add(tab_btn).clicked() { *active_tab = i as u8; }
                                            }
                                        });
                                    });
                            });

                        // - - - Track action intent for sticky footer - - -
                        let mut do_encrypted_copy = false;
                        let mut do_plaintext_copy = false;
                        let mut do_import         = false;
                        let looks_encrypted = import_text.contains("\"magic\"") && import_text.contains("\"cipher_b64\"");
                        let can_export_enc  = !export_password.is_empty();
                        let can_import      = !import_text.trim().is_empty() && (!looks_encrypted || !import_password.is_empty());

                        // - - - Scrollable tab body - - -
                        egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                        egui::Frame::none().inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 12.0, bottom: 10.0 })
                            .show(ui, |ui| {
                                ui.set_min_width(484.0);
                                ui.add_space(2.0);

                                if *active_tab == 0 {
                                    // - - - EXPORT TAB (encrypted) - - -
                                    // - - - Encryption toggle row - - -
                                    {
                                        let enc_bg = if *encrypted_export {
                                            if dm { egui::Color32::from_rgb(18, 38, 52) } else { egui::Color32::from_rgb(230, 240, 255) }
                                        } else {
                                            if dm { egui::Color32::from_rgb(40, 35, 10) } else { egui::Color32::from_rgb(255, 253, 230) }
                                        };
                                        let enc_border = if *encrypted_export {
                                            egui::Color32::from_rgb(80, 120, 200)
                                        } else {
                                            egui::Color32::from_rgb(175, 130, 15)
                                        };
                                        egui::Frame::none().fill(enc_bg).rounding(9.0)
                                            .inner_margin(egui::Margin::symmetric(12.0, 9.0))
                                            .stroke(egui::Stroke::new(1.0, enc_border))
                                            .show(ui, |ui| {
                                                ui.set_min_width(ui.available_width());
                                                ui.horizontal(|ui| {
                                                    ui.label(egui::RichText::new(if *encrypted_export { "🔐" } else { "⚠️" }).size(13.0));
                                                    ui.add_space(6.0);
                                                    let msg = if *encrypted_export {
                                                        "Encrypted export — protected with a separate password."
                                                    } else {
                                                        "Plaintext export — store securely and delete after use."
                                                    };
                                                    let msg_col = if *encrypted_export {
                                                        if dm { egui::Color32::from_rgb(140, 185, 255) } else { egui::Color32::from_rgb(40, 80, 180) }
                                                    } else {
                                                        if dm { egui::Color32::from_rgb(220, 185, 60) } else { egui::Color32::from_rgb(115, 75, 5) }
                                                    };
                                                    ui.label(egui::RichText::new(msg).size(12.0).color(msg_col));
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        let toggle_col = if *encrypted_export { accent } else { egui::Color32::from_rgb(175, 130, 15) };
                                                        let toggle_lbl = if *encrypted_export { "Encrypted" } else { "Plaintext" };
                                                        let tb = egui::Button::new(egui::RichText::new(toggle_lbl).size(11.0).color(egui::Color32::WHITE))
                                                            .fill(toggle_col).rounding(6.0).min_size(egui::vec2(80.0, 22.0));
                                                        if ui.add(tb).clicked() { *encrypted_export = !*encrypted_export; }
                                                    });
                                                });
                                            });
                                        ui.add_space(12.0);
                                    }

                                    if *encrypted_export {
                                        // - - - Export password field - - -
                                        ui.label(egui::RichText::new("🔑  Export Password").size(12.0).color(c_sub));
                                        ui.add_space(4.0);
                                        let pw_stroke = if export_password.is_empty() {
                                            egui::Stroke::new(1.0, c_border)
                                        } else {
                                            egui::Stroke::new(1.5, accent)
                                        };
                                        egui::Frame::none().fill(c_input).rounding(9.0)
                                            .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(pw_stroke)
                                            .show(ui, |ui| {
                                                ui.add(egui::TextEdit::singleline(export_password)
                                                    .password(true)
                                                    .hint_text("Password for this export file")
                                                    .desired_width(ui.available_width()).frame(false));
                                            });
                                        ui.add_space(6.0);
                                    } else {
                                        // - - - Plaintext preview - - -
                                        ui.label(egui::RichText::new("Preview (all entries & notes):").size(12.0).color(c_sub));
                                        ui.add_space(6.0);
                                        egui::Frame::none().fill(c_input).rounding(9.0)
                                            .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                                            .stroke(egui::Stroke::new(1.0, c_border))
                                            .show(ui, |ui| {
                                                egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                                                    ui.add(egui::TextEdit::multiline(export_preview)
                                                        .desired_width(ui.available_width()).frame(false).interactive(false));
                                                });
                                            });
                                        ui.add_space(6.0);
                                    }
                                } else {
                                    // - - - IMPORT TAB - - -
                                    let info_bg = if dm { egui::Color32::from_rgb(22, 26, 46) } else { egui::Color32::from_rgb(236, 238, 255) };
                                    egui::Frame::none().fill(info_bg).rounding(9.0)
                                        .inner_margin(egui::Margin::symmetric(12.0, 9.0))
                                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgb(99, 111, 200)))
                                        .show(ui, |ui| {
                                            ui.set_min_width(ui.available_width());
                                            ui.horizontal(|ui| {
                                                ui.label(egui::RichText::new("ℹ️").size(13.0));
                                                ui.add_space(6.0);
                                                ui.label(egui::RichText::new("Paste an encrypted or plaintext ZeroPass export. Duplicate IDs are skipped.")
                                                    .size(12.0).color(if dm { egui::Color32::from_rgb(165, 175, 245) } else { egui::Color32::from_rgb(60, 55, 160) }));
                                            });
                                        });
                                    ui.add_space(12.0);

                                    ui.label(egui::RichText::new("Paste JSON:").size(12.0).color(c_sub));
                                    ui.add_space(6.0);
                                    egui::Frame::none().fill(c_input).rounding(9.0)
                                        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                                        .stroke(egui::Stroke::new(1.0, c_border))
                                        .show(ui, |ui| {
                                            egui::ScrollArea::vertical().max_height(160.0).show(ui, |ui| {
                                                ui.add(egui::TextEdit::multiline(import_text)
                                                    .hint_text("Paste exported JSON here…")
                                                    .desired_width(ui.available_width()).frame(false));
                                            });
                                        });
                                    ui.add_space(10.0);

                                    // - - - Detect if it looks like an EncFile and show password field - - -
                                    let looks_encrypted = import_text.contains("\"magic\"") && import_text.contains("\"cipher_b64\"");
                                    if looks_encrypted {
                                        ui.label(egui::RichText::new("🔑  Import Password").size(12.0).color(c_sub));
                                        ui.add_space(4.0);
                                        let pw_stroke = if import_password.is_empty() {
                                            egui::Stroke::new(1.5, egui::Color32::from_rgb(200, 80, 80))
                                        } else {
                                            egui::Stroke::new(1.5, accent)
                                        };
                                        egui::Frame::none().fill(c_input).rounding(9.0)
                                            .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(pw_stroke)
                                            .show(ui, |ui| {
                                                ui.add(egui::TextEdit::singleline(import_password)
                                                    .password(true)
                                                    .hint_text("Password used when exporting")
                                                    .desired_width(ui.available_width()).frame(false));
                                            });
                                        ui.add_space(10.0);
                                    }

                                    ui.add_space(6.0);
                                }
                            }); // - - - inner frame - - -
                        }); // - - - scroll area - - -

                        // - - - Sticky footer - - -
                        let footer_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(215, 211, 204) };
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, footer_sep));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 10.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    if *active_tab == 0 {
                                        if *encrypted_export {
                                            let btn_fill = if can_export_enc { accent } else {
                                                if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(194, 189, 180) }
                                            };
                                            let export_btn = egui::Button::new(
                                                egui::RichText::new("🔐  Copy Encrypted Export").size(13.0).color(egui::Color32::WHITE)
                                            ).fill(btn_fill).rounding(9.0).min_size(egui::vec2(200.0, 36.0));
                                            if ui.add_enabled(can_export_enc, export_btn).clicked() {
                                                do_encrypted_copy = true;
                                            }
                                        } else {
                                            let copy_btn = egui::Button::new(
                                                egui::RichText::new("📋  Copy Plaintext").size(13.0).color(egui::Color32::WHITE)
                                            ).fill(egui::Color32::from_rgb(175, 130, 15)).rounding(9.0).min_size(egui::vec2(150.0, 36.0));
                                            if ui.add(copy_btn).clicked() { do_plaintext_copy = true; }
                                        }
                                    } else {
                                        let btn_fill = if can_import { egui::Color32::from_rgb(66, 153, 54) } else {
                                            if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(194, 189, 180) }
                                        };
                                        let import_btn = egui::Button::new(
                                            egui::RichText::new("📥  Import").size(13.0).color(egui::Color32::WHITE)
                                        ).fill(btn_fill).rounding(9.0).min_size(egui::vec2(110.0, 36.0));
                                        if ui.add_enabled(can_import, import_btn).clicked() { do_import = true; }
                                    }
                                    ui.add_space(8.0);
                                    let close_btn = egui::Button::new(
                                        egui::RichText::new("Close").size(13.0).color(c_title)
                                    ).fill(c_cancel).rounding(9.0).min_size(egui::vec2(80.0, 36.0));
                                    if ui.add(close_btn).clicked() { close_on_action = true; }
                                });
                            });

                        // - - - Act on footer intents after both scroll area and footer are drawn - - -
                        if do_encrypted_copy {
                            match encrypt_vault(&self.vault, export_password) {
                                Ok(enc) => {
                                    match serde_json::to_string_pretty(&enc) {
                                        Ok(enc_json) => {
                                            if let Ok(mut cb) = Clipboard::new() {
                                                let _ = cb.set_text(enc_json);
                                                self.push_toast("Encrypted export copied to clipboard.".into(), ToastKind::Success);
                                            }
                                        }
                                        Err(e) => self.push_toast(format!("Serialization error: {}", e), ToastKind::Error),
                                    }
                                }
                                Err(e) => self.push_toast(format!("Encryption failed: {}", e), ToastKind::Error),
                            }
                        }
                        if do_plaintext_copy {
                            if let Ok(mut cb) = Clipboard::new() {
                                let _ = cb.set_text(export_preview.clone());
                                self.push_toast("Plaintext JSON copied to clipboard.".into(), ToastKind::Success);
                            }
                        }
                        if do_import {
                            let import_result: Result<usize, VaultError> = if looks_encrypted {
                                serde_json::from_str::<EncFile>(import_text)
                                    .map_err(VaultError::Serde)
                                    .and_then(|enc| decrypt_vault(&enc, import_password))
                                    .and_then(|imported_vault| {
                                        let mut count = 0usize;
                                        let existing_ids: std::collections::HashSet<String> = self.vault.entries.iter().map(|e| e.id.clone()).collect();
                                        let existing_note_ids: std::collections::HashSet<String> = self.vault.notes.iter().map(|n| n.id.clone()).collect();
                                        for mut entry in imported_vault.entries {
                                            if existing_ids.contains(&entry.id) { entry.id = gen_id(); }
                                            self.vault.entries.push(entry); count += 1;
                                        }
                                        for mut note in imported_vault.notes {
                                            if existing_note_ids.contains(&note.id) { note.id = gen_id(); }
                                            self.vault.notes.push(note); count += 1;
                                        }
                                        Ok(count)
                                    })
                            } else {
                                import_vault_json(import_text, &mut self.vault)
                            };
                            match import_result {
                                Ok(n) => {
                                    match save_vault_file(&self.vault_path, &self.vault, &self.master_password) {
                                        Ok(_) => {
                                            self.push_toast(format!("Imported {} item(s) successfully.", n), ToastKind::Success);
                                            close_on_action = true;
                                        }
                                        Err(e) => self.handle_error(e),
                                    }
                                }
                                Err(e) => self.push_toast(format!("Import failed: {}", e), ToastKind::Error),
                            }
                        }
                    });
            }
        } // match

        if close_on_action { modal_is_open = false; }
        if modal_is_open {
            self.modal = current_modal;
        } else {
            current_modal.zeroize_sensitive();
        }
    }
}

impl App for VaultGui {
    /// Best-effort defense-in-depth: zeroize plaintext secrets still resident
    /// in memory when the app is closing, rather than relying solely on the
    /// struct's `ZeroizeOnDrop` (which `#[zeroize(skip)]` fields like `vault`
    /// and `modal` are intentionally excluded from, since they're rebuilt on
    /// every unlock and would otherwise add per-frame zeroize overhead).
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.master_password.zeroize();
        self.master_password_confirm.zeroize();
        self.modal.zeroize_sensitive();
        for entry in self.vault.entries.iter_mut() {
            entry.password.zeroize();
            if let Some(secret) = entry.totp_secret.as_mut() { secret.zeroize(); }
            for hist in entry.password_history.iter_mut() {
                hist.password.zeroize();
            }
        }
        for note in self.vault.notes.iter_mut() {
            note.content.zeroize();
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // - - - Custom theme based on dark_mode setting v1 - - -
        let mut style = (*ctx.style()).clone();
        
        if self.dark_mode {
            // - - - Dark theme — blue-slate base, not flat grey - - -
            style.visuals.dark_mode = true;
            style.visuals.window_fill = egui::Color32::from_rgb(18, 20, 28);
            style.visuals.panel_fill  = egui::Color32::from_rgb(18, 20, 28);
            style.visuals.extreme_bg_color = egui::Color32::from_rgb(13, 14, 20);
            style.visuals.widgets.noninteractive.bg_fill = egui::Color32::from_rgb(32, 36, 48);
            style.visuals.widgets.inactive.bg_fill        = egui::Color32::from_rgb(42, 46, 62);
            style.visuals.widgets.hovered.bg_fill         = egui::Color32::from_rgb(55, 60, 80);
            style.visuals.widgets.active.bg_fill          = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.selection.bg_fill               = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.override_text_color = Some(egui::Color32::from_rgb(225, 225, 238));
            style.visuals.window_stroke = egui::Stroke::new(1.0, egui::Color32::from_rgb(60, 66, 90));
        } else {
            // - - - Light theme — warm white base, ink text, indigo accent only - - -
            style.visuals.dark_mode = false;
            // - - - Background surfaces — warm white, not blue-tinted - - -
            style.visuals.window_fill                         = egui::Color32::from_rgb(250, 249, 246);
            style.visuals.panel_fill                          = egui::Color32::from_rgb(246, 245, 242);
            style.visuals.extreme_bg_color                    = egui::Color32::from_rgb(238, 236, 232);
            // - - - Widget fills — warm neutral greys - - -
            style.visuals.widgets.noninteractive.bg_fill      = egui::Color32::from_rgb(234, 232, 228);
            style.visuals.widgets.noninteractive.weak_bg_fill = egui::Color32::from_rgb(243, 242, 239);
            style.visuals.widgets.inactive.bg_fill            = egui::Color32::from_rgb(228, 226, 222);
            style.visuals.widgets.inactive.weak_bg_fill       = egui::Color32::from_rgb(240, 239, 236);
            style.visuals.widgets.hovered.bg_fill             = egui::Color32::from_rgb(218, 216, 210);
            style.visuals.widgets.hovered.weak_bg_fill        = egui::Color32::from_rgb(232, 230, 226);
            style.visuals.widgets.active.bg_fill              = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.widgets.active.weak_bg_fill         = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.selection.bg_fill                   = egui::Color32::from_rgba_unmultiplied(88, 101, 242, 38);
            style.visuals.selection.stroke                    = egui::Stroke::new(1.0, egui::Color32::from_rgb(88, 101, 242));
            // - - - Text — deep warm ink, not blue-black - - -
            style.visuals.override_text_color                 = Some(egui::Color32::from_rgb(22, 19, 14));
            // - - - Strokes — warm stone, not cool grey - - -
            style.visuals.window_stroke                       = egui::Stroke::new(1.0, egui::Color32::from_rgb(210, 207, 200));
            style.visuals.widgets.noninteractive.fg_stroke    = egui::Stroke::new(1.0, egui::Color32::from_rgb(110, 106, 98));
            style.visuals.widgets.inactive.fg_stroke          = egui::Stroke::new(1.0, egui::Color32::from_rgb(90, 86, 78));
            style.visuals.widgets.hovered.fg_stroke           = egui::Stroke::new(1.5, egui::Color32::from_rgb(30, 26, 18));
            style.visuals.widgets.active.fg_stroke            = egui::Stroke::new(2.0, egui::Color32::WHITE);
            style.visuals.widgets.noninteractive.bg_stroke    = egui::Stroke::new(1.0, egui::Color32::from_rgb(208, 204, 196));
            style.visuals.widgets.inactive.bg_stroke          = egui::Stroke::new(1.0, egui::Color32::from_rgb(196, 190, 180));
            style.visuals.widgets.hovered.bg_stroke           = egui::Stroke::new(1.5, egui::Color32::from_rgb(140, 136, 128));
            style.visuals.widgets.active.bg_stroke            = egui::Stroke::new(0.0, egui::Color32::TRANSPARENT);
            style.visuals.hyperlink_color                     = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.window_rounding                     = egui::Rounding::same(12.0);
            style.visuals.menu_rounding                       = egui::Rounding::same(8.0);
        }
        
        ctx.set_style(style);
        
        if let Some(ref receiver) = self.unlock_receiver {
            if let Ok(result) = receiver.try_recv() {
                match result {
                    UnlockResult::Success(vault) => {
                        self.vault = vault;
                        self.state = AppState::Unlocked;
                        self.view_opened = Some(Instant::now());
                        self.push_toast("Vault unlocked.".to_string(), ToastKind::Success);
                        play_unlock_sound();
                        // - - - Update registry timestamp - - -
                        let ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs();
                        let vp = self.vault_path.to_string_lossy().to_string();
                        let mut found = false;
                        for (i, r) in self.vault_registry.vaults.iter_mut().enumerate() {
                            if r.path == vp { r.last_opened = ts; self.vault_registry.last_used_index = Some(i); found = true; break; }
                        }
                        if !found {
                            let name = self.vault_path.file_stem().and_then(|s| s.to_str()).unwrap_or("Vault").to_string();
                            self.vault_registry.vaults.push(VaultRecord { name, path: vp, last_opened: ts });
                            self.vault_registry.last_used_index = Some(self.vault_registry.vaults.len() - 1);
                        }
                        save_registry(&self.vault_registry);
                    }
                    UnlockResult::Error(error) => {
                        self.push_toast(error.clone(), ToastKind::Error);
                        self.state = if self.vault_path.exists() { AppState::Locked } else { AppState::NoVault };
                        self.view_opened = Some(Instant::now());
                    }
                }
                self.unlock_receiver = None;
            }
        }

        // - - - Kick off a version check on the very first frame; harmless to - - -
        // - - - call once since update_status starts at Unknown and this guard - - -
        // - - - only fires while it's still Unknown and nothing is in flight. - - -
        if self.update_status == UpdateStatus::Unknown && self.update_check_receiver.is_none() {
            self.check_for_updates_async();
        }

        if let Some(ref receiver) = self.update_check_receiver {
            if let Ok(status) = receiver.try_recv() {
                // - - - Surface a toast only for actionable results — silent on - - -
                // - - - up-to-date/failure so we don't nag the user every launch. - - -
                match &status {
                    UpdateStatus::StableAvailable { version, .. } => {
                        self.push_toast(format!("Update available: v{version}"), ToastKind::Info);
                    }
                    UpdateStatus::BetaAvailable { version, .. } => {
                        self.push_toast(format!("Beta update available: v{version}"), ToastKind::Info);
                    }
                    _ => {}
                }
                self.update_status = status;
                self.update_check_receiver = None;
            }
        }
        
        self.clear_clipboard_if_needed();

        // - - - Track user activity for auto-lock - - -
        if ctx.input(|i| i.pointer.any_down() || !i.keys_down.is_empty()) {
            self.last_activity = Instant::now();
        }

        // - - - Security Features - - -
        if self.state == AppState::Unlocked {
            // - - - Feature: Auto-lock after inactivity - - -
            if self.auto_lock_enabled {
                let timeout = Duration::from_secs(self.auto_lock_timeout_mins * 60);
                if self.last_activity.elapsed() >= timeout {
                    self.lock_vault();
                    self.push_toast("Vault auto-locked due to inactivity.".to_string(), ToastKind::Info);
                }
            }
            
            // - - - Feature: Lock on focus loss - - -
            if self.lock_on_focus_loss && !ctx.input(|i| i.focused) {
                self.lock_vault();
                self.push_toast("Vault auto-locked due to focus loss.".to_string(), ToastKind::Info);
            }
        }

        ctx.request_repaint_after(Duration::from_millis(100));

        // - - - PERSISTENT LEFT SIDEBAR — shown whenever vault is unlocked - - -
        if self.state == AppState::Unlocked || self.state == AppState::KnownBugs || self.state == AppState::Notes || self.state == AppState::SettingsView || self.state == AppState::GeneratorView || self.state == AppState::VaultManager {
            let dm = self.dark_mode;
            let accent    = egui::Color32::from_rgb(99, 111, 245);
            let green     = egui::Color32::from_rgb(46, 120, 43);   // - - - #2e782b brand green - - -
            let red_col   = if dm { egui::Color32::from_rgb(230, 105, 105) } else { egui::Color32::from_rgb(190, 50, 50) };
            let c_title   = if dm { egui::Color32::from_rgb(228, 232, 242) } else { egui::Color32::from_rgb(18, 16, 12) };
            let c_sub     = if dm { egui::Color32::from_rgb(118, 122, 148) } else { egui::Color32::from_rgb(128, 122, 110) };
            let c_divider = if dm { egui::Color32::from_rgb(34, 38, 56) } else { egui::Color32::from_rgb(220, 216, 208) };
            let sidebar_bg     = if dm { egui::Color32::from_rgb(13, 14, 22) } else { egui::Color32::from_rgb(245, 243, 239) };
            let sidebar_border = if dm { egui::Color32::from_rgb(34, 38, 56) } else { egui::Color32::from_rgb(215, 210, 228) };

            let all_categories: Vec<String> = {
                let mut v: Vec<String> = self.vault.entries.iter()
                    .filter_map(|e| e.category.clone()).filter(|c| !c.is_empty()).collect();
                v.sort_unstable(); v.dedup(); v
            };
            let all_tags: Vec<String> = {
                let mut v: Vec<String> = self.vault.entries.iter()
                    .flat_map(|e| e.tags.iter().cloned()).filter(|t| !t.is_empty()).collect();
                v.sort_unstable(); v.dedup(); v
            };
            let all_note_categories: Vec<String> = {
                let mut v: Vec<String> = self.vault.notes.iter()
                    .filter_map(|n| n.category.clone()).filter(|c| !c.is_empty()).collect();
                v.sort_unstable(); v.dedup(); v
            };
            let all_note_tags: Vec<String> = {
                let mut v: Vec<String> = self.vault.notes.iter()
                    .flat_map(|n| n.tags.iter().cloned()).filter(|t| !t.is_empty()).collect();
                v.sort_unstable(); v.dedup(); v
            };

            // - - - Primary nav button: icon pill + label, with left accent bar when active - - -
            let nav_btn = |ui: &mut egui::Ui, icon: &str, label: &str, active: bool, col: egui::Color32| -> bool {
                let btn_bg = if active {
                    egui::Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), if dm { 28 } else { 18 })
                } else {
                    egui::Color32::TRANSPARENT
                };
                let lbl_col  = if active { col }  else { c_sub };
                let icon_bg  = if active {
                    egui::Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), if dm { 55 } else { 38 })
                } else {
                    egui::Color32::TRANSPARENT
                };

                let (resp, painter, rect) = {
                    let desired = egui::vec2(ui.available_width(), 34.0);
                    let (response, p) = ui.allocate_painter(desired, egui::Sense::click());
                    let r = response.rect;
                    (response, p, r)
                };

                // - - - Hover tint - - -
                let hovered = resp.hovered();
                if hovered && !active {
                    painter.rect_filled(rect, 8.0,
                        egui::Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), if dm { 10 } else { 8 }));
                }
                if active || hovered {
                    painter.rect_filled(rect, 8.0, btn_bg);
                }
                // - - - Left accent bar when active - - -
                if active {
                    painter.rect_filled(
                        egui::Rect::from_min_size(rect.min + egui::vec2(0.0, 6.0), egui::vec2(3.0, rect.height() - 12.0)),
                        2.0, col,
                    );
                }

                // - - - Icon pill - - -
                let icon_rect = egui::Rect::from_min_size(
                    rect.min + egui::vec2(10.0, (rect.height() - 22.0) / 2.0),
                    egui::vec2(24.0, 22.0),
                );
                painter.rect_filled(icon_rect, 6.0, icon_bg);
                painter.text(
                    icon_rect.center(),
                    egui::Align2::CENTER_CENTER,
                    icon,
                    egui::FontId::proportional(12.0),
                    lbl_col,
                );

                // - - - Label - - -
                painter.text(
                    rect.min + egui::vec2(42.0, rect.height() / 2.0),
                    egui::Align2::LEFT_CENTER,
                    label,
                    egui::FontId::proportional(13.0),
                    lbl_col,
                );

                resp.clicked()
            };

            // - - - Small filter button (categories / tags) - - -
            let filter_btn = |ui: &mut egui::Ui, label: &str, active: bool, col: egui::Color32| -> bool {
                let bg = if active {
                    egui::Color32::from_rgba_unmultiplied(col.r(), col.g(), col.b(), if dm { 28 } else { 18 })
                } else { egui::Color32::TRANSPARENT };
                let txt = if active { col } else { c_sub };
                let short_label = truncate_display(label, 24);
                let full_label = if active { format!("● {}", short_label) } else { format!("  {}", short_label) };
                ui.add(
                    egui::Button::new(egui::RichText::new(full_label).size(12.0).color(txt))
                        .fill(bg).stroke(egui::Stroke::NONE).rounding(6.0)
                        .min_size(egui::vec2(ui.available_width(), 26.0))
                ).on_hover_text(label).clicked()
            };

            egui::SidePanel::left("main_sidebar")
                .exact_width(220.0)
                .resizable(false)
                .frame(egui::Frame::none()
                    .fill(sidebar_bg)
                    .stroke(egui::Stroke::new(1.0, sidebar_border))
                    .inner_margin(egui::Margin { left: 10.0, right: 10.0, top: 18.0, bottom: 12.0 }))
                .show(ctx, |ui| {
                    ui.set_min_height(ui.available_height());
                    ui.spacing_mut().item_spacing.y = 2.0;

                    // - - - BRAND HEADER - - -
                    ui.horizontal(|ui| {
                        let logo_tex = self.logo_texture.get_or_insert_with(|| {
                            let pixels: Vec<egui::Color32> = LOGO_48_RGBA
                                .chunks_exact(4)
                                .map(|c| egui::Color32::from_rgba_unmultiplied(c[0], c[1], c[2], c[3]))
                                .collect();
                            ctx.load_texture("app_logo", egui::ColorImage {
                                size: [LOGO_48_W as usize, LOGO_48_H as usize],
                                pixels,
                            }, egui::TextureOptions::LINEAR)
                        }).clone();
                        let logo_size = egui::vec2(28.0, 30.0);
                        ui.add(egui::Image::new(&logo_tex).fit_to_exact_size(logo_size));
                        ui.add_space(8.0);
                        ui.vertical(|ui| {
                            ui.add_space(2.0);
                            ui.label(egui::RichText::new("ZeroPass").size(15.0).strong().color(c_title));
                            ui.label(egui::RichText::new("Password Manager").size(10.0).color(c_sub));
                        });
                    });

                    ui.add_space(16.0);
                    ui.painter().hline(
                        ui.available_rect_before_wrap().x_range(),
                        ui.cursor().top(),
                        egui::Stroke::new(1.0, c_divider),
                    );
                    ui.add_space(12.0);

                    // - - - Reserve space for the fixed footer, and let everything - - -
                    // - - - above it (nav + filters) scroll independently so long   - - -
                    // - - - category/tag lists never overflow the sidebar.          - - -
                    let footer_height = 90.0;
                    let scroll_max_height = (ui.available_height() - footer_height).max(0.0);

                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .max_height(scroll_max_height)
                        .show(ui, |ui| {

                    // - - - MAIN NAV - - -
                    ui.label(egui::RichText::new("  VAULT").size(9.5).color(
                        egui::Color32::from_rgba_unmultiplied(c_sub.r(), c_sub.g(), c_sub.b(), 160)
                    ));
                    ui.add_space(4.0);

                    let passwords_active = self.state == AppState::Unlocked;
                    if nav_btn(ui, "🔐", "Passwords", passwords_active, green) {
                        if self.state != AppState::Unlocked {
                            self.info_page_opened = None;
                            self.notes_page_opened = None;
                            self.view_opened = Some(Instant::now());
                            self.state = AppState::Unlocked;
                        }
                    }
                    ui.add_space(1.0);
                    let notes_active = self.state == AppState::Notes;
                    if nav_btn(ui, "📝", "Secure Notes", notes_active, green) {
                        if notes_active {
                            self.notes_page_opened = None;
                            self.view_opened = Some(Instant::now());
                            self.state = AppState::Unlocked;
                        } else {
                            self.notes_page_opened = Some(Instant::now());
                            self.state = AppState::Notes;
                        }
                    }
                    ui.add_space(1.0);
                    let generator_active = self.state == AppState::GeneratorView;
                    if nav_btn(ui, "🎲", "Generator", generator_active, green) {
                        if generator_active {
                            self.generator_page_opened = None;
                            self.view_opened = Some(Instant::now());
                            self.state = AppState::Unlocked;
                        } else {
                            self.generator_page_opened = Some(Instant::now());
                            self.state = AppState::GeneratorView;
                        }
                    }

                    ui.add_space(12.0);
                    ui.painter().hline(
                        ui.available_rect_before_wrap().x_range(),
                        ui.cursor().top(),
                        egui::Stroke::new(1.0, c_divider),
                    );
                    ui.add_space(12.0);

                    // - - - TOOLS NAV - - -
                    ui.label(egui::RichText::new("  TOOLS").size(9.5).color(
                        egui::Color32::from_rgba_unmultiplied(c_sub.r(), c_sub.g(), c_sub.b(), 160)
                    ));
                    ui.add_space(4.0);

                    let settings_active = self.state == AppState::SettingsView;
                    if nav_btn(ui, "⚙️", "Settings", settings_active, green) {
                        if settings_active {
                            self.settings_page_opened = None;
                            self.view_opened = Some(Instant::now());
                            self.state = AppState::Unlocked;
                        } else {
                            self.settings_page_opened = Some(Instant::now());
                            self.state = AppState::SettingsView;
                        }
                    }
                    ui.add_space(1.0);
                    let import_export_open = matches!(&self.modal, Modal::ImportExport { .. });
                    if nav_btn(ui, "📤", "Import / Export", import_export_open, green) {
                        let preview = export_vault_json(&self.vault).unwrap_or_default();
                        self.modal = Modal::ImportExport {
                            active_tab: 0,
                            import_text: String::new(),
                            export_preview: preview,
                            export_password: String::new(),
                            import_password: String::new(),
                            encrypted_export: true,
                        };
                    }
                    ui.add_space(1.0);
                    let info_active = self.state == AppState::KnownBugs;
                    if nav_btn(ui, "ℹ️", "Info", info_active, green) {
                        if info_active {
                            self.info_page_opened = None;
                            self.view_opened = Some(Instant::now());
                            self.state = AppState::Unlocked;
                        } else {
                            self.info_page_opened = Some(Instant::now());
                            self.state = AppState::KnownBugs;
                        }
                    }
                    ui.add_space(1.0);
                    let vm_active = self.state == AppState::VaultManager;
                    if nav_btn(ui, "🗂", "Vaults", vm_active, green) {
                        if vm_active {
                            self.vault_manager_opened = None;
                            self.view_opened = Some(Instant::now());
                            self.state = AppState::Unlocked;
                        } else {
                            self.vault_manager_opened = Some(Instant::now());
                            self.state = AppState::VaultManager;
                        }
                    }

                    // - - - CATEGORIES (only on Passwords tab) - - -
                    if self.state == AppState::Unlocked && !all_categories.is_empty() {
                        ui.add_space(12.0);
                        ui.painter().hline(
                            ui.available_rect_before_wrap().x_range(),
                            ui.cursor().top(),
                            egui::Stroke::new(1.0, c_divider),
                        );
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new("  FILTER").size(9.5).color(
                            egui::Color32::from_rgba_unmultiplied(c_sub.r(), c_sub.g(), c_sub.b(), 160)
                        ));
                        ui.add_space(6.0);

                        let no_filter = self.active_category_filter.is_none() && self.active_tag_filter.is_none();
                        if filter_btn(ui, "All entries", no_filter, green) {
                            self.active_category_filter = None;
                            self.active_tag_filter = None;
                        }

                        if !all_categories.is_empty() {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("  Categories").size(10.0).color(c_sub));
                            ui.add_space(2.0);
                            let cats = all_categories.clone();
                            for cat in &cats {
                                let active = self.active_category_filter.as_deref() == Some(cat.as_str());
                                if filter_btn(ui, cat, active, green) {
                                    if active { self.active_category_filter = None; }
                                    else { self.active_category_filter = Some(cat.clone()); self.active_tag_filter = None; }
                                }
                            }
                        }

                        if !all_tags.is_empty() {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("  Tags").size(10.0).color(c_sub));
                            ui.add_space(2.0);
                            let tags = all_tags.clone();
                            for tag in &tags {
                                let active = self.active_tag_filter.as_deref() == Some(tag.as_str());
                                if filter_btn(ui, tag, active, green) {
                                    if active { self.active_tag_filter = None; }
                                    else { self.active_tag_filter = Some(tag.clone()); self.active_category_filter = None; }
                                }
                            }
                        }
                    }

                    // - - - NOTES FILTER (only on Notes tab) - - -
                    if self.state == AppState::Notes
                        && (!all_note_categories.is_empty() || !all_note_tags.is_empty())
                    {
                        ui.add_space(12.0);
                        ui.painter().hline(
                            ui.available_rect_before_wrap().x_range(),
                            ui.cursor().top(),
                            egui::Stroke::new(1.0, c_divider),
                        );
                        ui.add_space(12.0);
                        ui.label(egui::RichText::new("  FILTER").size(9.5).color(
                            egui::Color32::from_rgba_unmultiplied(c_sub.r(), c_sub.g(), c_sub.b(), 160)
                        ));
                        ui.add_space(6.0);

                        let no_note_filter = self.active_note_category_filter.is_none()
                            && self.active_note_tag_filter.is_none();
                        if filter_btn(ui, "All notes", no_note_filter, green) {
                            self.active_note_category_filter = None;
                            self.active_note_tag_filter = None;
                        }

                        if !all_note_categories.is_empty() {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("  Categories").size(10.0).color(c_sub));
                            ui.add_space(2.0);
                            let cats = all_note_categories.clone();
                            for cat in &cats {
                                let active = self.active_note_category_filter.as_deref() == Some(cat.as_str());
                                if filter_btn(ui, cat, active, green) {
                                    if active { self.active_note_category_filter = None; }
                                    else { self.active_note_category_filter = Some(cat.clone()); self.active_note_tag_filter = None; }
                                }
                            }
                        }

                        if !all_note_tags.is_empty() {
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new("  Tags").size(10.0).color(c_sub));
                            ui.add_space(2.0);
                            let tags = all_note_tags.clone();
                            for tag in &tags {
                                let active = self.active_note_tag_filter.as_deref() == Some(tag.as_str());
                                if filter_btn(ui, tag, active, green) {
                                    if active { self.active_note_tag_filter = None; }
                                    else { self.active_note_tag_filter = Some(tag.clone()); self.active_note_category_filter = None; }
                                }
                            }
                        }
                    } // - - - end NOTES FILTER block - - -

                    }); // - - - end sidebar_scroll ScrollArea - - -

                    ui.painter().hline(
                        ui.available_rect_before_wrap().x_range(),
                        ui.cursor().top(),
                        egui::Stroke::new(1.0, c_divider),
                    );
                    ui.add_space(10.0);

                    // - - - Context action (New Entry / New Note) - - -
                    if self.state == AppState::Unlocked {
                        if nav_btn(ui, "➕", "New Entry", false, green) {
                            self.modal = Modal::AddEntry {
                                service: String::new(), username: String::new(),
                                password: String::new(), password_length: self.default_password_length as f32,
                                totp_secret: String::new(), totp_open: false,
                                category: String::new(), tags: String::new(),
                            };
                        }
                        ui.add_space(2.0);
                    }
                    if self.state == AppState::Notes {
                        if nav_btn(ui, "➕", "New Note", false, green) {
                            self.modal = Modal::AddNote {
                                title: String::new(), content: String::new(),
                                category: String::new(), tags: String::new(),
                            };
                        }
                        ui.add_space(2.0);
                    }

                    // - - - Theme toggle + Lock on one row - - -
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 6.0;

                        // Theme pill button
                        let theme_icon = if dm { "☀️" } else { "🌙" };
                        let theme_tip  = if dm { "Light mode" } else { "Dark mode" };
                        let theme_btn = egui::Button::new(egui::RichText::new(theme_icon).size(13.0))
                            .fill(if dm { egui::Color32::from_rgb(32, 34, 52) } else { egui::Color32::from_rgb(232, 228, 220) })
                            .stroke(egui::Stroke::new(1.0, c_divider))
                            .rounding(8.0)
                            .min_size(egui::vec2(36.0, 32.0));
                        if ui.add(theme_btn).on_hover_text(theme_tip).clicked() {
                            self.dark_mode = !self.dark_mode;
                            let mut s = load_settings();
                            s.dark_mode = self.dark_mode;
                            save_settings(&s);
                            ctx.set_visuals(if self.dark_mode { egui::Visuals::dark() } else { egui::Visuals::light() });
                        }

                        // Lock button — fills remaining width
                        let lock_btn = egui::Button::new(
                            egui::RichText::new("🔒  Lock Vault").size(12.5)
                                .color(egui::Color32::from_rgb(200, 90, 90))
                        )
                        .fill(egui::Color32::from_rgba_unmultiplied(180, 50, 50, if dm { 22 } else { 14 }))
                        .stroke(egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(180, 50, 50, 60)))
                        .rounding(8.0)
                        .min_size(egui::vec2(ui.available_width(), 32.0));
                        if ui.add(lock_btn).clicked() {
                            self.lock_vault();
                        }
                    });
                });
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // - - - Main content area - - -
            match self.state {
                AppState::Locked => self.draw_locked_view(ui, ctx),
                AppState::Unlocking(start) => self.draw_loading_view(ui, start, "Unlocking vault...", "Deriving encryption key, please wait."),
                AppState::Unlocked => self.draw_unlocked_view(ui),
                AppState::NoVault => self.draw_no_vault_view(ui, ctx),
                AppState::CreatingVault(start) => self.draw_loading_view(ui, start, "Creating vault...", "This may take a moment."),
                AppState::KnownBugs => self.draw_known_bugs_view(ui),
                AppState::Notes => self.draw_notes_view(ui),
                AppState::SettingsView => self.draw_settings_view(ui, ctx),
                AppState::GeneratorView => self.draw_generator_view(ui, ctx),
                AppState::VaultManager => self.draw_vault_manager(ui, ctx),
            }
        });
        
        self.draw_toasts(ctx);
        self.draw_modals(ctx);
    }
}



fn load_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    
    fonts.font_data.insert("noto_sans".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/Inter_28pt-MediumItalic.ttf")));

    fonts.font_data.insert("noto_emoji".to_owned(),
        egui::FontData::from_static(include_bytes!("../assets/NotoEmoji-Regular.ttf")).tweak(
            egui::FontTweak { scale: 1.15, ..Default::default() }
        ));

    fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap()
        .insert(0, "noto_sans".to_owned());
    
    fonts.families.get_mut(&egui::FontFamily::Proportional).unwrap()
        .push("noto_emoji".to_owned());
        
    ctx.set_fonts(fonts);
}

fn main() -> Result<(), Box<dyn StdError>> {
    let settings = load_settings();

    // - - - Load registry and determine which vault to open - - -
    let mut registry = load_registry();

    // - - - Register the default vault if registry is empty - - -
    let default_path = default_vault_path()?;
    if registry.vaults.is_empty() && default_path.exists() {
        registry.vaults.push(VaultRecord {
            name: "Default Vault".to_string(),
            path: default_path.to_string_lossy().to_string(),
            last_opened: 0,
        });
        save_registry(&registry);
    }

    // - - - Pick the vault to open: last used, or default - - -
    let vault_path = registry.last_used_index
        .and_then(|i| registry.vaults.get(i))
        .map(|r| PathBuf::from(&r.path))
        .unwrap_or(default_path);

    // - - - Window icon from embedded RGBA pixel data - - -
    let viewport = egui::ViewportBuilder::default()
        .with_inner_size([1100.0, 720.0])
        .with_min_inner_size([800.0, 520.0])
        .with_position([160.0, 80.0])
        .with_icon(std::sync::Arc::new(egui::IconData {
            rgba: LOGO_256_RGBA.to_vec(),
            width: LOGO_256_W,
            height: LOGO_256_H,
        }));

    let options = eframe::NativeOptions {
        viewport,
        vsync: settings.vsync_enabled,
        ..Default::default()
    };
    
    eframe::run_native(
        "ZeroPass",
        options,
        Box::new(move |cc| {
            load_fonts(&cc.egui_ctx);
            Ok(Box::new(VaultGui::new(vault_path, settings)))
        }),
    ).map_err(|e| e.into())
}