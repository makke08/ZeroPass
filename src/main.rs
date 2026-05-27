#![windows_subsystem = "windows"]

use std::fs::{self, File};
use std::io::{Read, Write};
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
use rand::{RngCore, Rng};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};
use arboard::Clipboard;

// --- Constants ---
const MAGIC: &str = "RV_GUI_V1";
const MINIMUM_LOAD_TIME: Duration = Duration::from_millis(1500);

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

// --- Toast Notifications ---
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

// --- Error Handling ---
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

// --- Data Structures ---
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Entry {
    id: String,
    service: String,
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
struct Vault {
    entries: Vec<Entry>,
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
    compact_view: bool,
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
            compact_view: false,
        }
    }
}

// --- Core Logic ---

fn default_vault_path() -> Result<PathBuf, VaultError> {
    let proj = ProjectDirs::from("com", "example", "Aegis")
        .ok_or_else(|| VaultError::Msg("Unable to determine data dir".into()))?;
    let dir = proj.data_dir();
    fs::create_dir_all(dir)?;
    Ok(dir.join("vault.json.enc"))
}

fn settings_path() -> Result<PathBuf, Box<dyn StdError>> {
    let proj = ProjectDirs::from("com", "example", "Aegis")
        .ok_or_else(|| VaultError::Msg("Unable to determine data dir".into()))?;
    let dir = proj.data_dir();
    fs::create_dir_all(dir)?;
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
    }
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

// --- GUI State Management ---

#[derive(PartialEq, Debug)]
enum AppState {
    Locked,
    Unlocking(Instant),
    Unlocked,
    NoVault,
    CreatingVault(Instant),
    KnownBugs,
}

enum UnlockResult {
    Success(Vault),
    Error(String),
}

#[derive(Default)]
enum Modal {
    #[default]
    None,
    AddEntry { service: String, username: String, password: String, password_length: f32 },
    EditEntry { original_id: String, service: String, username: String, password: String },
    ChangePassword { old: String, new: String, confirm: String },
    DeleteVault { confirmation: String },
    Settings { 
        vsync_changed: bool, 
        theme_changed: bool, 
        active_tab: u8, // 0=Appearance, 1=Security, 2=Passwords, 3=Performance
    },
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct VaultGui {
    #[zeroize(skip)]
    state: AppState,
    #[zeroize(skip)]
    message: String,
    #[zeroize(skip)]
    vault_path: PathBuf,
    
    #[zeroize(skip)]
    vault: Vault,
    
    master_password: String,

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
    compact_view: bool,

    #[zeroize(skip)]
    last_activity: Instant,

    #[zeroize(skip)]
    toasts: Vec<Toast>,

    #[zeroize(skip)]
    info_page_opened: Option<Instant>,

    #[zeroize(skip)]
    view_opened: Option<Instant>,
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
            unlock_receiver: None,
            modal: Modal::None,
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
            compact_view: settings.compact_view,
            last_activity: Instant::now(),
            toasts: Vec::new(),
            info_page_opened: None,
            view_opened: Some(Instant::now()),
        }
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
        self.vault = Vault::default();
        self.state = if self.vault_path.exists() { AppState::Locked } else { AppState::NoVault };
        self.view_opened = Some(Instant::now());
        self.push_toast("Vault locked.".to_string(), ToastKind::Info);
        self.clipboard_clear_time = None;
        self.unlock_receiver = None;
        self.modal = Modal::None;
        self.search_query.clear();
    }

    fn add_entry_and_save(&mut self, service: String, username: String, password: String) {
        if service.is_empty() || username.is_empty() {
            self.push_toast("Service and username are required".into(), ToastKind::Error);
            return;
        }
        let entry = Entry {
            id: gen_id(),
            service: service.trim().to_string(),
            username: username.trim().to_string(),
            password,
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
            compact_view: self.compact_view,
        }
    }
}

// --- Modern UI Drawing Logic --- bright
impl VaultGui {
    fn draw_loading_spinner(&self, ui: &mut egui::Ui, elapsed_time: f32) {
        let spinner_radius = 30.0;
        let center = ui.available_rect_before_wrap().center();
        let painter = ui.painter();
        
        // Outer ring
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
                .color(if dm { egui::Color32::from_rgb(235, 235, 245) } else { egui::Color32::from_rgb(20, 20, 35) }));
            ui.add_space(8.0);
            ui.label(egui::RichText::new(subtitle).size(13.0)
                .color(if dm { egui::Color32::from_rgb(165, 165, 185) } else { egui::Color32::from_rgb(95, 95, 115) }));
        });
    }

    fn draw_locked_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let dm = self.dark_mode;
        let accent   = egui::Color32::from_rgb(99, 111, 245);
        let c_title  = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(18, 18, 34) };
        let c_sub    = if dm { egui::Color32::from_rgb(155, 158, 182) } else { egui::Color32::from_rgb(105, 105, 125) };
        let c_card   = if dm { egui::Color32::from_rgb(26, 29, 42) } else { egui::Color32::from_rgb(255, 255, 255) };
        let c_border = if dm { egui::Color32::from_rgb(58, 64, 92)  } else { egui::Color32::from_rgb(212, 212, 232) };
        let c_input  = if dm { egui::Color32::from_rgb(13, 14, 21)  } else { egui::Color32::from_rgb(244, 244, 252) };

        // Animation
        const ANIM_DUR: f32 = 0.45;
        const SLIDE_PX: f32 = 24.0;
        let elapsed = self.view_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_DUR + 0.25 { ui.ctx().request_repaint(); }

        ui.vertical_centered(|ui| {
            ui.set_max_width(360.0);

            // Icon + title block (delay 0.0)
            let t0 = anim_t(0.0);
            ui.add_space(52.0 + SLIDE_PX * (1.0 - t0));

            // Icon: filled accent circle with lock inside
            let icon_bg = if dm {
                egui::Color32::from_rgb(32, 36, 62)
            } else {
                egui::Color32::from_rgb(232, 232, 252)
            };
            egui::Frame::none()
                .fill(fc(icon_bg, t0))
                .rounding(28.0)
                .inner_margin(egui::Margin::symmetric(24.0, 20.0))
                .stroke(egui::Stroke::new(1.5, fc(accent, t0)))
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("🔒").size(48.0).color(fc(accent, t0)));
                });

            ui.add_space(20.0);
            ui.label(egui::RichText::new("Vault Locked").size(24.0).strong().color(fc(c_title, t0)));
            ui.add_space(5.0);
            ui.label(egui::RichText::new("Enter your master password to continue").size(13.0).color(fc(c_sub, t0)));
            ui.add_space(28.0);

            // Login card (delay 0.08)
            let t1 = anim_t(0.08);
            ui.add_space(SLIDE_PX * (1.0 - t1));

            let card = egui::Frame::none()
                .fill(fc(c_card, t1))
                .rounding(16.0)
                .inner_margin(egui::Margin::symmetric(24.0, 22.0))
                .stroke(egui::Stroke::new(1.0, fc(c_border, t1)));

            card.show(ui, |ui| {
                ui.set_min_width(300.0);

                let lbl_color = if dm { egui::Color32::from_rgb(175, 178, 205) } else { egui::Color32::from_rgb(80, 80, 100) };
                ui.label(egui::RichText::new("Master Password").size(11.5).color(fc(lbl_color, t1)));
                ui.add_space(5.0);

                let input_frame = egui::Frame::none()
                    .fill(fc(c_input, t1))
                    .rounding(10.0)
                    .inner_margin(egui::Margin::symmetric(13.0, 10.0))
                    .stroke(egui::Stroke::new(1.0, fc(c_border, t1)));
                input_frame.show(ui, |ui| {
                    let te = egui::TextEdit::singleline(&mut self.master_password)
                        .password(true)
                        .desired_width(ui.available_width())
                        .hint_text("Enter your master password")
                        .frame(false);
                    let resp = ui.add(te);
                    if resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
                        self.unlock_vault();
                    }
                });

                ui.add_space(14.0);

                ui.allocate_ui_with_layout(
                    egui::vec2(ui.available_width(), 44.0),
                    egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                    |ui| {
                        let btn = egui::Button::new(
                            egui::RichText::new("Unlock Vault").size(14.0).strong().color(fc(egui::Color32::WHITE, t1))
                        )
                        .fill(fc(accent, t1))
                        .rounding(10.0);
                        if ui.add(btn).clicked() { self.unlock_vault(); }
                    }
                );
            });

            ui.add_space(18.0);

            // Danger zone (delay 0.16)
            let t2 = anim_t(0.16);
            ui.add_space(SLIDE_PX * (1.0 - t2));

            let danger_red = egui::Color32::from_rgb(210, 68, 68);
            let danger_frame = egui::Frame::none()
                .fill(fc(if dm { egui::Color32::from_rgb(38, 14, 14) } else { egui::Color32::from_rgb(255, 243, 243) }, t2))
                .rounding(10.0)
                .inner_margin(egui::Margin::symmetric(16.0, 11.0))
                .stroke(egui::Stroke::new(1.0, fc(egui::Color32::from_rgb(130, 42, 42), t2)));

            danger_frame.show(ui, |ui| {
                ui.set_min_width(300.0);
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("⚠️").size(13.0).color(fc(danger_red, t2)));
                    ui.add_space(6.0);
                    ui.label(egui::RichText::new("Danger Zone").size(12.0).strong().color(fc(danger_red, t2)));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let del_btn = egui::Button::new(
                            egui::RichText::new("Delete Vault").size(11.5).color(fc(danger_red, t2))
                        )
                        .fill(egui::Color32::TRANSPARENT)
                        .stroke(egui::Stroke::new(1.0, fc(egui::Color32::from_rgb(150, 48, 48), t2)))
                        .rounding(7.0)
                        .min_size(egui::vec2(0.0, 26.0));
                        if ui.add(del_btn).clicked() {
                            self.modal = Modal::DeleteVault { confirmation: "".into() };
                        }
                    });
                });
            });
        });
    }

    fn draw_no_vault_view(&mut self, ui: &mut egui::Ui) {
        let dm = self.dark_mode;
        let accent   = egui::Color32::from_rgb(99, 111, 245);
        let c_title  = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(18, 18, 34) };
        let c_sub    = if dm { egui::Color32::from_rgb(160, 162, 185) } else { egui::Color32::from_rgb(100, 100, 122) };
        let c_card   = if dm { egui::Color32::from_rgb(28, 31, 44) } else { egui::Color32::from_rgb(255, 255, 255) };
        let c_border = if dm { egui::Color32::from_rgb(62, 68, 95)  } else { egui::Color32::from_rgb(210, 210, 230) };
        let c_input  = if dm { egui::Color32::from_rgb(13, 14, 21)  } else { egui::Color32::from_rgb(244, 244, 252) };

        // Animation
        const ANIM_DUR: f32 = 0.45;
        const SLIDE_PX: f32 = 28.0;
        let elapsed = self.view_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_DUR + 0.25 { ui.ctx().request_repaint(); }

        ui.vertical_centered(|ui| {
            ui.set_max_width(380.0);

            // Icon + title (delay 0.0)
            let t0 = anim_t(0.0);
            ui.add_space(50.0 + SLIDE_PX * (1.0 - t0));

            let icon_frame = egui::Frame::none()
                .fill(fc(if dm { egui::Color32::from_rgb(40, 44, 58) } else { egui::Color32::from_rgb(238, 238, 252) }, t0))
                .rounding(22.0)
                .inner_margin(egui::Margin::symmetric(22.0, 18.0))
                .stroke(egui::Stroke::new(1.5, fc(accent, t0)));
            icon_frame.show(ui, |ui| {
                let shield_col = if dm { egui::Color32::WHITE } else { egui::Color32::from_rgb(88, 101, 242) };
                ui.label(egui::RichText::new("🛡️").size(52.0).color(fc(shield_col, t0)));
            });

            ui.add_space(22.0);
            ui.label(egui::RichText::new("Welcome to Aegis").size(26.0).strong().color(fc(c_title, t0)));
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Your encrypted password vault — create one to begin").size(13.0).color(fc(c_sub, t0)));
            ui.add_space(10.0);

            // Feature pills (delay 0.08)
            let t1 = anim_t(0.08);
            ui.add_space(SLIDE_PX * (1.0 - t1));

            ui.horizontal_wrapped(|ui| {
                ui.add_space(20.0);
                for (icon, label) in [("🔐", "End-to-end encrypted"), ("⚡", "Fast & local"), ("🔑", "Argon2id KDF")] {
                    let pill = egui::Frame::none()
                        .fill(fc(if dm { egui::Color32::from_rgb(42, 47, 63) } else { egui::Color32::from_rgb(238, 238, 252) }, t1))
                        .rounding(20.0)
                        .inner_margin(egui::Margin::symmetric(10.0, 5.0))
                        .stroke(egui::Stroke::new(1.0, fc(if dm { egui::Color32::from_rgb(75, 82, 108) } else { egui::Color32::from_rgb(205, 205, 228) }, t1)));
                    pill.show(ui, |ui| {
                        ui.horizontal(|ui| {
                            let pill_icon_col = if dm { egui::Color32::WHITE } else { egui::Color32::from_rgb(88, 101, 242) };
                            ui.label(egui::RichText::new(icon).size(12.0).color(fc(pill_icon_col, t1)));
                            ui.label(egui::RichText::new(label).size(11.0).color(fc(if dm { egui::Color32::from_rgb(185, 185, 210) } else { egui::Color32::from_rgb(80, 80, 105) }, t1)));
                        });
                    });
                    ui.add_space(4.0);
                }
            });

            ui.add_space(28.0);

            // Create vault card (delay 0.16)
            let t2 = anim_t(0.16);
            ui.add_space(SLIDE_PX * (1.0 - t2));

            let card = egui::Frame::none()
                .fill(fc(c_card, t2))
                .rounding(16.0)
                .inner_margin(egui::Margin::symmetric(28.0, 24.0))
                .stroke(egui::Stroke::new(1.0, fc(c_border, t2)));

            card.show(ui, |ui| {
                ui.set_min_width(320.0);

                let lbl_color = if dm { egui::Color32::from_rgb(190, 190, 210) } else { egui::Color32::from_rgb(75, 75, 95) };
                ui.label(egui::RichText::new("✨  Choose a Master Password").size(12.0).color(fc(lbl_color, t2)));
                ui.add_space(4.0);
                ui.label(egui::RichText::new("This password encrypts everything — don't lose it.").size(11.0).color(fc(c_sub, t2)));
                ui.add_space(10.0);

                let input_frame = egui::Frame::none()
                    .fill(fc(c_input, t2))
                    .rounding(10.0)
                    .inner_margin(egui::Margin::symmetric(14.0, 11.0))
                    .stroke(egui::Stroke::new(1.0, fc(c_border, t2)));
                input_frame.show(ui, |ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.master_password)
                        .password(true)
                        .desired_width(ui.available_width())
                        .hint_text("Choose a strong master password")
                        .frame(false));
                });

                ui.add_space(14.0);

                let is_valid = !self.master_password.is_empty();
                let btn_fill = if is_valid { accent } else {
                    if dm { egui::Color32::from_rgb(50, 54, 68) } else { egui::Color32::from_rgb(200, 200, 215) }
                };

                ui.horizontal(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(ui.available_width(), 46.0),
                        egui::Layout::centered_and_justified(egui::Direction::LeftToRight),
                        |ui| {
                            let btn = egui::Button::new(
                                egui::RichText::new("✨  Create Vault").size(15.0).color(fc(egui::Color32::WHITE, t2))
                            )
                            .fill(fc(btn_fill, t2))
                            .rounding(10.0);
                            if ui.add_enabled(is_valid, btn).clicked() { self.create_new_vault(); }
                        }
                    );
                });
            });
        });
    }

    fn draw_unlocked_view(&mut self, ui: &mut egui::Ui) {
        let dm = self.dark_mode;
        let accent    = egui::Color32::from_rgb(99, 111, 245);
        let green     = egui::Color32::from_rgb(55, 168, 90);
        let c_title   = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(14, 14, 26) };
        let c_sub     = if dm { egui::Color32::from_rgb(160, 162, 185) } else { egui::Color32::from_rgb(95, 95, 115) };
        let c_card    = if dm { egui::Color32::from_rgb(28, 31, 44)  } else { egui::Color32::from_rgb(255, 255, 255) };
        let c_border  = if dm { egui::Color32::from_rgb(62, 68, 95)  } else { egui::Color32::from_rgb(218, 218, 232) };
        let c_input   = if dm { egui::Color32::from_rgb(13, 14, 21)  } else { egui::Color32::from_rgb(245, 245, 250) };
        let c_icon_bg = if dm { egui::Color32::from_rgb(48, 52, 72)  } else { egui::Color32::from_rgb(236, 236, 252) };
        let c_icon_st = if dm { egui::Color32::from_rgb(78, 85, 115) } else { egui::Color32::from_rgb(200, 200, 228) };

        // Animation — bar + search slide in as one block, entries stagger per-card
        const ANIM_DUR: f32 = 0.40;
        const SLIDE_PX: f32 = 22.0;
        let elapsed = self.view_opened.map(|t| t.elapsed().as_secs_f32()).unwrap_or(f32::MAX);
        let smooth = |t: f32| -> f32 { let t = t.clamp(0.0, 1.0); t * t * (3.0 - 2.0 * t) };
        let anim_t = |delay: f32| -> f32 { smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0)) };
        let fc = |base: egui::Color32, t: f32| -> egui::Color32 {
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), (t * 255.0) as u8)
        };
        if elapsed < ANIM_DUR + 0.5 { ui.ctx().request_repaint(); }

        // ── TOP ACTION BAR (delay 0.0) ──
        let t_bar = anim_t(0.0);
        ui.add_space(SLIDE_PX * (1.0 - t_bar));

        let bar_frame = egui::Frame::none()
            .fill(fc(c_card, t_bar))
            .rounding(14.0)
            .inner_margin(egui::Margin { left: 16.0, right: 16.0, top: 10.0, bottom: 10.0 })
            .stroke(egui::Stroke::new(1.0, fc(c_border, t_bar)));

        bar_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🔐  Passwords").size(14.0).strong().color(fc(c_title, t_bar)));
                ui.add_space(6.0);
                let count = self.vault.entries.len();
                let badge_bg = if dm { egui::Color32::from_rgb(55, 62, 92) } else { egui::Color32::from_rgb(228, 228, 252) };
                let badge_txt = if dm { egui::Color32::from_rgb(190, 195, 235) } else { accent };
                let badge = egui::Frame::none()
                    .fill(fc(badge_bg, t_bar))
                    .rounding(10.0)
                    .inner_margin(egui::Margin { left: 8.0, right: 8.0, top: 2.0, bottom: 2.0 });
                badge.show(ui, |ui| {
                    ui.label(egui::RichText::new(format!("{count}")).size(11.0).strong().color(fc(badge_txt, t_bar)));
                });

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let add_btn = egui::Button::new(
                        egui::RichText::new("✖️  New Entry").size(12.5).strong().color(fc(egui::Color32::WHITE, t_bar))
                    )
                    .fill(fc(green, t_bar)).rounding(9.0).min_size(egui::vec2(110.0, 34.0));
                    if ui.add(add_btn).clicked() {
                        self.modal = Modal::AddEntry {
                            service: String::new(), username: String::new(),
                            password: String::new(), password_length: self.default_password_length as f32,
                        };
                    }

                    ui.add_space(8.0);
                    let cur = ui.cursor();
                    let sep = fc(if dm { egui::Color32::from_rgb(58, 64, 90) } else { egui::Color32::from_rgb(215, 215, 232) }, t_bar);
                    ui.painter().vline(cur.left(), cur.y_range(), egui::Stroke::new(1.0, sep));
                    ui.add_space(8.0);

                    let lock_icon_col = if dm { egui::Color32::from_rgb(235, 110, 110) } else { egui::Color32::from_rgb(195, 55, 55) };
                    let lock_btn = egui::Button::new(egui::RichText::new("🔒").size(14.0).color(fc(lock_icon_col, t_bar)))
                        .fill(if dm { egui::Color32::TRANSPARENT } else { fc(egui::Color32::from_rgb(255, 243, 243), t_bar) })
                        .stroke(egui::Stroke::new(1.0, fc(egui::Color32::from_rgb(195, 60, 60), t_bar)))
                        .rounding(8.0).min_size(egui::vec2(34.0, 34.0));
                    if ui.add(lock_btn).on_hover_text("Lock vault").clicked() { self.lock_vault(); }

                    ui.add_space(4.0);

                    let icon_text_col = if dm { egui::Color32::from_rgb(210, 212, 235) } else { egui::Color32::from_rgb(60, 62, 95) };
                    let settings_btn = egui::Button::new(egui::RichText::new("⚙️").size(14.0).color(fc(icon_text_col, t_bar)))
                        .fill(fc(c_icon_bg, t_bar)).stroke(egui::Stroke::new(1.0, fc(c_icon_st, t_bar)))
                        .rounding(8.0).min_size(egui::vec2(34.0, 34.0));
                    if ui.add(settings_btn).on_hover_text("Settings").clicked() {
                        self.modal = Modal::Settings { 
                            vsync_changed: false, 
                            theme_changed: false, 
                            active_tab: 0,
                        };
                    }
                });
            });
        });

        // ── SEARCH BAR (delay 0.06) ──
        let t_search = anim_t(0.06);
        ui.add_space(12.0 + SLIDE_PX * (1.0 - t_search));

        let search_frame = egui::Frame::none()
            .fill(fc(c_input, t_search))
            .rounding(11.0)
            .inner_margin(egui::Margin { left: 14.0, right: 14.0, top: 9.0, bottom: 9.0 })
            .stroke(egui::Stroke::new(1.0, fc(c_border, t_search)));

        search_frame.show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🔍").size(14.0).color(fc(c_sub, t_search)));
                ui.add_space(6.0);
                ui.add(egui::TextEdit::singleline(&mut self.search_query)
                    .hint_text("Search by service or username…")
                    .desired_width(ui.available_width())
                    .frame(false));
            });
        });

        ui.add_space(14.0);

        // ── ENTRIES LIST — each card staggered ──
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            let mut to_remove_id: Option<String> = None;
            let search_lower = self.search_query.to_lowercase();

            let filtered_entries: Vec<Entry> = self.vault.entries.iter()
                .filter(|e| {
                    search_lower.is_empty()
                    || e.service.to_lowercase().contains(&search_lower)
                    || e.username.to_lowercase().contains(&search_lower)
                })
                .cloned()
                .collect();

            if filtered_entries.is_empty() {
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
                            .color(fc(if dm { egui::Color32::from_rgb(115, 115, 138) } else { egui::Color32::from_rgb(145, 145, 165) }, t_empty)));
                    }
                });
            }

            for (i, entry) in filtered_entries.iter().enumerate() {
                // Each card staggers by 0.04s per index, starting at 0.12s
                let t_card = anim_t(0.12 + i as f32 * 0.04);
                ui.add_space(SLIDE_PX * (1.0 - t_card));

                let card = egui::Frame::none()
                    .fill(fc(c_card, t_card))
                    .rounding(12.0)
                    .inner_margin(egui::Margin { left: 14.0, right: 14.0, top: 12.0, bottom: 12.0 })
                    .stroke(egui::Stroke::new(1.0, fc(c_border, t_card)));

                card.show(ui, |ui| {
                    ui.horizontal(|ui| {
                        let first_char = entry.service.chars().next().unwrap_or('?').to_uppercase().to_string();
                        let icon_size = 40.0;
                        let rect = ui.available_rect_before_wrap();
                        let center = egui::pos2(rect.left() + icon_size / 2.0, rect.top() + icon_size / 2.0);
                        // Subtle drop shadow
                        ui.painter().circle_filled(
                            egui::pos2(center.x + 1.5, center.y + 2.0),
                            icon_size / 2.0,
                            egui::Color32::from_rgba_premultiplied(0, 0, 0, if dm { 45 } else { 18 }),
                        );
                        ui.painter().circle_filled(center, icon_size / 2.0, fc(accent, t_card));
                        ui.painter().text(
                            center, egui::Align2::CENTER_CENTER, &first_char,
                            egui::FontId::proportional(16.0), fc(egui::Color32::WHITE, t_card),
                        );
                        ui.add_space(icon_size + 10.0);

                        ui.vertical(|ui| {
                            ui.label(egui::RichText::new(&entry.service).size(14.0).strong().color(fc(c_title, t_card)));
                            ui.add_space(1.0);
                            ui.label(egui::RichText::new(&entry.username).size(11.5).color(fc(c_sub, t_card)));
                            if self.show_passwords {
                                ui.add_space(2.0);
                                ui.label(egui::RichText::new(&entry.password).size(10.5)
                                    .color(fc(if dm { egui::Color32::from_rgb(120, 195, 120) } else { egui::Color32::from_rgb(35, 128, 58) }, t_card))
                                    .monospace());
                            }
                        });

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let del_col = if dm { egui::Color32::from_rgb(215, 70, 70) } else { egui::Color32::from_rgb(200, 55, 55) };
                            let del_bg  = if dm { egui::Color32::TRANSPARENT } else { egui::Color32::from_rgb(255, 245, 245) };
                            let del_btn = egui::Button::new(
                                egui::RichText::new("🗑️").size(13.0).color(fc(del_col, t_card))
                            )
                            .fill(fc(del_bg, t_card))
                            .stroke(egui::Stroke::new(1.0, fc(egui::Color32::from_rgb(195, 58, 58), t_card)))
                            .rounding(8.0).min_size(egui::vec2(32.0, 32.0));
                            if ui.add(del_btn).on_hover_text("Delete entry").clicked() {
                                to_remove_id = Some(entry.id.clone());
                            }

                            ui.add_space(4.0);

                            let edit_icon_col = if dm { egui::Color32::from_rgb(205, 208, 232) } else { egui::Color32::from_rgb(60, 62, 95) };
                            let edit_btn = egui::Button::new(egui::RichText::new("✏️").size(13.0).color(fc(edit_icon_col, t_card)))
                                .fill(fc(c_icon_bg, t_card)).stroke(egui::Stroke::new(1.0, fc(c_icon_st, t_card)))
                                .rounding(8.0).min_size(egui::vec2(32.0, 32.0));
                            if ui.add(edit_btn).on_hover_text("Edit entry").clicked() {
                                self.modal = Modal::EditEntry {
                                    original_id: entry.id.clone(),
                                    service: entry.service.clone(),
                                    username: entry.username.clone(),
                                    password: entry.password.clone(),
                                };
                            }

                            ui.add_space(4.0);

                            let copy_bg = if dm { egui::Color32::from_rgb(38, 105, 52) } else { egui::Color32::from_rgb(46, 158, 78) };
                            let copy_btn = egui::Button::new(egui::RichText::new("📋").size(13.0).color(fc(egui::Color32::WHITE, t_card)))
                                .fill(fc(copy_bg, t_card)).rounding(8.0).min_size(egui::vec2(32.0, 32.0));
                            if ui.add(copy_btn).on_hover_text("Copy password").clicked() {
                                self.copy_to_clipboard(entry.password.clone(), entry.service.clone());
                            }
                        });
                    });
                });

                ui.add_space(if self.compact_view { 4.0 } else { 8.0 });
            }

            if let Some(id) = to_remove_id {
                self.vault.entries.retain(|e| e.id != id);
                self.save_after_change();
            }
        });
    }

    fn draw_known_bugs_view(&mut self, ui: &mut egui::Ui) {
        let dm = self.dark_mode;
        let accent    = egui::Color32::from_rgb(99, 111, 245);
        let c_title   = if dm { egui::Color32::from_rgb(225, 225, 240) } else { egui::Color32::from_rgb(20, 20, 36) };
        let c_sub     = if dm { egui::Color32::from_rgb(148, 151, 175) } else { egui::Color32::from_rgb(108, 108, 130) };
        let c_card    = if dm { egui::Color32::from_rgb(26, 28, 42) } else { egui::Color32::from_rgb(255, 255, 255) };
        let c_border  = if dm { egui::Color32::from_rgb(55, 60, 88) } else { egui::Color32::from_rgb(215, 215, 235) };
        let c_row     = if dm { egui::Color32::from_rgb(20, 22, 34) } else { egui::Color32::from_rgb(246, 246, 252) };
        let green     = egui::Color32::from_rgb(72, 199, 116);
        let green_bg  = if dm { egui::Color32::from_rgb(14, 38, 22) } else { egui::Color32::from_rgb(236, 255, 244) };
        let green_bdr = egui::Color32::from_rgb(45, 148, 76);
        let discord   = egui::Color32::from_rgb(110, 132, 215);

        let card_margin   = egui::Margin::symmetric(20.0, 16.0);
        let card_rounding = 12.0_f32;

        // --- Animation setup ---
        // Each element (title, card1, card2) has its own stagger delay.
        // t goes 0→1 over ANIM_DUR seconds; ease = smooth-step.
        const ANIM_DUR: f32 = 0.45;
        const SLIDE_PX: f32 = 28.0;
        let elapsed = self.info_page_opened
            .map(|t| t.elapsed().as_secs_f32())
            .unwrap_or(f32::MAX);

        // smooth-step: 3t²-2t³
        let smooth = |t: f32| -> f32 {
            let t = t.clamp(0.0, 1.0);
            t * t * (3.0 - 2.0 * t)
        };

        // t for each layer given a stagger delay in seconds
        let anim_t = |delay: f32| -> f32 {
            smooth(((elapsed - delay) / ANIM_DUR).clamp(0.0, 1.0))
        };

        // If any animation is still running, keep repainting
        if elapsed < ANIM_DUR + 0.25 {
            ui.ctx().request_repaint();
        }

        // Helper: apply vertical offset + alpha fade by drawing into a child ui
        // We do this by offsetting the ui cursor with add_space and using painter alpha.
        // egui doesn't have a built-in opacity node, so we animate via a vertical
        // layout shift and blend text colors toward the background manually.
        // For a clean approach: use ui.add_space for slide, and color alpha for fade.
        let fade_color = |base: egui::Color32, t: f32| -> egui::Color32 {
            let a = (t * 255.0) as u8;
            egui::Color32::from_rgba_unmultiplied(base.r(), base.g(), base.b(), a)
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.set_max_width(480.0);

                // ── Title block ── (delay 0.0)
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

                // ── Version card ── (delay 0.08)
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

                            ui.label(
                                egui::RichText::new("Current version")
                                    .size(11.0)
                                    .color(fade_color(c_sub, t1)),
                            );
                            ui.add_space(8.0);

                            ui.horizontal(|ui| {
                                let badge_fill = egui::Color32::from_rgba_unmultiplied(
                                    if dm { 36 } else { 232 },
                                    if dm { 40 } else { 232 },
                                    if dm { 62 } else { 252 },
                                    (t1 * 255.0) as u8,
                                );
                                egui::Frame::none()
                                    .fill(badge_fill)
                                    .rounding(6.0)
                                    .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                                    .stroke(egui::Stroke::new(
                                        1.0,
                                        egui::Color32::from_rgba_unmultiplied(99, 111, 245, (t1 * 255.0) as u8),
                                    ))
                                    .show(ui, |ui| {
                                        ui.label(
                                            egui::RichText::new("v1.0.5")
                                                .size(13.0)
                                                .strong()
                                                .color(fade_color(accent, t1)),
                                        );
                                    });
                                ui.add_space(8.0);
                                ui.label(
                                    egui::RichText::new("2026-05-28")
                                        .size(13.0)
                                        .color(fade_color(c_sub, t1)),
                                );
                            });

                            ui.add_space(12.0);

                            let gbg = egui::Color32::from_rgba_unmultiplied(
                                green_bg.r(), green_bg.g(), green_bg.b(), (t1 * 255.0) as u8,
                            );
                            let gbdr = egui::Color32::from_rgba_unmultiplied(
                                green_bdr.r(), green_bdr.g(), green_bdr.b(), (t1 * 255.0) as u8,
                            );
                            egui::Frame::none()
                                .fill(gbg)
                                .rounding(8.0)
                                .inner_margin(egui::Margin::symmetric(12.0, 8.0))
                                .stroke(egui::Stroke::new(1.0, gbdr))
                                .show(ui, |ui| {
                                    ui.set_min_width(ui.available_width());
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new("✓")
                                                .size(13.0)
                                                .color(fade_color(green, t1)),
                                        );
                                        ui.add_space(8.0);
                                        ui.label(
                                            egui::RichText::new("Fixed: Light Mode.")
                                                .size(13.0)
                                                .color(fade_color(green, t1)),
                                        );
                                    });
                                });

                            ui.add_space(12.0);

                            // GitHub button — fades in with card
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
                                ui.ctx().open_url(egui::OpenUrl::new_tab("https://github.com/makke08/Aegis/releases"));
                            }
                        });

                    ui.add_space(12.0);
                }

                // ── Support card ── (delay 0.18)
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
                                ui.ctx().open_url(egui::OpenUrl::new_tab("https://discord.gg/hhbuwAmYgW"));
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

                // ── Vault Location card ── (delay 0.26)
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

                            // Path display box
                            let path_str = self.vault_path.to_string_lossy().to_string();
                            let path_bg = if dm {
                                egui::Color32::from_rgba_unmultiplied(13, 14, 21, (t3 * 255.0) as u8)
                            } else {
                                egui::Color32::from_rgba_unmultiplied(244, 244, 252, (t3 * 255.0) as u8)
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

                            // "Open folder" button
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
                            let open_btn = egui::Button::new(
                                egui::RichText::new("📂  Open vault folder")
                                    .size(12.0)
                                    .color(btn_text_col),
                            )
                            .fill(btn_col)
                            .stroke(egui::Stroke::new(1.0, btn_border))
                            .rounding(8.0)
                            .min_size(egui::vec2(160.0, 32.0));

                            if ui.add(open_btn).clicked() {
                                // Open the parent directory in the OS file manager
                                if let Some(parent) = self.vault_path.parent() {
                                    #[cfg(target_os = "windows")]
                                    { let _ = std::process::Command::new("explorer").arg(parent).spawn(); }
                                    #[cfg(target_os = "macos")]
                                    { let _ = std::process::Command::new("open").arg(parent).spawn(); }
                                    #[cfg(target_os = "linux")]
                                    { let _ = std::process::Command::new("xdg-open").arg(parent).spawn(); }
                                }
                            }
                        });

                    ui.add_space(24.0);
                }
            });
        });
    }
    
    fn draw_toasts(&mut self, ctx: &egui::Context) {
        let dm = self.dark_mode;
        let now = Instant::now();

        // Expire old toasts
        self.toasts.retain(|t| now.duration_since(t.spawned).as_secs_f32() < TOAST_TOTAL_SECS);

        let screen_rect = ctx.screen_rect();
        let toast_w = 300.0_f32;
        // Anchored Top-Right layout
        let toast_x = screen_rect.width() - toast_w - 16.0;  
        let base_y  = 16.0_f32;  // top margin

        // Collect render info first to avoid borrow issues
        let renders: Vec<(String, ToastKind, f32, f32)> = self.toasts.iter().enumerate().map(|(i, t)| {
            let elapsed = now.duration_since(t.spawned).as_secs_f32();
            // y offset: fly in from above (negative → 0), fly out upward (0 → negative)
            let y_offset = if elapsed < TOAST_ENTER_SECS {
                // entering: fly down from -60
                let p = elapsed / TOAST_ENTER_SECS;
                let p = 1.0 - (1.0 - p) * (1.0 - p);  // ease-out quad
                -60.0 * (1.0 - p)
            } else if elapsed > TOAST_ENTER_SECS + TOAST_HOLD_SECS {
                // exiting: fly up
                let p = (elapsed - TOAST_ENTER_SECS - TOAST_HOLD_SECS) / TOAST_EXIT_SECS;
                let p = p * p;  // ease-in quad
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
                    if dm { egui::Color32::from_rgb(18, 44, 28) } else { egui::Color32::from_rgb(238, 255, 244) },
                    egui::Color32::from_rgb(55, 160, 88),
                    "✅",
                    egui::Color32::from_rgb(100, 210, 140),
                ),
                ToastKind::Error => (
                    if dm { egui::Color32::from_rgb(52, 22, 22) } else { egui::Color32::from_rgb(255, 240, 240) },
                    egui::Color32::from_rgb(180, 55, 55),
                    "❌",
                    egui::Color32::from_rgb(255, 120, 120),
                ),
                ToastKind::Info => (
                    if dm { egui::Color32::from_rgb(22, 26, 52) } else { egui::Color32::from_rgb(240, 242, 255) },
                    egui::Color32::from_rgb(88, 101, 242),
                    "ℹ️",
                    egui::Color32::from_rgb(140, 170, 255),
                ),
            };

            fn with_alpha(c: egui::Color32, a: f32) -> egui::Color32 {
                let a8 = (a * 255.0) as u8;
                egui::Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a8)
            }

            // Shadow
            painter.rect_filled(
                rect.translate(egui::vec2(2.0, 2.0)),
                10.0,
                with_alpha(egui::Color32::from_rgb(0, 0, 0), alpha * 0.25),
            );
            // Background
            painter.rect_filled(rect, 10.0, with_alpha(bg, alpha));
            // Border
            painter.rect_stroke(rect, 10.0, egui::Stroke::new(1.0, with_alpha(border, alpha)));

            // Icon
            let icon_pos = egui::pos2(rect.left() + 14.0, rect.center().y);
            painter.text(
                icon_pos,
                egui::Align2::LEFT_CENTER,
                icon,
                egui::FontId::proportional(13.0),
                with_alpha(egui::Color32::WHITE, alpha),
            );

            // Message (truncate if too long)
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

        // Keep repainting while toasts are animating
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
        let c_title   = if dm { egui::Color32::from_rgb(232, 232, 245) } else { egui::Color32::from_rgb(18, 18, 34) };
        let c_sub     = if dm { egui::Color32::from_rgb(160, 162, 185) } else { egui::Color32::from_rgb(100, 100, 122) };
        // Modal window: clearly lighter than panel (18,20,28)
        let c_win     = if dm { egui::Color32::from_rgb(28, 31, 44)  } else { egui::Color32::from_rgb(255, 255, 255) };
        // Input: clearly darker than modal window — deep inset look
        let c_input   = if dm { egui::Color32::from_rgb(13, 14, 21)  } else { egui::Color32::from_rgb(244, 244, 252) };
        // Border: well above both fills
        let c_border  = if dm { egui::Color32::from_rgb(62, 68, 95)  } else { egui::Color32::from_rgb(205, 205, 228) };
        // Field labels: bright enough to read easily
        let c_lbl     = if dm { egui::Color32::from_rgb(188, 190, 215) } else { egui::Color32::from_rgb(68, 68, 92) };
        // Cancel button: clearly visible, not overpowering
        let c_cancel  = if dm { egui::Color32::from_rgb(45, 50, 70)  } else { egui::Color32::from_rgb(215, 215, 232) };

        // Helper to make a styled input field frame
        let input_field = |ui: &mut egui::Ui, fill: egui::Color32, stroke: egui::Stroke| {
            egui::Frame::none().fill(fill).rounding(9.0)
                .inner_margin(egui::Margin::symmetric(12.0, 9.0)).stroke(stroke)
        };

        match &mut current_modal {
            Modal::None => return,

            // ────────────────────────────────────────────────────────────
            //  ADD ENTRY
            // ────────────────────────────────────────────────────────────
            Modal::AddEntry { service, username, password, password_length } => {
                egui::Window::new("➕  Add New Entry")
                    .open(&mut modal_is_open)
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
                        // Title bar
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(248, 248, 253) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(36, 40, 58) } else { egui::Color32::from_rgb(230, 248, 236) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("➕").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Add New Entry").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 18.0 })
                            .show(ui, |ui| {
                                // Sub-header
                                ui.label(egui::RichText::new("Fill in the details for the new entry.").size(12.0).color(c_sub));
                                ui.add_space(14.0);

                                let field_stroke = egui::Stroke::new(1.0, c_border);

                                // Service
                                ui.label(egui::RichText::new("🌐  Service").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(service)
                                .hint_text("e.g. GitHub, Gmail, Netflix")
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(10.0);

                        // Username
                        ui.label(egui::RichText::new("👤  Username / Email").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(username)
                                .hint_text("Username or email address")
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(10.0);

                        // Password
                        ui.label(egui::RichText::new("🔐  Password").size(12.0).color(c_lbl));
                        ui.add_space(4.0);
                        input_field(ui, c_input, field_stroke).show(ui, |ui| {
                            ui.add(egui::TextEdit::singleline(password)
                                .password(true)
                                .hint_text("Enter or generate a password")
                                .desired_width(ui.available_width()).frame(false));
                        });

                        ui.add_space(14.0);

                        // Password generator panel
                        let gen_frame = egui::Frame::none()
                            .fill(if dm { egui::Color32::from_rgb(13, 14, 21) } else { egui::Color32::from_rgb(240, 240, 252) })
                            .rounding(10.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 12.0))
                            .stroke(egui::Stroke::new(1.0, if dm { egui::Color32::from_rgb(58, 64, 90) } else { egui::Color32::from_rgb(200, 200, 225) }));

                        gen_frame.show(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(egui::RichText::new("🎲  Length").size(12.0).color(c_lbl));
                                ui.add_space(6.0);
                                ui.add(egui::Slider::new(password_length, 8.0..=64.0)
                                    .text("chars").show_value(true));
                            });
                            ui.add_space(8.0);
                            let gen_btn = egui::Button::new(
                                egui::RichText::new("🎲  Generate Password").size(12.0).color(egui::Color32::WHITE)
                            )
                            .fill(accent).rounding(7.0).min_size(egui::vec2(160.0, 30.0));
                            if ui.add(gen_btn).clicked() {
                                *password = generate_password(
                                    *password_length as usize, 
                                    self.gen_use_uppercase, 
                                    self.gen_use_numbers, 
                                    self.gen_use_symbols
                                );
                            }
                        });

                        ui.add_space(18.0);

                        // Action row
                        ui.horizontal(|ui| {
                            let can_add = !service.is_empty() && !username.is_empty();
                            let add_fill = if can_add { green } else {
                                if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(200, 200, 215) }
                            };
                            let add_btn = egui::Button::new(
                                egui::RichText::new("➕  Add Entry").size(14.0).color(egui::Color32::WHITE)
                            )
                            .fill(add_fill).rounding(9.0).min_size(egui::vec2(130.0, 40.0));
                            if ui.add_enabled(can_add, add_btn).clicked() {
                                self.add_entry_and_save(service.clone(), username.clone(), password.clone());
                                close_on_action = true;
                            }
                            ui.add_space(8.0);
                            let cancel_btn = egui::Button::new(
                                egui::RichText::new("Cancel").size(13.0).color(c_title)
                            )
                            .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 40.0));
                            if ui.add(cancel_btn).clicked() { close_on_action = true; }
                        });
                        }); // inner frame
                    });
            }
            // ────────────────────────────────────────────────────────────
            //  EDIT ENTRY
            // ────────────────────────────────────────────────────────────
            Modal::EditEntry { original_id, service, username, password } => {
                egui::Window::new("edit_entry_modal")
                    .open(&mut modal_is_open)
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
                        // Title bar
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(248, 248, 253) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(36, 40, 58) } else { egui::Color32::from_rgb(232, 232, 248) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("✏️").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Edit Entry").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 18.0 })
                            .show(ui, |ui| {
                                let field_stroke = egui::Stroke::new(1.0, c_border);

                                ui.label(egui::RichText::new("🌐  Service").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(service).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("👤  Username / Email").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(username).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(10.0);

                                ui.label(egui::RichText::new("🔐  Password").size(12.0).color(c_lbl));
                                ui.add_space(4.0);
                                input_field(ui, c_input, field_stroke).show(ui, |ui| {
                                    ui.add(egui::TextEdit::singleline(password).password(true).desired_width(ui.available_width()).frame(false));
                                });
                                ui.add_space(18.0);

                                ui.horizontal(|ui| {
                                    let save_btn = egui::Button::new(
                                        egui::RichText::new("💾  Save Changes").size(14.0).color(egui::Color32::WHITE)
                                    )
                                    .fill(accent).rounding(9.0).min_size(egui::vec2(140.0, 40.0));
                                    if ui.add(save_btn).clicked() {
                                        if let Some(entry) = self.vault.entries.iter_mut().find(|e| &e.id == original_id) {
                                            entry.service = service.clone();
                                            entry.username = username.clone();
                                            entry.password = password.clone();
                                            self.save_after_change();
                                        }
                                        close_on_action = true;
                                    }
                                    ui.add_space(8.0);
                                    let cancel_btn = egui::Button::new(
                                        egui::RichText::new("Cancel").size(13.0).color(c_title)
                                    )
                                    .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 40.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            }); // inner frame
                    });
            }

            // ────────────────────────────────────────────────────────────
            //  CHANGE MASTER PASSWORD
            // ────────────────────────────────────────────────────────────
            Modal::ChangePassword { old, new, confirm } => {
                egui::Window::new("change_pw_modal")
                    .open(&mut modal_is_open)
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
                        let title_bg = if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::from_rgb(248, 248, 253) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let icon_bg = if dm { egui::Color32::from_rgb(40, 36, 58) } else { egui::Color32::from_rgb(235, 232, 252) };
                                    egui::Frame::none().fill(icon_bg).rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| { ui.label(egui::RichText::new("🔑").size(13.0)); });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Change Master Password").size(14.0).strong().color(c_title));
                                });
                            });
                        ui.painter().hline(ui.available_rect_before_wrap().x_range(), ui.cursor().top(), egui::Stroke::new(1.0, c_border));
                        egui::Frame::none()
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 18.0 })
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

                                if mismatch {
                                    ui.add_space(6.0);
                                    let warn_frame = egui::Frame::none()
                                        .fill(if dm { egui::Color32::from_rgb(50, 18, 18) } else { egui::Color32::from_rgb(255, 240, 240) })
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

                                ui.add_space(18.0);

                                ui.horizontal(|ui| {
                                    let can_change = !old.is_empty() && !new.is_empty() && new == confirm;
                                    let btn_fill = if can_change { accent } else {
                                        if dm { egui::Color32::from_rgb(44, 48, 62) } else { egui::Color32::from_rgb(200, 200, 215) }
                                    };
                                    let change_btn = egui::Button::new(
                                        egui::RichText::new("💾  Change Password").size(14.0).color(egui::Color32::WHITE)
                                    )
                                    .fill(btn_fill).rounding(9.0).min_size(egui::vec2(160.0, 40.0));
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
                                    )
                                    .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 40.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            }); // inner frame
                    });
            }

            // ────────────────────────────────────────────────────────────
            //  DELETE VAULT
            // ────────────────────────────────────────────────────────────
            Modal::DeleteVault { confirmation } => {
                egui::Window::new("delete_vault_modal")
                    .open(&mut modal_is_open)
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
                            .inner_margin(egui::Margin { left: 18.0, right: 18.0, top: 16.0, bottom: 18.0 })
                            .show(ui, |ui| {
                                // Warning banner
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

                                ui.add_space(18.0);

                                ui.horizontal(|ui| {
                                    let enabled = !confirmation.is_empty();
                                    let del_fill = if enabled { egui::Color32::from_rgb(200, 55, 55) } else {
                                        if dm { egui::Color32::from_rgb(60, 40, 40) } else { egui::Color32::from_rgb(210, 190, 190) }
                                    };
                                    let del_btn = egui::Button::new(
                                        egui::RichText::new("🗑️  Delete Vault").size(14.0).color(egui::Color32::WHITE)
                                    )
                                    .fill(del_fill).rounding(9.0).min_size(egui::vec2(140.0, 40.0));
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
                                    )
                                    .fill(c_cancel).rounding(9.0).min_size(egui::vec2(90.0, 40.0));
                                    if ui.add(cancel_btn).clicked() { close_on_action = true; }
                                });
                            }); // inner frame
                    });
            }


            // ────────────────────────────────────────────────────────────
            //  SETTINGS
            // ────────────────────────────────────────────────────────────
            Modal::Settings { vsync_changed, theme_changed, active_tab } => {
                // ── Tabs: 0=Appearance, 1=Security, 2=Passwords, 3=Performance ──
                let tabs: &[(&str, &str)] = &[
                    ("🌙", "Appearance"),
                    ("🔒", "Security"),
                    ("🎲", "Passwords"),
                    ("🖥️", "Performance"),
                ];

                // Colors
                let c_sidebar = if dm { egui::Color32::from_rgb(11, 12, 19) } else { egui::Color32::from_rgb(242, 242, 250) };
                let c_divider = if dm { egui::Color32::from_rgb(42, 46, 62) } else { egui::Color32::from_rgb(218, 218, 234) };
                let c_tab_active_bg = if dm { egui::Color32::from_rgb(32, 36, 58) } else { egui::Color32::from_rgb(255, 255, 255) };
                let c_tab_hover_bg  = if dm { egui::Color32::from_rgb(24, 26, 42) } else { egui::Color32::from_rgb(232, 232, 248) };
                let c_tab_icon_active = accent;
                let c_tab_icon_idle   = if dm { egui::Color32::from_rgb(115, 120, 152) } else { egui::Color32::from_rgb(148, 148, 175) };

                // Helper: animated toggle
                let draw_toggle = |ui: &mut egui::Ui, ctx: &egui::Context, id: &str, value: bool, accent: egui::Color32| -> bool {
                    let switch_size = egui::vec2(46.0, 26.0);
                    let (rect, response) = ui.allocate_exact_size(switch_size, egui::Sense::click());
                    let clicked = response.clicked();
                    let cur_val = if clicked { !value } else { value };
                    let t = ctx.animate_bool_with_time(egui::Id::new(id), cur_val, 0.18);
                    if ui.is_rect_visible(rect) {
                        let off_color = if dm { egui::Color32::from_rgb(68, 72, 96) } else { egui::Color32::from_rgb(200, 200, 218) };
                        let bg = egui::Color32::from_rgb(
                            (off_color.r() as f32 + (accent.r() as f32 - off_color.r() as f32) * t) as u8,
                            (off_color.g() as f32 + (accent.g() as f32 - off_color.g() as f32) * t) as u8,
                            (off_color.b() as f32 + (accent.b() as f32 - off_color.b() as f32) * t) as u8,
                        );
                        ui.painter().rect_filled(rect, 13.0, bg);
                        let knob_min_x = rect.left() + 12.0;
                        let knob_max_x = rect.right() - 12.0;
                        let cx = knob_min_x + (knob_max_x - knob_min_x) * t;
                        ui.painter().circle_filled(egui::pos2(cx, rect.center().y + 0.5), 8.5, egui::Color32::from_rgba_premultiplied(0, 0, 0, 30));
                        ui.painter().circle_filled(egui::pos2(cx, rect.center().y), 8.5, egui::Color32::WHITE);
                        if t > 0.01 && t < 0.99 { ctx.request_repaint(); }
                    }
                    clicked
                };

                // Helper: draw a clean settings row with icon, title, subtitle, and right widget
                let row_divider = |ui: &mut egui::Ui| {
                    let col = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(230, 230, 244) };
                    let r = ui.available_rect_before_wrap();
                    ui.painter().hline(r.x_range(), ui.cursor().top(), egui::Stroke::new(1.0, col));
                    ui.add_space(1.0);
                };

                egui::Window::new("Settings")
                    .title_bar(false)
                    .open(&mut modal_is_open)
                    .resizable(false)
                    .collapsible(false)
                    .default_width(529.0)
                    .fixed_size(egui::vec2(529.0, 510.0))
                    .frame(
                        egui::Frame::window(&ctx.style())
                            .fill(if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::WHITE })
                            .rounding(14.0)
                            .stroke(egui::Stroke::new(1.0, c_divider))
                            .inner_margin(egui::Margin::same(0.0))
                    )
                    .show(ctx, |ui| {
                        // ── Custom title bar — rounded top to match outer window ──
                        let title_bg = if dm { egui::Color32::from_rgb(13, 14, 21) } else { egui::Color32::from_rgb(248, 248, 253) };
                        egui::Frame::none()
                            .fill(title_bg)
                            .rounding(egui::Rounding { nw: 14.0, ne: 14.0, sw: 0.0, se: 0.0 })
                            .inner_margin(egui::Margin { left: 20.0, right: 16.0, top: 14.0, bottom: 14.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    // Icon pill
                                    let icon_bg = if dm {
                                        egui::Color32::from_rgb(36, 40, 60)
                                    } else {
                                        egui::Color32::from_rgb(230, 230, 248)
                                    };
                                    egui::Frame::none()
                                        .fill(icon_bg)
                                        .rounding(8.0)
                                        .inner_margin(egui::Margin::symmetric(7.0, 5.0))
                                        .show(ui, |ui| {
                                            ui.label(egui::RichText::new("⚙️").size(14.0));
                                        });
                                    ui.add_space(8.0);
                                    ui.label(egui::RichText::new("Settings").size(14.0).strong().color(c_title));
                                });
                            });

                        // Thin separator
                        ui.painter().hline(
                            ui.available_rect_before_wrap().x_range(),
                            ui.cursor().top(),
                            egui::Stroke::new(1.0, c_divider),
                        );

                        // ── Two-column layout: sidebar + content ──────────────
                        let body_height = 430.0_f32;
                        let sidebar_width = 128.0_f32;
                        let content_width = 400.0_f32;

                        ui.horizontal(|ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);

                            // Left sidebar — fixed width column
                            ui.allocate_ui_with_layout(
                                egui::vec2(sidebar_width, body_height),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                                    egui::Frame::none()
                                        .fill(c_sidebar)
                                        .rounding(egui::Rounding { nw: 0.0, ne: 0.0, sw: 14.0, se: 0.0 })
                                        .inner_margin(egui::Margin { left: 6.0, right: 6.0, top: 12.0, bottom: 12.0 })
                                        .show(ui, |ui| {
                                            ui.set_width(sidebar_width);
                                            ui.set_min_height(body_height);

                                            for (i, (icon, label)) in tabs.iter().enumerate() {
                                                let is_active = *active_tab == i as u8;
                                                let tab_t = ctx.animate_bool_with_time(
                                                    egui::Id::new(format!("settings_tab_{}", i)),
                                                    is_active,
                                                    0.15,
                                                );
                                                let icon_col = egui::Color32::from_rgb(
                                                    (c_tab_icon_idle.r() as f32 + (c_tab_icon_active.r() as f32 - c_tab_icon_idle.r() as f32) * tab_t) as u8,
                                                    (c_tab_icon_idle.g() as f32 + (c_tab_icon_active.g() as f32 - c_tab_icon_idle.g() as f32) * tab_t) as u8,
                                                    (c_tab_icon_idle.b() as f32 + (c_tab_icon_active.b() as f32 - c_tab_icon_idle.b() as f32) * tab_t) as u8,
                                                );
                                                // Detect hover before drawing so we can set the correct bg fill
                                                // We allocate a probe rect at the cursor to check pointer position
                                                let tab_id = egui::Id::new(format!("tab_click_{}", i));
                                                let is_hovered = ctx.pointer_hover_pos()
                                                    .map(|p| {
                                                        // Estimate tab rect from current cursor
                                                        let tab_top = ui.cursor().top();
                                                        let tab_rect = egui::Rect::from_min_size(
                                                            egui::pos2(ui.cursor().left(), tab_top),
                                                            egui::vec2(sidebar_width, 56.0),
                                                        );
                                                        tab_rect.contains(p)
                                                    })
                                                    .unwrap_or(false);

                                                let hover_t = ctx.animate_bool_with_time(
                                                    egui::Id::new(format!("settings_tab_hover_{}", i)),
                                                    is_hovered && !is_active,
                                                    0.15,
                                                );

                                                let bg_col = if is_active {
                                                    c_tab_active_bg
                                                } else {
                                                    // Lerp sidebar → hover bg
                                                    egui::Color32::from_rgb(
                                                        (c_sidebar.r() as f32 + (c_tab_hover_bg.r() as f32 - c_sidebar.r() as f32) * hover_t) as u8,
                                                        (c_sidebar.g() as f32 + (c_tab_hover_bg.g() as f32 - c_sidebar.g() as f32) * hover_t) as u8,
                                                        (c_sidebar.b() as f32 + (c_tab_hover_bg.b() as f32 - c_sidebar.b() as f32) * hover_t) as u8,
                                                    )
                                                };

                                                let tab_frame = egui::Frame::none()
                                                    .fill(bg_col)
                                                    .rounding(egui::Rounding::same(10.0))
                                                    .stroke(if is_active {
                                                        egui::Stroke::new(1.0, egui::Color32::from_rgba_unmultiplied(99, 111, 245, 60))
                                                    } else {
                                                        egui::Stroke::NONE
                                                    })
                                                    .inner_margin(egui::Margin { left: 10.0, right: 10.0, top: 9.0, bottom: 9.0 });

                                                let tab_resp = tab_frame.show(ui, |ui| {
                                                    ui.set_min_width(sidebar_width - 20.0);
                                                    ui.horizontal(|ui| {
                                                        // Accent indicator bar
                                                        if is_active {
                                                            let bar_rect = egui::Rect::from_min_size(
                                                                ui.cursor().min - egui::vec2(10.0, 0.0),
                                                                egui::vec2(3.0, 36.0),
                                                            );
                                                            ui.painter().rect_filled(bar_rect, 2.0, accent);
                                                            ui.add_space(4.0);
                                                        } else {
                                                            ui.add_space(7.0);
                                                        }
                                                        ui.vertical(|ui| {
                                                            ui.label(egui::RichText::new(*icon).size(18.0).color(icon_col));
                                                            ui.add_space(2.0);
                                                            let lbl_col = if is_active { c_title } else { c_sub };
                                                            ui.label(egui::RichText::new(*label).size(10.5).color(lbl_col));
                                                        });
                                                    });

                                                    // Shimmer sweep: bright band slides cleanly left→right on hover entry,
                                                    // clamped so it never overshoots the button edge.
                                                    if hover_t > 0.01 && !is_active {
                                                        let r = ui.min_rect();
                                                        // Clamp band center to [left, right] range
                                                        let progress = (hover_t * 1.2).min(1.0);
                                                        let band_x = r.left() + r.width() * progress;
                                                        let band_half = r.width() * 0.30;
                                                        let painter = ui.painter();
                                                        let steps = 16i32;
                                                        for s in 0..steps {
                                                            let fx = s as f32 / (steps - 1) as f32;
                                                            let dx = (fx - 0.5) * 2.0;
                                                            let falloff = (-dx * dx * 4.0).exp();
                                                            // Fade out as sweep completes so it doesn't linger
                                                            let sweep_fade = 1.0 - (hover_t * 1.2 - 1.0).max(0.0) / 0.2;
                                                            let alpha = (falloff * sweep_fade * 22.0) as u8;
                                                            if alpha == 0 { continue; }
                                                            let x = band_x + (fx - 0.5) * band_half * 2.0;
                                                            let slice = egui::Rect::from_min_max(
                                                                egui::pos2(x - band_half / steps as f32, r.top()),
                                                                egui::pos2(x + band_half / steps as f32, r.bottom()),
                                                            );
                                                            painter.rect_filled(
                                                                slice,
                                                                0.0,
                                                                egui::Color32::from_rgba_unmultiplied(210, 215, 255, alpha),
                                                            );
                                                        }
                                                    }
                                                });
                                                let tab_interact = ui.interact(
                                                    tab_resp.response.rect,
                                                    tab_id,
                                                    egui::Sense::click(),
                                                );
                                                if hover_t > 0.01 && hover_t < 0.99 { ctx.request_repaint(); }
                                                if tab_interact.clicked() {
                                                    *active_tab = i as u8;
                                                }
                                                ui.add_space(2.0);
                                            }
                                        });
                                },
                            );

                            // Vertical divider
                            let avail = ui.available_rect_before_wrap();
                            ui.painter().vline(avail.left(), avail.y_range(), egui::Stroke::new(1.0, c_divider));
                            ui.add_space(1.0);

                            // Right content panel — fixed width column
                            ui.allocate_ui_with_layout(
                                egui::vec2(content_width, body_height),
                                egui::Layout::top_down(egui::Align::Min),
                                |ui| {
                            egui::Frame::none()
                                .fill(if dm { egui::Color32::from_rgb(20, 22, 32) } else { egui::Color32::WHITE })
                                .rounding(egui::Rounding { nw: 0.0, ne: 0.0, sw: 0.0, se: 14.0 })
                                .inner_margin(egui::Margin { left: 20.0, right: 20.0, top: 18.0, bottom: 18.0 })
                                .show(ui, |ui| {
                                    ui.set_min_width(content_width - 40.0);

                                    egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                                        ui.set_min_width(370.0);

                                        match *active_tab {

                                            // ── Tab 0: Appearance ─────────────────────────
                                            0 => {
                                                ui.label(egui::RichText::new("Appearance").size(13.0).strong().color(c_title));
                                                ui.add_space(14.0);

                                                // Row: Dark Mode
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Dark Mode").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Toggle dark / light theme").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        let was_dark = self.dark_mode;
                                                        if draw_toggle(ui, ctx, "toggle_dark_mode", self.dark_mode, accent) {
                                                            self.dark_mode = !self.dark_mode;
                                                        }
                                                        if was_dark != self.dark_mode {
                                                            save_settings(&self.to_settings());
                                                            *theme_changed = true;
                                                        }
                                                    });
                                                });

                                                if *theme_changed {
                                                    ui.add_space(10.0);
                                                    let note_bg = if dm { egui::Color32::from_rgb(28, 24, 48) } else { egui::Color32::from_rgb(242, 240, 255) };
                                                    let note_stroke = egui::Color32::from_rgb(99, 111, 245);
                                                    egui::Frame::none()
                                                        .fill(note_bg)
                                                        .rounding(8.0)
                                                        .inner_margin(egui::Margin::symmetric(12.0, 10.0))
                                                        .stroke(egui::Stroke::new(1.0, note_stroke))
                                                        .show(ui, |ui| {
                                                            ui.set_min_width(ui.available_width());
                                                            ui.horizontal(|ui| {
                                                                ui.label(egui::RichText::new("🔄").size(13.0));
                                                                ui.add_space(6.0);
                                                                ui.vertical(|ui| {
                                                                    ui.label(egui::RichText::new("Restart required to apply theme changes.")
                                                                        .size(12.0)
                                                                        .strong()
                                                                        .color(if dm { egui::Color32::from_rgb(190, 190, 240) } else { egui::Color32::from_rgb(60, 60, 160) }));
                                                                    ui.add_space(2.0);
                                                                    ui.label(egui::RichText::new("The app may display inconsistently until restarted.")
                                                                        .size(11.0)
                                                                        .color(if dm { egui::Color32::from_rgb(145, 145, 185) } else { egui::Color32::from_rgb(110, 110, 160) }));
                                                                });
                                                            });
                                                            ui.add_space(8.0);
                                                            let restart_btn = egui::Button::new(
                                                                egui::RichText::new("Restart Now").size(12.0).color(egui::Color32::WHITE)
                                                            )
                                                            .fill(egui::Color32::from_rgb(99, 111, 245))
                                                            .rounding(7.0)
                                                            .min_size(egui::vec2(110.0, 30.0));
                                                            if ui.add(restart_btn).clicked() {
                                                                // Save settings first, then re-launch the current executable
                                                                save_settings(&self.to_settings());
                                                                if let Ok(exe) = std::env::current_exe() {
                                                                    let _ = std::process::Command::new(exe).spawn();
                                                                }
                                                                std::process::exit(0);
                                                            }
                                                        });
                                                    ui.add_space(4.0);
                                                }

                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Compact View
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Compact View").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Tighter spacing between entries").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_compact", self.compact_view, accent) {
                                                            self.compact_view = !self.compact_view;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });
                                            }

                                            // ── Tab 1: Security ───────────────────────────
                                            1 => {
                                                ui.label(egui::RichText::new("Security").size(13.0).strong().color(c_title));
                                                ui.add_space(14.0);

                                                // Row: Show Passwords
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Show Passwords").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Reveal passwords in the entry list").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_show_pw", self.show_passwords, accent) {
                                                            self.show_passwords = !self.show_passwords;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });
                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Auto-Lock
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Auto-Lock").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Lock vault after inactivity").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_autolock", self.auto_lock_enabled, accent) {
                                                            self.auto_lock_enabled = !self.auto_lock_enabled;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });

                                                if self.auto_lock_enabled {
                                                    ui.add_space(8.0);
                                                    ui.horizontal(|ui| {
                                                        ui.add_space(4.0);
                                                        ui.label(egui::RichText::new("Lock after").size(12.0).color(c_sub));
                                                        ui.add_space(8.0);
                                                        let mut mins = self.auto_lock_timeout_mins as f32;
                                                        let slider = egui::Slider::new(&mut mins, 1.0..=60.0).suffix(" min").show_value(true).integer();
                                                        if ui.add(slider).changed() {
                                                            self.auto_lock_timeout_mins = mins as u64;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                }

                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Lock on Focus Loss
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Lock on Focus Loss").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Lock when the window loses focus").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_focus_loss", self.lock_on_focus_loss, accent) {
                                                            self.lock_on_focus_loss = !self.lock_on_focus_loss;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });
                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Clipboard Timeout
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Clipboard Auto-Clear").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Clear clipboard after copying a password").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        let enabled = self.clipboard_timeout_secs.is_some();
                                                        if draw_toggle(ui, ctx, "toggle_autoclear", enabled, accent) {
                                                            self.clipboard_timeout_secs = if enabled { None } else { Some(10) };
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });

                                                if let Some(secs) = self.clipboard_timeout_secs {
                                                    ui.add_space(8.0);
                                                    ui.horizontal(|ui| {
                                                        ui.add_space(4.0);
                                                        ui.label(egui::RichText::new("Clear after").size(12.0).color(c_sub));
                                                        ui.add_space(8.0);
                                                        let mut secs_f32 = secs as f32;
                                                        let slider = egui::Slider::new(&mut secs_f32, 5.0..=120.0).suffix(" s").show_value(true).integer();
                                                        if ui.add(slider).changed() {
                                                            self.clipboard_timeout_secs = Some(secs_f32 as u64);
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                }

                                                // Change master password row (only when unlocked)
                                                if self.state == AppState::Unlocked {
                                                    row_divider(ui);
                                                    ui.add_space(12.0);
                                                    let mut open_change_pw = false;
                                                    ui.horizontal(|ui| {
                                                        ui.set_min_height(44.0);
                                                        ui.vertical(|ui| {
                                                            ui.label(egui::RichText::new("Change Master Password").size(13.0).color(c_title));
                                                            ui.label(egui::RichText::new("Re-encrypt your vault with a new password").size(11.0).color(c_sub));
                                                        });
                                                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                            let btn = egui::Button::new(
                                                                egui::RichText::new("Change →").size(12.0).color(egui::Color32::WHITE)
                                                            )
                                                            .fill(accent).rounding(8.0).min_size(egui::vec2(78.0, 28.0));
                                                            if ui.add(btn).clicked() { open_change_pw = true; }
                                                        });
                                                    });
                                                    if open_change_pw {
                                                        self.modal = Modal::ChangePassword { old: String::new(), new: String::new(), confirm: String::new() };
                                                        close_on_action = true;
                                                    }
                                                }
                                            }

                                            // ── Tab 2: Passwords ──────────────────────────
                                            2 => {
                                                ui.label(egui::RichText::new("Password Generator").size(13.0).strong().color(c_title));
                                                ui.add_space(14.0);

                                                // Row: Default Length
                                                ui.vertical(|ui| {
                                                    ui.label(egui::RichText::new("Default Length").size(13.0).color(c_title));
                                                    ui.label(egui::RichText::new("Pre-fill length when generating passwords").size(11.0).color(c_sub));
                                                    ui.add_space(10.0);
                                                    let mut len = self.default_password_length as f32;
                                                    let slider = egui::Slider::new(&mut len, 8.0..=64.0).suffix(" chars").show_value(true).integer();
                                                    if ui.add(slider).changed() {
                                                        self.default_password_length = len as u32;
                                                        save_settings(&self.to_settings());
                                                    }
                                                });
                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Uppercase
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Uppercase Letters").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Include A–Z in generated passwords").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_gen_upper", self.gen_use_uppercase, accent) {
                                                            self.gen_use_uppercase = !self.gen_use_uppercase;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });
                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Numbers
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Numbers").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Include 0–9 in generated passwords").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_gen_nums", self.gen_use_numbers, accent) {
                                                            self.gen_use_numbers = !self.gen_use_numbers;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });
                                                row_divider(ui);
                                                ui.add_space(12.0);

                                                // Row: Symbols
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("Symbols").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Include special characters (!@#…)").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        if draw_toggle(ui, ctx, "toggle_gen_syms", self.gen_use_symbols, accent) {
                                                            self.gen_use_symbols = !self.gen_use_symbols;
                                                            save_settings(&self.to_settings());
                                                        }
                                                    });
                                                });
                                            }

                                            // ── Tab 3: Performance ────────────────────────
                                            _ => {
                                                ui.label(egui::RichText::new("Performance").size(13.0).strong().color(c_title));
                                                ui.add_space(14.0);

                                                // Row: VSync
                                                ui.horizontal(|ui| {
                                                    ui.set_min_height(44.0);
                                                    ui.vertical(|ui| {
                                                        ui.label(egui::RichText::new("VSync").size(13.0).color(c_title));
                                                        ui.label(egui::RichText::new("Sync frame rate with display — restart required").size(11.0).color(c_sub));
                                                    });
                                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                        let was = self.vsync_enabled;
                                                        if draw_toggle(ui, ctx, "toggle_vsync", self.vsync_enabled, accent) {
                                                            self.vsync_enabled = !self.vsync_enabled;
                                                        }
                                                        if was != self.vsync_enabled {
                                                            save_settings(&self.to_settings()); *vsync_changed = true;
                                                        }
                                                    });
                                                });

                                                if *vsync_changed {
                                                    ui.add_space(10.0);
                                                    let note_bg = if dm { egui::Color32::from_rgb(38, 32, 14) } else { egui::Color32::from_rgb(255, 249, 230) };
                                                    let note_stroke = egui::Color32::from_rgb(160, 110, 20);
                                                    egui::Frame::none()
                                                        .fill(note_bg)
                                                        .rounding(8.0)
                                                        .inner_margin(egui::Margin::symmetric(12.0, 9.0))
                                                        .stroke(egui::Stroke::new(1.0, note_stroke))
                                                        .show(ui, |ui| {
                                                            ui.set_min_width(ui.available_width());
                                                            ui.horizontal(|ui| {
                                                                ui.label(egui::RichText::new("ℹ️").size(13.0));
                                                                ui.add_space(6.0);
                                                                ui.vertical(|ui| {
                                                                    ui.label(egui::RichText::new("Restart required to apply this change.").size(12.0)
                                                                        .color(if dm { egui::Color32::from_rgb(230, 170, 55) } else { egui::Color32::from_rgb(120, 80, 5) }));
                                                                    ui.add_space(2.0);
                                                                    ui.label(egui::RichText::new("The app may display inconsistently until restarted.")
                                                                        .size(11.0)
                                                                        .color(if dm { egui::Color32::from_rgb(185, 145, 60) } else { egui::Color32::from_rgb(160, 110, 20) }));
                                                                });
                                                            });
                                                            ui.add_space(8.0);
                                                            let restart_btn = egui::Button::new(
                                                                egui::RichText::new("Restart Now").size(12.0).color(egui::Color32::WHITE)
                                                            )
                                                            .fill(egui::Color32::from_rgb(160, 110, 20))
                                                            .rounding(7.0)
                                                            .min_size(egui::vec2(110.0, 30.0));
                                                            if ui.add(restart_btn).clicked() {
                                                                save_settings(&self.to_settings());
                                                                if let Ok(exe) = std::env::current_exe() {
                                                                    let _ = std::process::Command::new(exe).spawn();
                                                                }
                                                                std::process::exit(0);
                                                            }
                                                        });
                                                }
                                            }
                                        }

                                        ui.add_space(8.0);
                                    }); // ScrollArea

                                    // ── Done button — always visible, outside scroll area ──
                                    let c_done_sep = if dm { egui::Color32::from_rgb(38, 42, 58) } else { egui::Color32::from_rgb(225, 225, 242) };
                                    ui.painter().hline(
                                        ui.available_rect_before_wrap().x_range(),
                                        ui.cursor().top(),
                                        egui::Stroke::new(1.0, c_done_sep),
                                    );
                                    ui.add_space(12.0);
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        let done_btn = egui::Button::new(
                                            egui::RichText::new("Done").size(13.0).strong().color(egui::Color32::WHITE)
                                        )
                                        .fill(accent)
                                        .rounding(9.0)
                                        .min_size(egui::vec2(88.0, 36.0));
                                        if ui.add(done_btn).clicked() { close_on_action = true; }
                                    });
                                    ui.add_space(4.0);
                                }); // Frame (content panel)
                                }, // allocate_ui_with_layout (content)
                            ); // allocate_ui_with_layout close
                        }); // ui.horizontal
                    }); // Window
            }
        }

        if close_on_action { modal_is_open = false; }
        if modal_is_open { self.modal = current_modal; }
    }
}

impl App for VaultGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut Frame) {
        // Custom theme based on dark_mode setting v1
        let mut style = (*ctx.style()).clone();
        
        if self.dark_mode {
            // Dark theme — blue-slate base, not flat grey
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
            // Light theme — clean white/warm-grey, crisp typography
            style.visuals.dark_mode = false;
            style.visuals.window_fill                         = egui::Color32::from_rgb(252, 252, 254);
            style.visuals.panel_fill                          = egui::Color32::from_rgb(248, 248, 252);
            style.visuals.extreme_bg_color                    = egui::Color32::from_rgb(240, 240, 248);
            // Widget fills — neutral greys, not blue-tinted
            style.visuals.widgets.noninteractive.bg_fill      = egui::Color32::from_rgb(232, 232, 238);
            style.visuals.widgets.noninteractive.weak_bg_fill = egui::Color32::from_rgb(242, 242, 246);
            style.visuals.widgets.inactive.bg_fill            = egui::Color32::from_rgb(225, 225, 232);
            style.visuals.widgets.inactive.weak_bg_fill       = egui::Color32::from_rgb(238, 238, 244);
            style.visuals.widgets.hovered.bg_fill             = egui::Color32::from_rgb(210, 212, 230);
            style.visuals.widgets.hovered.weak_bg_fill        = egui::Color32::from_rgb(228, 228, 242);
            style.visuals.widgets.active.bg_fill              = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.widgets.active.weak_bg_fill         = egui::Color32::from_rgb(88, 101, 242);
            style.visuals.selection.bg_fill                   = egui::Color32::from_rgba_unmultiplied(88, 101, 242, 40);
            style.visuals.selection.stroke                    = egui::Stroke::new(1.0, egui::Color32::from_rgb(88, 101, 242));
            // Text — near-black for readability
            style.visuals.override_text_color                 = Some(egui::Color32::from_rgb(16, 16, 28));
            // Strokes — soft grey, not purple-blue
            style.visuals.window_stroke                       = egui::Stroke::new(1.0, egui::Color32::from_rgb(218, 218, 228));
            style.visuals.widgets.noninteractive.fg_stroke    = egui::Stroke::new(1.0, egui::Color32::from_rgb(100, 100, 115));
            style.visuals.widgets.inactive.fg_stroke          = egui::Stroke::new(1.0, egui::Color32::from_rgb(80, 80, 100));
            style.visuals.widgets.hovered.fg_stroke           = egui::Stroke::new(1.5, egui::Color32::from_rgb(30, 30, 50));
            style.visuals.widgets.active.fg_stroke            = egui::Stroke::new(2.0, egui::Color32::WHITE);
            // Borders on inactive widgets — subtle
            style.visuals.widgets.noninteractive.bg_stroke    = egui::Stroke::new(1.0, egui::Color32::from_rgb(210, 210, 222));
            style.visuals.widgets.inactive.bg_stroke          = egui::Stroke::new(1.0, egui::Color32::from_rgb(205, 205, 218));
            style.visuals.widgets.hovered.bg_stroke           = egui::Stroke::new(1.5, egui::Color32::from_rgb(160, 168, 210));
            style.visuals.widgets.active.bg_stroke            = egui::Stroke::new(0.0, egui::Color32::TRANSPARENT);
            style.visuals.hyperlink_color                     = egui::Color32::from_rgb(88, 101, 242);
            // Rounding — consistent with dark mode
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
        
        self.clear_clipboard_if_needed();

        // Track user activity for auto-lock
        if ctx.input(|i| i.pointer.any_down() || !i.keys_down.is_empty()) {
            self.last_activity = Instant::now();
        }

        // --- Security Features ---
        if self.state == AppState::Unlocked {
            // Feature: Auto-lock after inactivity
            if self.auto_lock_enabled {
                let timeout = Duration::from_secs(self.auto_lock_timeout_mins * 60);
                if self.last_activity.elapsed() >= timeout {
                    self.lock_vault();
                    self.push_toast("Vault auto-locked due to inactivity.".to_string(), ToastKind::Info);
                }
            }
            
            // Feature: Lock on focus loss
            if self.lock_on_focus_loss && !ctx.input(|i| i.focused) {
                self.lock_vault();
                self.push_toast("Vault auto-locked due to focus loss.".to_string(), ToastKind::Info);
            }
        }

        ctx.request_repaint_after(Duration::from_millis(100));

        egui::CentralPanel::default().show(ctx, |ui| {
            // Top navigation bar
            let nav_bg = if self.dark_mode { egui::Color32::from_rgb(14, 15, 22) } else { egui::Color32::from_rgb(252, 252, 254) };
            let nav_frame = egui::Frame::none()
                .fill(nav_bg)
                .inner_margin(egui::Margin { left: 20.0, right: 20.0, top: 12.0, bottom: 12.0 });
                
            nav_frame.show(ui, |ui| {
                ui.horizontal(|ui| {
                    let title_color = if self.dark_mode { egui::Color32::WHITE } else { egui::Color32::from_rgb(20, 20, 35) };
                    let accent = egui::Color32::from_rgb(88, 101, 242);
                    // Shield icon in accent color, name in primary text color
                    ui.label(egui::RichText::new("🛡️").size(18.0).color(accent));
                    ui.add_space(4.0);
                    ui.label(egui::RichText::new("Aegis").size(17.0).strong().color(title_color));
                    
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if self.state == AppState::KnownBugs {
                            let back_button = egui::Button::new(
                                egui::RichText::new("← Back")
                                    .size(13.0)
                                    .color(if self.dark_mode { egui::Color32::from_rgb(215, 215, 232) } else { egui::Color32::from_rgb(50, 50, 72) })
                            )
                            .fill(egui::Color32::TRANSPARENT)
                            .stroke(egui::Stroke::new(1.0, if self.dark_mode { egui::Color32::from_rgb(95, 100, 128) } else { egui::Color32::from_rgb(195, 195, 215) }))
                            .rounding(8.0)
                            .min_size(egui::vec2(80.0, 30.0));
                            
                            if ui.add(back_button).clicked() {
                                self.info_page_opened = None;
                                self.view_opened = Some(Instant::now());
                                self.state = if self.vault_path.exists() { AppState::Locked } else { AppState::NoVault };
                                if !self.master_password.is_empty() && !self.vault.entries.is_empty() { 
                                    self.state = AppState::Unlocked; 
                                }
                            }
                        } else if self.state != AppState::Unlocking(Instant::now()) && self.state != AppState::CreatingVault(Instant::now()) {
                            // Animate a gentle breathing glow on the Info button
                            let pulse = (ui.input(|i| i.time) * 2.0).sin() as f32 * 0.5 + 0.5;
                            let btn_stroke_alpha = (80.0 + pulse * 80.0) as u8;
                            let btn_stroke_color = if self.dark_mode {
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, btn_stroke_alpha)
                            } else {
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, btn_stroke_alpha)
                            };
                            let btn_fill = if self.dark_mode {
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, (pulse * 18.0) as u8)
                            } else {
                                egui::Color32::from_rgba_unmultiplied(99, 111, 245, (pulse * 12.0) as u8)
                            };
                            let issues_button = egui::Button::new(
                                egui::RichText::new("ℹ️  Info")
                                    .size(12.0)
                                    .color(if self.dark_mode { egui::Color32::from_rgb(210, 210, 230) } else { egui::Color32::from_rgb(60, 60, 80) })
                            )
                            .fill(btn_fill)
                            .stroke(egui::Stroke::new(1.0, btn_stroke_color))
                            .rounding(8.0)
                            .min_size(egui::vec2(80.0, 30.0));
                            
                            if ui.add(issues_button).clicked() {
                                self.info_page_opened = Some(Instant::now());
                                self.state = AppState::KnownBugs;
                            }
                            ui.ctx().request_repaint();
                        }
                    });
                });
            });
            
            // Thin accent separator under the nav bar May
            let sep_color = if self.dark_mode { egui::Color32::from_rgb(50, 55, 75) } else { egui::Color32::from_rgb(218, 218, 228) };
            ui.painter().hline(
                ui.available_rect_before_wrap().x_range(),
                ui.cursor().top(),
                egui::Stroke::new(1.0, sep_color),
            );
            
            ui.add_space(20.0);

            // Main content area prevents 
            match self.state {
                AppState::Locked => self.draw_locked_view(ui, ctx),
                AppState::Unlocking(start) => self.draw_loading_view(ui, start, "Unlocking vault...", "Deriving encryption key, please wait."),
                AppState::Unlocked => self.draw_unlocked_view(ui),
                AppState::NoVault => self.draw_no_vault_view(ui),
                AppState::CreatingVault(start) => self.draw_loading_view(ui, start, "Creating vault...", "This may take a moment."),
                AppState::KnownBugs => self.draw_known_bugs_view(ui),
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
    let vault_path = default_vault_path()?;
    let settings = load_settings();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 800.0])
            .with_min_inner_size([600.0, 500.0]),
        vsync: settings.vsync_enabled,
        ..Default::default()
    };
    
    eframe::run_native(
        "Aegis Release",
        options,
        Box::new(move |cc| {
            load_fonts(&cc.egui_ctx);
            Ok(Box::new(VaultGui::new(vault_path, settings)))
        }),
    ).map_err(|e| e.into())
}
// 2026