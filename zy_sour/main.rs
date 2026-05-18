#![windows_subsystem = "windows"]
use arboard::Clipboard;
use enigo::*;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash,
        PasswordHasher,
        PasswordVerifier,
        SaltString,
    },
    Argon2,
    Algorithm,
    Params,
    Version,
};

use eframe::egui;
use eframe::icon_data::from_png_bytes;
use egui::{FontData, FontDefinitions, FontFamily};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use aes_gcm::{Aes256Gcm, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use hex;
use zeroize::Zeroize;
use std::thread;
use std::time::Duration;

const VAULT_FILE: &str = "vault.json";
const SESSION_TIMEOUT_SECS: u64 = 600;
const CLIPBOARD_CLEAR_SECS: u64 = 60;

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    platform: String,
    account: String,
    encrypted_password: String,
}

#[derive(Serialize, Deserialize)]
struct VaultData {
    master_hash_93: String,
    salt: String,
    entries: Vec<Entry>,
    first_setup: bool,
}

struct VaultApp {
    input: String,
    message: String,
    unlocked: bool,
    entries: Vec<Entry>,

    new_platform: String,
    new_account: String,
    new_password: String,
    change_password: String,
    confirm_password: String,

    data: VaultData,
    encryption_key: Option<Vec<u8>>,
    last_activity: u64,

    in_setup: bool,
    setup_password: String,
    setup_confirm: String,
    failed_attempts: u32,
    lock_until: u64,
    current_lock_minutes: u64,
    
    clipboard_clear_time: Option<u64>,
}

fn get_current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn get_argon2_strong() -> Argon2<'static> {
    // Option 2: Strong config (1-2 giây)
    let params = Params::new(
        262144, // m_cost: 256 MiB memory
        4,      // t_cost: 4 iterations
        2,      // p_cost: 2 parallelism (multi-core)
        None
    ).expect("Invalid argon2 params");

    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
    )
}

fn derive_encryption_key(
    master_password: &str,
    salt: &str,
) -> Vec<u8> {
    let mut output_key = [0u8; 32];

    get_argon2_strong()
        .hash_password_into(
            master_password.as_bytes(),
            salt.as_bytes(),
            &mut output_key,
        )
        .expect("derive key failed");

    output_key.to_vec()
}

fn encrypt_password(password: &str, key: &[u8]) -> Result<String, String> {
    if key.len() < 32 {
        return Err("Khóa mã hóa không hợp lệ".to_string());
    }

    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes);

    let cipher_key = <[u8; 32]>::try_from(&key[..32]).unwrap();
    let cipher = Aes256Gcm::new(&cipher_key.into());
    let nonce = Nonce::from_slice(&nonce_bytes);

    match cipher.encrypt(nonce, password.as_bytes().as_ref()) {
        Ok(ciphertext) => {
            let mut result = nonce_bytes.to_vec();
            result.extend_from_slice(&ciphertext);
            Ok(hex::encode(result))
        }
        Err(_) => Err("Lỗi mã hóa mật khẩu".to_string()),
    }
}

fn decrypt_password(encrypted: &str, key: &[u8]) -> Result<String, String> {
    if key.len() < 32 {
        return Err("Khóa mã hóa không hợp lệ".to_string());
    }

    let data = hex::decode(encrypted)
        .map_err(|_| "Dữ liệu mã hóa không hợp lệ".to_string())?;

    if data.len() < 12 {
        return Err("Dữ liệu mã hóa bị hỏng".to_string());
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher_key = <[u8; 32]>::try_from(&key[..32]).unwrap();
    let cipher = Aes256Gcm::new(&cipher_key.into());

    cipher.decrypt(nonce, ciphertext.as_ref())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| "Giải mã thất bại".to_string())
}

fn create_hash(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);

    get_argon2_strong()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| "Lỗi tạo hash".to_string())
}

fn verify(hash: &str, password: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => {
            get_argon2_strong()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        }
        Err(_) => false,
    }
}

fn paste_text(text: String) -> Result<(), String> {
    let mut clipboard = Clipboard::new()
        .map_err(|_| "Lỗi truy cập clipboard".to_string())?;

    clipboard
        .set_text(text.clone())
        .map_err(|_| "Lỗi sao chép".to_string())?;

    thread::sleep(Duration::from_millis(100));

    let mut enigo = Enigo::new();
    enigo.key_down(enigo::Key::Control);
    enigo.key_click(enigo::Key::Layout('v'));
    enigo.key_up(enigo::Key::Control);

    // Clear clipboard after 60 seconds
    thread::spawn(|| {
        thread::sleep(Duration::from_secs(CLIPBOARD_CLEAR_SECS));
        if let Ok(mut clipboard) = Clipboard::new() {
            let _ = clipboard.set_text("".to_string());
        }
    });

    Ok(())
}

fn save(data: &VaultData) -> Result<(), String> {

    use rand::seq::SliceRandom;
    use rand::Rng;

    let entries_json = serde_json::to_string_pretty(
        &data.entries
    ).map_err(|_| "Lỗi JSON".to_string())?;

    let mut rng = rand::thread_rng();

    let mut hash_lines: Vec<String> = vec![];

    let mut current_p: u8 =
        rng.gen_range(b'a'..=b'z');

    let parts: Vec<&str> =
        data.master_hash_93.split('$').collect();

    let salt_part = parts[4];
    let hash_part = parts[5];

    for i in 1..=100 {

        if i == 93 {
            continue;
        }

        let fake_p =
            current_p as char;

        current_p += 1;

        if current_p > b'z' {
            current_p = b'a';
        }

        let mut shifted_salt = String::new();

        for c in salt_part.chars() {

            let new_c = match c {

                'a'..='z' => {
                    let letters =
                        b"abcdefghijklmnopqrstuvwxyz";

                    letters[
                        rng.gen_range(0..letters.len())
                    ] as char
                }

                'A'..='Z' => {
                    let letters =
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

                    letters[
                        rng.gen_range(0..letters.len())
                    ] as char
                }

                '0'..='9' => {
                    let numbers =
                        b"0123456789";

                    numbers[
                        rng.gen_range(0..numbers.len())
                    ] as char
                }

                '$' | '+' | '/' | '=' => {
                    let symbols =
                        ['&', '!', '*', '-', '#', '_'];

                    symbols[
                        rng.gen_range(0..symbols.len())
                    ]
                }

                _ => c,
            };

            shifted_salt.push(new_c);
        }

        let mut shifted_hash = String::new();

        for c in hash_part.chars() {

            let new_c = match c {

                'a'..='z' => {
                    let letters =
                        b"abcdefghijklmnopqrstuvwxyz";

                    letters[
                        rng.gen_range(0..letters.len())
                    ] as char
                }

                'A'..='Z' => {
                    let letters =
                        b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

                    letters[
                        rng.gen_range(0..letters.len())
                    ] as char
                }

                '0'..='9' => {
                    let numbers =
                        b"0123456789";

                    numbers[
                        rng.gen_range(0..numbers.len())
                    ] as char
                }

                '$' | '+' | '/' | '=' => {
                    let symbols =
                        ['&', '!', '*', '-', '#', '_'];

                    symbols[
                        rng.gen_range(0..symbols.len())
                    ]
                }

                _ => {
                    let all =
                        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

                    all[
                        rng.gen_range(0..all.len())
                    ] as char
                }
            };

            shifted_hash.push(new_c);
        }

        let fake_hash = format!(
            "$argon2id$v=19$m=262144,t=4,p={}${}${}",
            fake_p,
            shifted_salt,
            shifted_hash
        );

        hash_lines.push(format!(
            r#""master_hash_{}": "{}""#,
            i,
            fake_hash
        ));
    }

    hash_lines.push(format!(
        r#""master_hash_93": "{}""#,
        data.master_hash_93
    ));

    hash_lines.shuffle(&mut rng);

    let hashes_block =
        hash_lines.join(",\n  ");

    let json = format!(
r#"{{
  {},

  "salt": "{}",

  "entries": {},

  "first_setup": {}
}}"#,
        hashes_block,
        data.salt,
        entries_json,
        data.first_setup
    );

    fs::write(VAULT_FILE, json)
        .map_err(|_| "Lỗi lưu file".to_string())
}

fn load() -> Result<VaultData, String> {
    match fs::read_to_string(VAULT_FILE) {
        Ok(content) => {
            serde_json::from_str(&content)
                .map_err(|_| "Lỗi đọc file".to_string())
        }
        Err(_) => {
            Ok(VaultData {
                master_hash_93: String::new(),
                salt: hex::encode(
                    (0..16)
                        .map(|_| rand::random::<u8>())
                        .collect::<Vec<_>>()
                ),
                entries: vec![],
                first_setup: true,
            })
        }
    }
}

impl Default for VaultApp {
    fn default() -> Self {
        let data = load().unwrap_or_else(|_| {
            VaultData {
                master_hash_93: String::new(),
                salt: hex::encode(
                    (0..16)
                        .map(|_| rand::random::<u8>())
                        .collect::<Vec<_>>()
                ),
                entries: vec![],
                first_setup: true,
            }
        });

        let in_setup = data.first_setup;

        Self {
            input: String::new(),
            message: String::new(),
            unlocked: false,
            entries: vec![],
            new_platform: String::new(),
            new_account: String::new(),
            new_password: String::new(),
            change_password: String::new(),
            confirm_password: String::new(),
            data,
            encryption_key: None,
            last_activity: get_current_time(),
            in_setup,
            setup_password: String::new(),
            setup_confirm: String::new(),
            failed_attempts: 0,
            lock_until: 0,
            current_lock_minutes: 5,
            clipboard_clear_time: None,
        }
    }
}

impl eframe::App for VaultApp {
    fn update(
        &mut self,
        ctx: &egui::Context,
        _: &mut eframe::Frame,
    ) {
        if self.unlocked {
            let now = get_current_time();

            if now - self.last_activity > SESSION_TIMEOUT_SECS {
                self.unlocked = false;
                
                if let Some(mut key) = self.encryption_key.take() {
                    key.zeroize();
                }
                
                self.entries.clear();
                self.message =
                    "⏱️ Session hết hạn".to_string();
            }
        }

        ctx.input(|i| {
            if i.pointer.any_down() {
                self.last_activity = get_current_time();
            }
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);

                ui.heading("🔒 xz pass");

                ui.add_space(20.0);

                if self.in_setup {
                    self.render_setup_screen(ui);
                } else if !self.unlocked {
                    self.render_unlock_screen(ui);
                } else {
                    self.render_main_screen(ui);
                }
            });
        });

        ctx.request_repaint_after(
            std::time::Duration::from_secs(1)
        );
    }
}

impl VaultApp {
    fn render_setup_screen(&mut self, ui: &mut egui::Ui) {
        ui.label("🆕 Thiết lập lần đầu");

        ui.add_space(15.0);

        ui.add_sized(
            [300.0, 40.0],
            egui::TextEdit::singleline(
                &mut self.setup_password
            )
            .password(true)
            .hint_text("Mật khẩu chính"),
        );

        ui.add_space(10.0);

        ui.add_sized(
            [300.0, 40.0],
            egui::TextEdit::singleline(
                &mut self.setup_confirm
            )
            .password(true)
            .hint_text("Xác nhận mật khẩu"),
        );

        ui.add_space(15.0);

        if ui.button("Tạo Vault").clicked() {
            if self.setup_password.len() < 6 {
                self.message =
                    "❌ Mật khẩu tối thiểu 6 ký tự"
                        .to_string();
            } else if self.setup_password
                != self.setup_confirm
            {
                self.message =
                    "❌ Mật khẩu không khớp"
                        .to_string();
            } else {
                match create_hash(
                    &self.setup_password
                ) {
                    Ok(hash) => {
                        self.data.master_hash_93 = hash;
                        self.data.first_setup = false;

                        if let Err(e) =
                            save(&self.data)
                        {
                            self.message =
                                format!("❌ {}", e);
                        } else {
                            self.message =
                                "✅ Đã tạo vault"
                                    .to_string();

                            self.in_setup = false;
                        }
                    }
                    Err(e) => {
                        self.message =
                            format!("❌ {}", e);
                    }
                }
                
                self.setup_password.zeroize();
                self.setup_confirm.zeroize();
            }
        }

        ui.label(&self.message);
    }

    fn render_unlock_screen(
        &mut self,
        ui: &mut egui::Ui,
    ) {
        let now = get_current_time();

        if now < self.lock_until {
            let remain = self.lock_until - now;

            ui.label(format!(
                "⛔ Đang bị khóa. Chờ {} phút {} giây",
                remain / 60,
                remain % 60
            ));

            ui.label(&self.message);
            return;
        }

        ui.label("Nhập mật khẩu chính");

        ui.add_space(15.0);

        ui.add_sized(
            [300.0, 40.0],
            egui::TextEdit::singleline(
                &mut self.input
            )
            .password(true)
            .hint_text("Mật khẩu"),
        );

        ui.add_space(10.0);

        if ui.button("Mở khóa").clicked() {
            if verify(
                &self.data.master_hash_93,
                &self.input,
            ) {
                let key = derive_encryption_key(
                    &self.input,
                    &self.data.salt,
                );

                self.encryption_key = Some(key);
                self.unlocked = true;
                self.entries =
                    self.data.entries.clone();

                self.message =
                    "✅ Đã mở khóa".to_string();

                self.failed_attempts = 0;
                self.current_lock_minutes = 5;
            } else {
                self.failed_attempts += 1;

                if self.failed_attempts >= 5 {
                    let minutes =
                        self.current_lock_minutes
                            * self.current_lock_minutes;

                    self.lock_until =
                        get_current_time()
                            + (minutes * 60);

                    self.message = format!(
                        "⛔ Sai 5 lần. Khóa {} phút",
                        minutes
                    );

                    self.failed_attempts = 0;

                    self.current_lock_minutes =
                        minutes;
                } else {
                    self.message = format!(
                        "❌ Sai mật khẩu ({}/5)",
                        self.failed_attempts
                    );
                }
            }

            self.input.zeroize();
        }

        ui.label(&self.message);
    }

    fn render_main_screen(
        &mut self,
        ui: &mut egui::Ui,
    ) {
        ui.heading("Danh sách mật khẩu");

        ui.separator();

        ui.label("➕ Thêm tài khoản");

        ui.add_sized(
            [300.0, 35.0],
            egui::TextEdit::singleline(
                &mut self.new_platform
            )
            .hint_text("Nền tảng"),
        );

        ui.add_sized(
            [300.0, 35.0],
            egui::TextEdit::singleline(
                &mut self.new_account
            )
            .hint_text("Tài khoản"),
        );

        ui.add_sized(
            [300.0, 35.0],
            egui::TextEdit::singleline(
                &mut self.new_password
            )
            .password(true)
            .hint_text("Mật khẩu"),
        );

        if ui.button("Thêm").clicked() {
            if let Some(key) = &self.encryption_key {
                match encrypt_password(
                    &self.new_password,
                    key,
                ) {
                    Ok(encrypted) => {
                        let entry = Entry {
                            platform:
                                self.new_platform.clone(),
                            account:
                                self.new_account.clone(),
                            encrypted_password:
                                encrypted,
                        };

                        self.entries.push(
                            entry.clone(),
                        );

                        self.data.entries.push(
                            entry,
                        );

                        let _ = save(&self.data);

                        self.message =
                            "✅ Đã thêm"
                                .to_string();

                        self.new_platform.clear();
                        self.new_account.clear();
                        
                        self.new_password.zeroize();
                    }
                    Err(e) => {
                        self.message =
                            format!("❌ {}", e);
                    }
                }
            }
        }

        ui.separator();

        egui::ScrollArea::vertical()
            .max_height(250.0)
            .show(ui, |ui| {
                let mut remove_index = None;

                for (i, entry)
                    in self.entries.iter().enumerate()
                {
                    ui.horizontal(|ui| {
                        ui.label(format!(
                            "📱 {}",
                            entry.platform
                        ));

                        if ui.button("👤 Copy").clicked()
                        {
                            let mut clipboard =
                                Clipboard::new()
                                    .unwrap();

                            let _ = clipboard.set_text(
                                entry.account.clone(),
                            );

                            self.message =
                                "✅ Đã copy"
                                    .to_string();
                        }

                        if ui.button("🔑 Paste").clicked()
                        {
                            if let Some(key) =
                                &self.encryption_key
                            {
                                if let Ok(password) =
                                    decrypt_password(
                                        &entry
                                            .encrypted_password,
                                        key,
                                    )
                                {
                                    let _ =
                                        paste_text(
                                            password,
                                        );

                                    self.message =
                                        "✅ Đã paste"
                                            .to_string();
                                }
                            }
                        }

                        if ui.button("🗑️ Xóa").clicked()
                        {
                            remove_index = Some(i);
                        }
                    });
                }

                if let Some(i) = remove_index {
                    self.entries.remove(i);
                    self.data.entries.remove(i);

                    let _ = save(&self.data);
                }
            });

        ui.separator();

        ui.label("🔐 Đổi mật khẩu chính");

        ui.add_sized(
            [220.0, 35.0],
            egui::TextEdit::singleline(
                &mut self.change_password
            )
            .password(true)
            .hint_text("Mật khẩu mới"),
        );

        ui.add_sized(
            [220.0, 35.0],
            egui::TextEdit::singleline(
                &mut self.confirm_password
            )
            .password(true)
            .hint_text("Xác nhận"),
        );

        if ui.button("Cập nhật mật khẩu").clicked() {
            if self.change_password
                != self.confirm_password
            {
                self.message =
                    "❌ Mật khẩu không khớp"
                        .to_string();

                return;
            }

            if let Some(old_key) =
                &self.encryption_key
            {
                let new_key =
                    derive_encryption_key(
                        &self.change_password,
                        &self.data.salt,
                    );

                let mut new_entries = vec![];

                for entry in &self.data.entries {
                    match decrypt_password(
                        &entry.encrypted_password,
                        old_key,
                    ) {
                        Ok(password) => {
                            match encrypt_password(
                                &password,
                                &new_key,
                            ) {
                                Ok(new_encrypted) => {
                                    new_entries.push(
                                        Entry {
                                            platform:
                                                entry
                                                    .platform
                                                    .clone(),
                                            account:
                                                entry
                                                    .account
                                                    .clone(),
                                            encrypted_password:
                                                new_encrypted,
                                        },
                                    );
                                }

                                Err(e) => {
                                    self.message =
                                        format!(
                                            "❌ {}",
                                            e
                                        );

                                    return;
                                }
                            }
                        }

                        Err(e) => {
                            self.message =
                                format!(
                                    "❌ {}",
                                    e
                                );

                            return;
                        }
                    }
                }

                match create_hash(
                    &self.change_password
                ) {
                    Ok(new_hash) => {
                        self.data.master_hash_93 =
                            new_hash;

                        self.data.entries =
                            new_entries.clone();

                        self.entries =
                            new_entries;

                        let mut old_key_copy = self.encryption_key.take().unwrap();
                        old_key_copy.zeroize();

                        self.encryption_key =
                            Some(new_key);

                        let _ = save(&self.data);

                        self.message =
                            "✅ Đã cập nhật mật khẩu"
                                .to_string();

                        self.change_password.zeroize();
                        self.confirm_password.zeroize();
                    }

                    Err(e) => {
                        self.message =
                            format!("❌ {}", e);
                    }
                }
            }
        }

        if ui.button("🔓 Đăng xuất").clicked() {
            self.unlocked = false;
            self.entries.clear();
            
            if let Some(mut key) = self.encryption_key.take() {
                key.zeroize();
            }
        }

        ui.label(&self.message);
    }
}

fn main() {
    let icon = from_png_bytes(
        include_bytes!("../icon.png")
    ).unwrap();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_icon(icon),
        ..Default::default()
    };

    let _ = eframe::run_native(
        "xz pass",
        options,
        Box::new(|cc| {

            let mut fonts = FontDefinitions::default();

            fonts.font_data.insert(
                "vietnamese".to_owned(),
                FontData::from_static(include_bytes!(
                    "C:/Windows/Fonts/arial.ttf"
                )),
            );

            fonts
                .families
                .entry(FontFamily::Proportional)
                .or_default()
                .insert(0, "vietnamese".to_owned());

            fonts
                .families
                .entry(FontFamily::Monospace)
                .or_default()
                .push("vietnamese".to_owned());

            cc.egui_ctx.set_fonts(fonts);

            Box::new(VaultApp::default())
        }),
    );
}
