# ZeroPass 🛡️

[![Rust Version](https://img.shields.io/badge/rust-latest-orange.svg)](https://www.rust-lang.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Status: Beta](https://img.shields.io/badge/status-beta-yellow.svg)](https://github.com/)

**ZeroPass** is a secure, local-first password manager and vault application built with **Rust** and **egui**. It is designed to be lightweight, fast, and uncompromising on security, keeping all your sensitive data strictly on your machine.

---

## 🌟 Key Features

* **End-to-End Encryption:** Your vault is secured using `XChaCha20Poly1305`, an authenticated encryption cipher that protects both the confidentiality and integrity of your data.
* **Hardened Security:** Uses `Argon2id` for key derivation, making your master password resistant to brute-force and GPU-accelerated cracking attempts.
* **Memory Safety:** Sensitive data is automatically zeroed out (`zeroize`) from RAM as soon as it is no longer in use.
* **Clipboard Management:** Includes automated clipboard clearing to prevent sensitive passwords from lingering in your system history.
* **Cross-Platform UI:** Built with `eframe` for a native, responsive desktop experience.
* **Offline-Only:** ZeroPass performs no network calls, ensuring your data never leaves your computer.
* **Audio Feedback:** Supports embedded sound cues to confirm successful vault unlocking.

---

## 🔒 Security Architecture

ZeroPass is built on a "Zero-Knowledge" philosophy:
1. **Local-Only:** There is no cloud sync and no telemetry. Your vault file is the only record of your data.
2. **Authenticated Encryption:** We use `XChaCha20Poly1305` (Aead) to ensure that your vault file cannot be tampered with without detection.
3. **Memory Hardness:** By utilizing `Argon2id` with configurable parameters, we ensure that the time and memory cost to derive your key is high for attackers but negligible for you.

---

## 🚀 Getting Started

### Prerequisites
* [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
* [Cargo](https://doc.rust-lang.org/cargo/)

### Building from Source

**Clone the repository:**

```bash
git clone https://github.com/makke08/ZeroPass.git
cd ZeroPass
```

### Build

```bash
cargo build --release
```

### Run

```bash
cargo run --release
```

---

## 🔐 Security

ZeroPass uses:

- Argon2id for key derivation
- XChaCha20-Poly1305 authenticated encryption
- Random cryptographic salts
- Random cryptographic nonces
- Automatic memory zeroization where possible

All encryption and decryption happens locally on your machine.

No data is sent to external servers.

---

## 📂 Vault Location

Vault files are stored locally in the application's data directory.

The vault can be copied to another device as long as the master password is known.

---

## 🛣️ Roadmap

- [ ] ✓ TOTP authenticator support
- [ ] Support for Linux and Mac
- [ ] Duplicate password detection
- [ ] ✓ Categories & tags
- [ ] Windows Hello support
- [ ] ✓ Secure notes
- [ ] Encrypted backups
- [ ] ✓ Import/export support

---

## 🤝 Contributing

Pull requests, bug reports, and feature suggestions are welcome.

---

## 📜 License

GNU AFFERO GENERAL PUBLIC LICENSE

---

## ⚠️ Windows Security Warning

This app is not code-signed, so Windows Defender SmartScreen may show a warning when you run it.
This is normal for unsigned programs and doesn’t necessarily mean the file is unsafe if downloaded from this repository.

If you see a warning:
Click “More info”
Then click “Run anyway”

You can also review or build the source code yourself for full transparency.

---

Built with ❤️ in Rust.
