# 🛡️ Aegis

A modern, local-first password manager built with Rust and egui.

Aegis stores your passwords in an encrypted vault secured using Argon2id and XChaCha20-Poly1305. Everything is stored locally on your device - no cloud, no accounts, no subscriptions.

---

## ✨ Features

- 🔐 Encrypted password vault
- ⚡ Fast local storage
- 🔑 Argon2id key derivation
- 🛡️ XChaCha20-Poly1305 encryption
- 📋 One-click password copying
- ⏳ Automatic clipboard clearing
- 🔍 Search entries instantly
- 🎲 Built-in password generator
- 🌙 Dark mode
- 🔒 Auto-lock support
- 🎨 Modern animated interface

---

## 📸 Screenshots

Check the "screenshots" folder
---

## 🚀 Installation

### Clone the repository

```bash
git clone https://github.com/makke08/Aegis.git
cd Aegis
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

Aegis uses:

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

  ✓ TOTP authenticator support
- [ ] Password health audit
- [ ] Duplicate password detection
- [ ] Categories & tags
- [ ] Windows Hello support
- [ ] Secure notes
- [ ] Encrypted backups
- [ ] Import/export support

---

## 🤝 Contributing

Pull requests, bug reports, and feature suggestions are welcome.

---

## 📜 License

MIT License

---

Built with ❤️ in Rust.
