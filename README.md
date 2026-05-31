Aegis Password Vault,
Aegis is a secure, local-first, end-to-end encrypted password manager built with Rust and egui.

Features
Security First: Uses XChaCha20-Poly1305 for authenticated encryption and Argon2id (KDF) to derive keys from your master password, ensuring your data is safe.

Local-Only: Your credentials remain on your machine; Aegis does not sync to the cloud.

Modern GUI: A polished, responsive interface built with egui, featuring:

Dark/Light mode support.

Smooth animations for a seamless user experience.

In-app toast notifications for actions.

Convenience:

Secure clipboard management (with auto-clear functionality to keep your secrets private).

Built-in password generator.

Searchable entry list.

Configurable: Adjust settings like auto-lock timeouts, clipboard clearing delays, and default password lengths to suit your workflow.

Security Architecture
The vault is stored as a single, encrypted file (vault.json.enc) in your system's application data directory. Upon startup, the app prompts for your master password, which is then passed through the Argon2id KDF to unlock the vault. The master password is zeroized from memory immediately after use.

Getting Started
Launch: Open the application.

Setup: Choose a strong master password to initialize your new, encrypted vault.

Manage: Use the intuitive interface to add, view, and copy your credentials.

Note: This application requires a valid master password to access your data. Do not lose your master password, as there is no way to recover it. It only works on Windows.

If you get a warning that the app cannot be opened, click "Run Anyways". You may need to click "more info" to see this option.
This warning is entirely harmless and only shows because the app is not signed. Signing it would cost me upwards of 300€/year.
