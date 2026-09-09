# LocalVault

LocalVault is a local-only encrypted password manager for Windows.

The application stores password vaults locally on the user's computer and does not require a cloud account, remote server, or online synchronization.

## Version

Current release: **1.0.0**

## Features

- Local encrypted `.lvault` vaults
- Argon2id master-key derivation
- XChaCha20-Poly1305 authenticated encryption
- Random per-vault encryption key
- Password and notes storage
- Categories, favorites and search
- Cryptographically secure password generator
- Protected Windows clipboard handling
- Clipboard auto-cleanup after approximately 30 seconds
- Passwords excluded from Windows clipboard history
- Automatic vault locking after inactivity
- Encrypted `.lvbackup` backups
- Backup restoration into a new vault
- Master-password rotation
- Protection against concurrent opening of the same vault
- Detection of external vault-file changes
- No cloud storage or telemetry

## Security model

LocalVault is designed to protect vault data while it is stored on disk.

The master password is not stored by LocalVault.

Like other desktop password managers, LocalVault cannot protect secrets from malware, keyloggers, process-memory inspection, or a compromised operating system while the vault is unlocked.

Users remain responsible for securing their Windows account, device and backup files.

## Release

LocalVault 1.0.0 was validated with:

- 164 Rust tests
- strict Clippy checks with warnings denied
- production frontend build
- Rust release compilation
- manual production EXE smoke testing

## Author

**Штраус Никита Алексеевич**

## License

Copyright © 2026 Штраус Никита Алексеевич.

This project is **not open-source software**.

The source code is published for viewing and evaluation only. Use, copying, modification, redistribution, publication, sublicensing, sale, incorporation into another product, or creation of derivative works is prohibited without prior written permission from the copyright holder.

See [LICENSE](LICENSE) for the complete terms.

Third-party libraries and dependencies remain subject to their respective licenses.
