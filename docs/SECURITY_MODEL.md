# Security Model

As of the 1S-C1/C2/C3 checkpoints, the cryptography, vault format, persisted data model, and TOTP engine described below live in `localvault-core` (`crates/localvault-core/src/crypto`, `vault::format`, `vault::data`, `totp` — see `@docs/ARCHITECTURE.md`) rather than directly in `src-tauri`. This was an ownership/module-boundary move only: every security property on this page held before that extraction and holds unchanged after it.

## Cryptographic model

- **Master password:** never stored. Used to derive a Master Key via Argon2id.
- **Vault Key:** a fresh random 256-bit key per vault, wrapped by the Master Key.
- **Encrypted payload:** XChaCha20-Poly1305 authenticated encryption.
- **Encrypted at rest:** credentials, passwords, profile information, categories, TOTP secrets, cached site icons and related metadata where applicable.
- The frontend (React/TypeScript) performs no vault cryptography — all of it is in Rust.

## Secret lifecycle

- TOTP setup secrets are stored only inside the encrypted vault payload; the raw TOTP secret is not returned to the frontend after save.
- Generated TOTP codes are not persisted.
- Protected clipboard copy computes/copies the code in Rust, not in the frontend.
- Setup input for TOTP is kept outside React state, and the DOM value is cleared before awaiting IPC where practical.
- Frontend clears derived TOTP state when the secret view closes, selection changes, or the vault locks.
- JavaScript strings cannot be reliably zeroized, so secret lifetimes in the frontend are minimized by design; Rust-side sensitive values use zeroization where applicable (`zeroize` crate on Argon2/ChaCha20Poly1305 key material).

## Clipboard

- Protected clipboard cleanup occurs after 30 seconds.
- Windows clipboard ownership/sequence protection is used to avoid clobbering or leaking into clipboard history.
- Explicit copy actions count as user activity for inactivity-lock purposes.

## Inactivity lock

- Auto-lock after 60 seconds of inactivity.
- Passive TOTP code refresh does **not** extend the inactivity auto-lock timer (only explicit user actions like an explicit copy do).

## Browser persistence policy

None of the following are used for vault secrets or TOTP codes:
- localStorage
- sessionStorage
- IndexedDB
- cookies

Generated passwords are kept in uncontrolled DOM where practical rather than in persisted browser storage.

## Network policy

LocalVault is local-first. General vault operation has no network dependency.

**Current intentional exception:** site favicon fetching, through a narrowly hardened, explicit feature (`site_icon_fetcher.rs`). This exception must not be used as precedent to add network calls elsewhere.

**TOTP must remain fully offline** — there is no TOTP network path; generation, validation, and storage are entirely local.

## Backups

- Backups (`.lvbackup`) remain encrypted — never plaintext.
- Password rotation preserves encrypted vault payload semantics.
- External disk changes to the vault file are detected and the app fails closed rather than silently accepting divergent state.
- Concurrent sessions against the same vault are protected by OS/file locking.
- Save operations are atomic and preserve the previous authenticated encrypted backup behavior.

## TOTP (RFC 6238)

- Algorithms: SHA1, SHA256, SHA512.
- Digit lengths: 6 or 8.
- Configurable period, up to 300 seconds.
- Defaults: SHA1 / 6 digits / 30 seconds.
- Setup accepted via bare Base32 secret or `otpauth://totp/...` URI.
- HOTP is explicitly rejected (TOTP only).
- QR scanning is intentionally deferred (planned for 1W, requires camera access — a platform adapter concern, not core).

## Vault schema and TOTP compatibility

- Current schema: 2. Legacy readable schema: 1.
- Schema 1 vaults remain readable only if they contain no TOTP secret — schema 1 cannot carry a TOTP secret at all.
- Schema 2 adds support for encrypted TOTP configuration.
- Any write to a legacy schema 1 vault upgrades it to schema 2. This upgrade path must remain explicit and must never silently change compatibility guarantees (see `@CLAUDE.md` non-negotiable rules).

## Known threat-model limitations

LocalVault does **not** claim to protect against:
- malware running as the user
- keyloggers
- hostile process-memory inspection while the vault is unlocked
- OS compromise
- clipboard observation while secret material is legitimately present
- someone obtaining both an unlocked vault and the user's active session

Storing TOTP in the same encrypted vault as the password improves convenience but is not as independent as keeping the second factor in a physically/logically separate authenticator app. This tradeoff is intentional and should be disclosed to users, not "fixed" by weakening the vault or by silently duplicating the secret elsewhere.

## Mobile / sync security requirements (forward-looking, for 1S–1V)

These apply once mobile and sync work begins — they are requirements on the design, not yet implemented:

- Vault cryptography must not be duplicated or reimplemented per platform; mobile adapters call into the same core crypto as desktop (see `@docs/ARCHITECTURE.md`).
- A sync provider/server must never receive: the master password, the plaintext Vault Key, plaintext credentials, or plaintext TOTP secrets. Only encrypted vault state may leave the device.
- No naive "last writer silently overwrites everything" sync. Conflict detection and safe atomic updates are required before any sync feature ships.
- Android secure-storage integration (e.g. Android Keystore) is only for approved convenience-unlock mechanisms, not as a substitute for the vault's own encryption, and stays in the platform adapter, not the core.
- Biometric unlock and Android Autofill (1W) must be reviewed for what they expose to the OS layer before being enabled by default.
