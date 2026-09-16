# Architecture

## Current architecture (as of 1S-C3)

- **Frontend:** Tauri 2 + React + TypeScript (`src/`). Performs no vault cryptography — it calls Tauri commands and renders results.
- **Shared core:** Rust, no Tauri/platform dependency (`crates/localvault-core/src/`, lib name `localvault_core`). Workspace member alongside `src-tauri`, declared in the root `Cargo.toml`.
- **Desktop/Tauri adapter:** Rust (`src-tauri/src/`, lib name `localvault_lib`), depends on `localvault-core` via a workspace path dependency.

`localvault-core` is no longer a naming placeholder for a future extraction — it is the actual package/lib name in use (`crates/localvault-core/Cargo.toml`, `[lib] name = "localvault_core"`), reconciled during 1S-C1.

Current module layout:

```
crates/localvault-core/src/
  crypto/                              # cipher, kdf, keys — intentionally private (mod, not pub mod);
                                        # only narrow types it must expose flow out through vault::format
  vault/
    data.rs                            # persisted VaultData/VaultEntry/VaultCategory/SiteIcon,
                                        # TotpConfig/TotpAlgorithm, schema validation, zeroization
    format.rs                          # VaultEnvelope: authenticated create/open/reseal/rewrap
  totp.rs                              # RFC 6238 parser + generator (bare Base32 / otpauth:// URI,
                                        # SHA1/SHA256/SHA512, caller-supplied time, no system clock)
  lib.rs

src-tauri/src/
  app_state.rs, app_state/            # in-memory session state: backups, categories, entries,
                                       # lifecycle, master_password, password_health, site_icons, totp
  commands.rs, commands/              # Tauri command handlers (glue): backups, categories,
                                       # credentials, entries, password_health, passwords,
                                       # recent_vaults, site_icons, totp
  vault/                              # backup, lifecycle, session, storage — orchestration/filesystem,
                                       # NOT the format/data model, which now live in localvault-core
  password_generator.rs
  recent_vaults.rs
  secure_clipboard.rs                 # Windows clipboard integration
  site_icon_fetcher.rs                # the one sanctioned network path (favicons)
  main.rs, lib.rs
```

Key dependencies:
- `crates/localvault-core/Cargo.toml`: `argon2` (KDF), `chacha20poly1305` (AEAD), `data-encoding`/`hmac`/`sha1`/`sha2` (TOTP), `url` (TOTP-URI query decoding via `form_urlencoded` only — not networking), `base64`, `serde`, `thiserror`, `uuid`, `zeroize`. No `tauri`, no async runtime, no networking client.
- `src-tauri/Cargo.toml`: `tauri`/`tauri-plugin-dialog` (desktop shell), `localvault-core` (path dependency), `zeroize`, `atomic-write-file`, `reqwest`+`tokio`+`url`+`scraper`+`image` (favicon fetch only), `clipboard-win` (Windows-only, `cfg(windows)` gated). `argon2`/`chacha20poly1305`/`data-encoding`/`hmac`/`sha1`/`sha2` were removed from `src-tauri` once their only production/test use moved into `localvault-core`.

`app_state/`, `commands/`, `vault/session.rs`, `vault/storage.rs`, `vault/backup.rs`, `vault/lifecycle.rs`, `password_generator.rs`, and `secure_clipboard.rs` remain in `src-tauri` — session orchestration, filesystem/backup I/O, clipboard, and Tauri command glue have not been extracted, and (aside from TOTP's config/error types) neither has password health or the password generator. See "What still remains outside core" below for the accurate, current boundary.

## Completed core extraction (1S-C1 - 1S-C3)

`localvault-core` currently owns:

1. **Private cryptographic primitives** (`crypto/`, not `pub mod`): Argon2id KDF, XChaCha20-Poly1305 AEAD, vault-key/salt generation. Only the narrow set of types required by `vault::format`'s public interface (`EncryptedBlob`, `KdfParams`, `SecretKey`, `CryptoError`) are re-exported through it.
2. **Authenticated vault envelope/format layer** (`localvault_core::vault::format`): `VaultEnvelope`, `create_envelope`/`create_envelope_with_key`, `open_envelope`/`open_envelope_with_key`, `reseal_envelope`, `rewrap_envelope_master_password`.
3. **Persisted vault domain/data model** (`localvault_core::vault::data`): `VaultData`, `VaultEntry`, `VaultCategory`, `SiteIcon`, `TotpConfig`/`TotpAlgorithm`, schema-version constants and validation (including the schema-1-cannot-carry-TOTP rule), and zeroization of sensitive fields on drop.
4. **TOTP RFC 6238 engine** (`localvault_core::totp`): bare-Base32 and `otpauth://` URI setup parsing, SHA1/SHA256/SHA512 generation, `TotpError` (12 variants), all with caller-supplied `now_ms` — core never reads the system clock, and the only network-adjacent dependency (`url::form_urlencoded`) is used solely for query-string decoding, not networking.

Each of these was a strict ownership/module-boundary move (1S-C1 `4721b05`, 1S-C2 `bfd7fec`, 1S-C3 `8f0d5a3`) — not a cryptographic redesign. See `@docs/PROJECT_STATUS.md` for the exact checkpoint commits and `@docs/SECURITY_MODEL.md` for the security properties these preserve unchanged.

A pre-extraction compatibility safety net (1S-B1, `bcdb1ad`; `src-tauri/tests/compat_baseline.rs` plus committed schema-1/schema-2 fixtures) exercises real persisted-format compatibility — including the v1→v2 upgrade-on-write path and the fixed-time TOTP vector — through every extraction step. `src-tauri/tests/data_storage_integration.rs` separately covers the encrypted-storage round trip for the persisted data model against desktop storage.

## What still remains outside core (not yet extracted, and not all destined for core)

The following are still implemented only in `src-tauri`. Some are genuine platform-adapter responsibilities that will likely stay there permanently (clipboard, filesystem, IPC, frontend); others (password health, password generator) simply have not had a placement decision made yet — their presence in this list is not a claim that they will move:

- `AppState` and session orchestration (`app_state/`, `vault/session.rs`)
- filesystem storage, atomic saves/backups (`vault/storage.rs`, `vault/backup.rs`, `atomic-write-file`)
- same-vault OS/session locking
- lifecycle/delete orchestration (`vault/lifecycle.rs`)
- clipboard (`secure_clipboard.rs`, `clipboard-win`)
- recent-vault UX state (`recent_vaults.rs`)
- favicon/network fetching (`site_icon_fetcher.rs`)
- Tauri commands/IPC (`commands.rs`, `commands/`)
- frontend (`src/`)
- password-health orchestration and current implementation (`app_state/password_health.rs`, `commands/password_health.rs`) — placement undecided
- password generator (`password_generator.rs`) — placement undecided
- Android adapter — does not exist yet (1T not started)
- synchronization — does not exist yet (1U/1V not started)

The subset of this list that is a permanent platform-adapter responsibility (not just "not yet extracted") is listed separately below in "What must stay outside the shared core."

Neither password-health nor password-generator placement is a prerequisite for 1T/Android MVP: the 1S remaining-work audit (see `@docs/PROJECT_STATUS.md`, `@docs/HANDOFF_1S_COMPLETE.md`) found both to be pure, low-coupling modules that can be extracted later, without schema or cryptography risk, if and when Android needs them. They are deferred long-term architecture decisions, not blockers that hold 1S open.

## Target boundary: `localvault-core`

LocalVault must not duplicate vault cryptography independently per platform. The intended long-term shape (partially realized — see "Completed core extraction" above):

```
localvault-core (Rust, no Tauri/platform dependency)
    |
    +-- vault format                          [DONE — 1S-C1]
    +-- encryption (Argon2id KDF, XChaCha20-Poly1305 AEAD)   [DONE — 1S-C1]
    +-- KDF/key handling                      [DONE — 1S-C1]
    +-- data model (entries, categories, profiles)  [DONE — 1S-C2]
    +-- validation                            [DONE — 1S-C2]
    +-- migrations (schema 1 -> 2 -> ...)      [schema constants/validation DONE — 1S-C2;
    |                                           upgrade-on-write orchestration still in src-tauri/vault/session.rs]
    +-- password health                        [NOT STARTED — placement undecided; deferred, not required before 1T]
    +-- TOTP (RFC 6238 generation/validation)  [DONE — 1S-C3]
    +-- future sync metadata and merge/conflict semantics  [NOT STARTED]
    |
    +-- Desktop/Tauri adapter   (src-tauri, current app)
    +-- Android adapter         (future, 1T — not started)
```

## What must stay outside the shared core (platform adapter responsibility)

- OS clipboard (`secure_clipboard.rs`'s Windows-specific parts; `clipboard-win`)
- OS filesystem / user-selected file dialogs (`tauri-plugin-dialog`)
- platform dialogs and window management
- biometric APIs
- mobile autofill APIs (Android Autofill)
- camera / QR scanner (deferred; see 1W)
- OS-specific secure storage integration
- Tauri command glue (`commands/` handlers themselves — thin wrappers only, no crypto/business logic)

## Dependencies that must not cross the core/adapter boundary

- The core must not depend on `tauri`, `tauri-plugin-dialog`, `clipboard-win`, or any other desktop/Tauri-specific crate.
- The core must not perform clipboard I/O, file-dialog I/O, or platform-specific storage directly — adapters pass it bytes/paths and receive results.
- Adapters must not implement or re-implement cryptography, KDF, AEAD, vault format parsing, migrations, or TOTP generation — all of that stays in the core.
- The favicon network path (`site_icon_fetcher.rs`) is a desktop-only, explicit, narrow exception and should not be assumed available on constrained mobile contexts without re-review; it must not be treated as precedent for adding network dependencies elsewhere.

## Future mobile architecture

Android (1T) gets a thin adapter analogous to the current `src-tauri` adapter: platform UI on top, calling into `localvault-core` for vault/crypto/TOTP logic (currently extracted) and whatever else has landed in core by the time 1T starts. Mobile-only concerns (autofill, biometrics, camera-based QR scanning, platform secure storage for convenience unlock) live entirely in the adapter, not in the core. Password-health and password-generator placement are undecided as of this checkpoint (see "What still remains outside core" above); the 1S remaining-work audit confirmed neither is required to be resolved before 1T, though either could still move into core later if a concrete Android need arises.

## Future sync abstraction

Sync (1U/1V) is a provider-abstracted transport for **encrypted** vault state only — see `@docs/SECURITY_MODEL.md` for what must never leave the device unencrypted. The sync layer needs, at minimum, before implementation: stable vault identity, revision/version semantics, device identity where required, conflict detection, atomic update rules, offline-first behavior, a recovery strategy, backup interaction, and migration/version compatibility. This design work belongs in the core (sync metadata, merge/conflict semantics) with the actual transport (WebDAV, cloud-storage provider, OS-synced folder, etc.) implemented as a swappable adapter — not hard-coded into the core.
