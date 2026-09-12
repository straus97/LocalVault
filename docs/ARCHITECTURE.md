# Architecture

## Current architecture (as of 1R)

- **Frontend:** Tauri 2 + React + TypeScript (`src/`). Performs no vault cryptography — it calls Tauri commands and renders results.
- **Backend/security core:** Rust (`src-tauri/src/`).

Observed module layout at the 1R checkpoint:

```
src-tauri/src/
  app_state.rs, app_state/            # in-memory session state: backups, categories, entries,
                                       # lifecycle, master_password, password_health, site_icons, totp
  commands.rs, commands/              # Tauri command handlers (glue): backups, categories,
                                       # credentials, entries, password_health, passwords,
                                       # recent_vaults, site_icons, totp
  crypto/                             # cipher, kdf, keys
  vault/                              # backup, data, format, lifecycle, session, storage
  password_generator.rs
  recent_vaults.rs
  secure_clipboard.rs                 # Windows clipboard integration
  site_icon_fetcher.rs                # the one sanctioned network path (favicons)
  totp.rs
  main.rs, lib.rs
```

Key dependencies (`src-tauri/Cargo.toml`): `tauri`/`tauri-plugin-dialog` (desktop shell), `argon2` (KDF), `chacha20poly1305` (AEAD), `hmac`/`sha1`/`sha2` (TOTP), `zeroize`, `atomic-write-file`, `reqwest`+`tokio`+`url`+`scraper`+`image` (favicon fetch only), `clipboard-win` (Windows-only, `cfg(windows)` gated).

Note the `crypto/`, `vault/`, and most of `app_state/` and `commands/` logic is already reasonably decoupled from Tauri specifics, but has not yet been extracted into a standalone crate — that extraction is the subject of the 1S-A audit (see `@docs/ROADMAP.md`).

## Target boundary: `localvault-core`

LocalVault must not duplicate vault cryptography independently per platform. The intended shape:

```
localvault-core (Rust, no Tauri/platform dependency)
    |
    +-- vault format
    +-- encryption (Argon2id KDF, XChaCha20-Poly1305 AEAD)
    +-- KDF/key handling
    +-- data model (entries, categories, profiles)
    +-- validation
    +-- migrations (schema 1 -> 2 -> ...)
    +-- password health
    +-- TOTP (RFC 6238 generation/validation)
    +-- future sync metadata and merge/conflict semantics
    |
    +-- Desktop/Tauri adapter   (src-tauri, current app)
    +-- Android adapter         (future, 1T)
```

`localvault-core` is a **working name**. Do not finalize the crate name without first inspecting repository/crate-registry conventions (the current package is named `localvault` / lib `localvault_lib` in `Cargo.toml` — the extraction plan from 1S-A should reconcile naming rather than assume `localvault-core` is final).

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

Android (1T) gets a thin adapter analogous to the current `src-tauri` adapter: platform UI on top, calling into `localvault-core` for all vault/crypto/TOTP/password-health logic. Mobile-only concerns (autofill, biometrics, camera-based QR scanning, platform secure storage for convenience unlock) live entirely in the adapter, not in the core.

## Future sync abstraction

Sync (1U/1V) is a provider-abstracted transport for **encrypted** vault state only — see `@docs/SECURITY_MODEL.md` for what must never leave the device unencrypted. The sync layer needs, at minimum, before implementation: stable vault identity, revision/version semantics, device identity where required, conflict detection, atomic update rules, offline-first behavior, a recovery strategy, backup interaction, and migration/version compatibility. This design work belongs in the core (sync metadata, merge/conflict semantics) with the actual transport (WebDAV, cloud-storage provider, OS-synced folder, etc.) implemented as a swappable adapter — not hard-coded into the core.
