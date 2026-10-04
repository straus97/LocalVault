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

## Android (1T, implemented through 1T-B5c)

Android reaches the exact same `localvault-core` crypto/format/schema/TOTP as desktop, through `crates/localvault-android-bridge` (stable UniFFI `=0.32.0` Kotlin/JNA bindings) — no cryptography, vault-format parsing, schema validation, or TOTP generation is duplicated or reimplemented in Kotlin or in the bridge. Full architecture: `@docs/ARCHITECTURE.md`; full history/rationale: `@docs/HANDOFF_1T_PROGRESS.md`.

- **Session ownership:** the decrypted `VaultData` is Rust-owned inside `VaultSession` and never crosses FFI. Locking/dropping the session zeroizes it via `localvault-core`'s existing `Drop` impls — this is unchanged, not reimplemented, by the Android adapter.
- **Keys:** the Master Key and Vault Key never cross FFI; `open_vault` uses `open_envelope` (not `_with_key`), so the bridge never even retains them.
- **Master password:** enters through one narrow `open_vault` call and is wrapped in `Zeroizing` Rust-side as early as practical. The JVM/JNA-side `String` copy that produced it is **not** claimed to be zeroized — Kotlin/JVM cannot deterministically zeroize strings, the same limitation already documented above for the desktop frontend's JS strings.
- **Passwords:** individual entry passwords cross FFI only on an explicit user show/copy action (`entry_password`), never as part of a list/summary. `EntrySummary`/`EntryDetails`/`CategorySummary` are exhaustively field-pinned by bridge tests to guarantee no secret field is added silently.
- **TOTP:** the stored secret/configuration never crosses FFI outward; normal read/display state exposes only whether TOTP is enabled plus a generated `TotpStatus` (code plus its remaining/period timing, via `totp_status`), computed by `localvault_core::totp::generate_totp` for an Android-supplied wall-clock Unix time. Android owns only the clock read, the UI refresh timer, and passive on-screen rotation — this mirrors the desktop rule that core never reads a system clock. Passive TOTP refresh is explicitly not treated as user activity.
- **TOTP setup/replace/remove (1T-B5c):** `localvault-core` remains the sole owner of TOTP parsing, validation and generation; Kotlin does not parse, normalize or construct TOTP configuration. The raw setup input (bare Base32 or `otpauth://`) crosses FFI only inward, as the direct argument of `stage_set_entry_totp`, and is passed verbatim; an invalid input is rejected by core (`InvalidTotpConfiguration`) with no parser-internals oracle. Set/replace/remove use the same transactional SAF save pipeline as other mutations. The Android UI uses a dedicated setup screen; the raw input lives only in its input field until submit, is never put in a snapshot, Bundle, status/error object, toast or log, and is wiped on submit, Cancel, system Back, `onStop`/background, lock and destroy (best-effort — the JVM `String` handed across FFI is not claimed to be zeroized). The immediate `onStop` lock remains a hard invariant. Removal needs an explicit confirmation that warns the key cannot be shown again. Create-with-TOTP and QR scanning are not implemented (QR is deferred to 1W).
- **Authentication errors:** the bridge's `BridgeError` preserves the same wrong-password/corrupted-ciphertext indistinguishability as core (`AuthenticationFailed` covers both) — it does not add a finer authentication oracle. `UnsupportedFormat` is exposed separately only because it is decided before, or independent of, any password-dependent step.
- **Storage/SAF:** the authoritative vault is always the SAF document, read via `ContentResolver`/SAF `ACTION_OPEN_DOCUMENT` once per unlock; no broad filesystem permission is requested. No decrypted/plaintext copy of the vault is ever persisted internally. Since 1T-B5, a save first stores the encrypted pre-write primary bytes as a ciphertext-only recovery snapshot in app-private persistent storage, with associated non-secret recovery/marker metadata; this is deliberate, bounded recovery state, not the authoritative vault, and reconciliation may perform an additional primary read when recovery state must be resolved. Recent-vault history persists only non-secret metadata (document URI string + display name, capped at 5 entries) via a persisted URI grant — never the master password or any decrypted data. **1T-B1–B4 were read-only**; from 1T-B5 onward Android writes through a transactional SAF save pipeline (recovery snapshot/marker and stale-source checks that detect external changes before overwrite; `ChangedExternally` forces a safe lock/reopen and never overwrites the externally changed primary). Known B5 follow-ups, not fixed by B5c: `finishEntrySave`/`finishEntryDelete` can skip a cache refresh after navigation, and after `WriteFailed` Rust can leave the staged candidate pending until lock/reconciliation.
- **Clipboard:** password and TOTP-code copies go through a single ownership-verified Android clipboard (`SecureClipboard`), with a 30-second intended LocalVault lifetime, Android 13+ sensitive-content marking, and a random non-secret per-copy ownership token (never the copied value) used to decide whether a clipboard-clear is safe. Because Android 10+ denies clipboard reads to an unfocused app, a background expiry cannot always be verified and cleared immediately — LocalVault defers that cleanup until it regains focus rather than blindly clearing (which could erase another app's newer copy) or leaving stale state unresolved. **This is not, and must not be described as, the Windows clipboard sequence-number guarantee** — Android offers no equivalent. Locking the vault does not itself clear the clipboard (the normal flow is copy → switch app → paste); manually verified across the foreground, background-then-return, and unrelated-content-preserved cases.
- **Session lifecycle:** the vault locks immediately when the Android app leaves the foreground (`onStop`) or on an explicit Lock/Back action from an unlocked screen — there is currently no 60-second-style inactivity grace period on Android (unlike desktop); this is a deliberately more conservative default, not an oversight.
- **Screenshots/recents thumbnail:** blocked via `FLAG_SECURE` in non-debug builds. A debuggable build disables `FLAG_SECURE` (derived from the app's real `ApplicationInfo.FLAG_DEBUGGABLE` state, not a hard-coded flag) so development screenshots stay possible. **Non-debug/release screenshot-blocking behavior has not been exercised in an actual release build** — only the debug-vs-debuggable logic has been verified.
- **Known open blocker — Android release `panic = "abort"`:** the workspace `[profile.release]` sets `panic = "abort"` (originally for the desktop release binary). UniFFI's panic containment at the FFI boundary expects Rust unwinding; an `abort` panic strategy can prevent it from converting a Rust panic into a catchable Kotlin exception in a **release** build of the Android bridge. This has not caused any problem so far because all Android work through 1T-B5c has used debug builds only (default `panic = "unwind"`). It must be deliberately resolved — without naively changing the shared workspace profile in a way that could affect the existing Windows release — before any production Android release is considered safe. Not solved as of this checkpoint.
- **`applicationId`/package identity:** still `com.localvault.android.proof` — an intentionally temporary bootstrap identity, not yet a deliberate production choice.

## Mobile / sync security requirements (forward-looking, for 1U–1V; Android write support landed in 1T-B5)

These apply to work not yet done (except where noted) — they are requirements on the design, not yet implemented:

- A sync provider/server must never receive: the master password, the plaintext Vault Key, plaintext credentials, or plaintext TOTP secrets. Only encrypted vault state may leave the device.
- No naive "last writer silently overwrites everything" sync. Conflict detection and safe atomic updates are required before any sync feature ships.
- Android secure-storage integration (e.g. Android Keystore) is only for approved convenience-unlock mechanisms, not as a substitute for the vault's own encryption, and stays in the platform adapter, not the core. No convenience-unlock mechanism exists yet.
- Biometric unlock and Android Autofill (1W) must be reviewed for what they expose to the OS layer before being enabled by default. Neither is implemented.
- Android **write** support (1T-B5, implemented through B5c) was required to define, before implementation: writable-SAF access scope, safe save/replace semantics, backup/recovery behavior, external-change detection, stale-write handling, concurrent-session behavior, and compatibility with the same persisted vault format desktop writes — it must not simply copy desktop's path-based rename/lock semantics onto SAF's URI/document model, which does not support them the same way.
