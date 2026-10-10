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

- **Session ownership:** the decrypted `VaultData` (and the Vault Key, see "Keys" below) is Rust-owned inside `VaultSession` and never crosses FFI. Locking/dropping the session zeroizes it via `localvault-core`'s existing `Drop` impls — this is unchanged, not reimplemented, by the Android adapter.
- **Keys (corrected; the B1–B4 statement that `open_vault` used `open_envelope` and retained neither key is obsolete since B5a — this is a documentation correction, not a newly discovered vulnerability):** the **Master Key is not retained** — `open_vault` uses `open_envelope_with_key`, which drops and zeroizes it before returning, and the master password is never stored. The **Vault Key is retained Rust-side only**, inside `SessionState` while the vault session is unlocked, and temporarily inside `PendingVaultCreation` during the create flow until finalization or discard. It is a zeroizing `SecretKey` and is dropped (zeroized) when the session or pending creation is locked/discarded/dropped, together with the decrypted `VaultData` and any staged candidate. It is retained so Android can reseal the encrypted envelope after mutations without storing the master password or re-running Argon2id on every save, which matches the desktop session model conceptually. Neither key crosses FFI in plaintext: Kotlin receives only opaque UniFFI handles and encrypted `VaultEnvelope` bytes (in which `wrapped_vault_key` is already wrapped), and never owns cryptographic key material; no plaintext vault data is persisted. While the vault is unlocked the process necessarily holds decrypted secret state and the Vault Key in memory, and hostile process-memory inspection while unlocked remains outside the protection boundary described under "Known threat-model limitations".
- **Master password:** enters through one narrow `open_vault` call and is wrapped in `Zeroizing` Rust-side as early as practical. The JVM/JNA-side `String` copy that produced it is **not** claimed to be zeroized — Kotlin/JVM cannot deterministically zeroize strings, the same limitation already documented above for the desktop frontend's JS strings.
- **Passwords:** individual entry passwords cross FFI only on an explicit user show/copy action (`entry_password`), never as part of a list/summary. `EntrySummary`/`EntryDetails`/`CategorySummary` are exhaustively field-pinned by bridge tests to guarantee no secret field is added silently.
- **TOTP:** the stored secret/configuration never crosses FFI outward; normal read/display state exposes only whether TOTP is enabled plus a generated `TotpStatus` (code plus its remaining/period timing, via `totp_status`), computed by `localvault_core::totp::generate_totp` for an Android-supplied wall-clock Unix time. Android owns only the clock read, the UI refresh timer, and passive on-screen rotation — this mirrors the desktop rule that core never reads a system clock. Passive TOTP refresh is explicitly not treated as user activity.
- **TOTP setup/replace/remove (1T-B5c):** `localvault-core` remains the sole owner of TOTP parsing, validation and generation; Kotlin does not parse, normalize or construct TOTP configuration. The raw setup input (bare Base32 or `otpauth://`) crosses FFI only inward, as the direct argument of `stage_set_entry_totp`, and is passed verbatim; an invalid input is rejected by core (`InvalidTotpConfiguration`) with no parser-internals oracle. Set/replace/remove use the same transactional SAF save pipeline as other mutations. The Android UI uses a dedicated setup screen; the raw input lives only in its input field until submit, is never put in a snapshot, Bundle, status/error object, toast or log, and is wiped on submit, Cancel, system Back, `onStop`/background, lock and destroy (best-effort — the JVM `String` handed across FFI is not claimed to be zeroized). The immediate `onStop` lock remains a hard invariant. Removal needs an explicit confirmation that warns the key cannot be shown again. Create-with-TOTP and QR scanning are not implemented (QR is deferred to 1W).
- **Authentication errors:** the bridge's `BridgeError` preserves the same wrong-password/corrupted-ciphertext indistinguishability as core (`AuthenticationFailed` covers both) — it does not add a finer authentication oracle. `UnsupportedFormat` is exposed separately only because it is decided before, or independent of, any password-dependent step.
- **Storage/SAF:** the authoritative vault is always the SAF document, read via `ContentResolver`/SAF `ACTION_OPEN_DOCUMENT` once per unlock; no broad filesystem permission is requested. No decrypted/plaintext copy of the vault is ever persisted internally. Since 1T-B5, a save first stores the encrypted pre-write primary bytes as a ciphertext-only recovery snapshot in app-private persistent storage, with associated non-secret recovery/marker metadata; this is deliberate, bounded recovery state, not the authoritative vault, and reconciliation may perform an additional primary read when recovery state must be resolved. Recent-vault history persists only non-secret metadata (document URI string + display name, capped at 5 entries) via a persisted URI grant — never the master password or any decrypted data. **1T-B1–B4 were read-only**; from 1T-B5 onward Android writes through a transactional SAF save pipeline (recovery snapshot/marker and stale-source checks that detect external changes before overwrite; `ChangedExternally` forces a safe lock/reopen and never overwrites the externally changed primary). After any failed/unverified primary write (write throws, readback throws, or readback bytes differ from the staged bytes; `cfe9e6f`), the coordinator discards the Rust staged candidate before returning `WriteFailed`, leaving the recovery marker and encrypted pre-write snapshot untouched and not advancing the baseline; a retry is still guarded by stale check #1. `ChangedExternally` (entry save/delete and category mutations; `d1a85e4`) locks only if the Activity is alive and the mutation's coordinator still owns the live session, so a callback from a replaced/closed coordinator cannot lock a newer session. The two earlier B5 correctness follow-ups are closed; no real-device QA was required for them.
- **Clipboard:** password and TOTP-code copies go through a single ownership-verified Android clipboard (`SecureClipboard`), with a 30-second intended LocalVault lifetime, Android 13+ sensitive-content marking, and a random non-secret per-copy ownership token (never the copied value) used to decide whether a clipboard-clear is safe. Because Android 10+ denies clipboard reads to an unfocused app, a background expiry cannot always be verified and cleared immediately — LocalVault defers that cleanup until it regains focus rather than blindly clearing (which could erase another app's newer copy) or leaving stale state unresolved. **This is not, and must not be described as, the Windows clipboard sequence-number guarantee** — Android offers no equivalent. Locking the vault does not itself clear the clipboard (the normal flow is copy → switch app → paste); manually verified across the foreground, background-then-return, and unrelated-content-preserved cases.
- **Session lifecycle:** the vault locks immediately when the Android app leaves the foreground (`onStop`) or on an explicit Lock/Back action from an unlocked screen — there is currently no 60-second-style inactivity grace period on Android (unlike desktop); this is a deliberately more conservative default, not an oversight.
- **Screenshots/recents thumbnail:** blocked via `FLAG_SECURE` in non-debug builds. A debuggable build disables `FLAG_SECURE` (derived from the app's real `ApplicationInfo.FLAG_DEBUGGABLE` state, not a hard-coded flag) so development screenshots stay possible. **Non-debug/release screenshot-blocking behavior has not been exercised in an actual release build** — only the debug-vs-debuggable logic has been verified.
- **Android release panic strategy — RESOLVED at the configuration level (Android-only profile):** the workspace `[profile.release]` keeps `panic = "abort"` and is **unchanged** (it is the desktop/Windows release profile; its failure semantics are intentionally outside the Android fix, and a panic there still terminates the process). UniFFI 0.32.0 wraps every generated `extern "C"` export (and the rustbuffer helpers) in `catch_unwind`; that containment only works with unwinding. Cargo rejects `panic` in a package-specific profile, so the root `Cargo.toml` adds a dedicated profile: `[profile.android-release]` = `inherits = "release"`, `panic = "unwind"`, `strip = "debuginfo"` (`strip = "debuginfo"` deliberately keeps the ELF `.symtab` so `uniffi-bindgen` can extract `UNIFFI_META` symbols). Android release-profile builds must use `android\scripts\build-android-debug.ps1 -RustProfile android-release` (runs `cargo ndk -t arm64-v8a build -p localvault-android-bridge --profile android-release`); **never `--release`** for the Android bridge. The script generates the Kotlin bindings from the original unstripped `.so`, then strips only the copied jniLibs `.so` with the pinned NDK `llvm-strip --strip-all`. `-RustProfile` accepts only `debug` (default, unchanged) and `android-release`; `release` is rejected. With unwind, a Rust panic inside a bridge call becomes a UniFFI `UnexpectedError` and surfaces in Kotlin as `InternalException` (not a `BridgeException`), which existing broad Kotlin `catch` sites turn into a generic failure; the bridge adds **no** `catch_unwind`, no panic-to-`BridgeError` translation, and Kotlin has no `InternalException`-specific handling. Audit basis: no `unwrap`/`expect`/`panic!` in bridge or core production code; the only realistic residual panic path found is `Uuid::new_v4()` when OS randomness fails (not changed). Every `stage_*` mutates a clone and only the final assignment of `staged` touches session state, and Rust performs no file I/O, so a caught panic cannot leave partially mutated persisted state.
  - **Not claimed:** non-panic aborts (e.g. out-of-memory, stack overflow) remain possible and are unaffected by panic strategy. **No deliberate Rust panic was injected on a physical device**, so on-device panic containment is evidenced by profile/ELF/UniFFI-source analysis plus a device smoke test, not by a live probe. No final automated device logcat gate was completed. Android release **packaging/signing is not implemented** (Gradle remains `assembleDebug`, no release buildType); this resolution does not mean the Android release pipeline is ready to ship.
- **`applicationId`/package identity:** `com.localvault.android` (the production identity; the temporary bootstrap identity `com.localvault.android.proof` was retired by the package cleanup, which changed no behavior, permissions or storage semantics). The Rust/UniFFI bridge namespace `uniffi.localvault_android_bridge` is separate and unchanged. A build with the new `applicationId` installs as a different app from one built with the old identity: it does not share the old app's private data (recent-vault history, recovery snapshots) or its persisted SAF URI grants.

## Mobile / sync security requirements (forward-looking, for 1U–1V; Android write support landed in 1T-B5)

These apply to work not yet done (except where noted) — they are requirements on the design, not yet implemented:

- A sync provider/server must never receive: the master password, the plaintext Vault Key, plaintext credentials, or plaintext TOTP secrets. Only encrypted vault state may leave the device.
- No naive "last writer silently overwrites everything" sync. Conflict detection and safe atomic updates are required before any sync feature ships.
- Android secure-storage integration (e.g. Android Keystore) is only for approved convenience-unlock mechanisms, not as a substitute for the vault's own encryption, and stays in the platform adapter, not the core. No convenience-unlock mechanism exists yet.
- Biometric unlock and Android Autofill (1W) must be reviewed for what they expose to the OS layer before being enabled by default. Neither is implemented.
- Android **write** support (1T-B5, implemented through B5c) was required to define, before implementation: writable-SAF access scope, safe save/replace semantics, backup/recovery behavior, external-change detection, stale-write handling, concurrent-session behavior, and compatibility with the same persisted vault format desktop writes — it must not simply copy desktop's path-based rename/lock semantics onto SAF's URI/document model, which does not support them the same way.
