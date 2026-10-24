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

- Current encrypted payload schema: **3**. Legacy readable schemas: 1 and 2.
- Schema 1 vaults remain readable only if they contain no TOTP secret — schema 1 cannot carry a TOTP secret at all.
- Schema 2 adds support for encrypted TOTP configuration.
- Schema 3 (Stage 1U-2) adds `revision: u64`. Opening never migrates a file; any successful payload write to a legacy (schema 1 or 2) vault upgrades it to schema 3 at revision 1, and each further committed write increments the revision by one. This upgrade path must remain explicit and must never silently change compatibility guarantees (see `@CLAUDE.md` non-negotiable rules).
- **Revision semantics.** The revision lives inside the existing XChaCha20-Poly1305 encrypted payload, so it is authenticated: it cannot be altered without the Vault Key. It is a write counter only — **not** a trusted timestamp, and **not** by itself proof that a copy is the latest or that a remote is fresh. An attacker or fault that serves an older, validly encrypted envelope presents an older but authentic revision. **Anti-rollback protection is not implemented**; the device-local high-water mark described under "Sync binding" is a local observation, not a freshness proof.
- **Envelope fingerprints.** The 1U-1 SHA-256 of raw envelope bytes (`localvault_core::sync`) proves byte identity only — not authenticity, validity, or that the bytes belong to the expected vault.
- **Compatibility.** Builds that predate schema 3 reject schema-3 vaults. Existing backups (`.lvbackup`, `.backup`) keep whatever schema they were written with.
- **Master-password change does not rotate the Vault Key.** `rewrap_envelope_master_password` re-wraps the same Vault Key under a new password-derived key and leaves the encrypted payload (and its revision) untouched; only the raw envelope bytes change. Anyone holding a historical envelope *and* its old master password can still recover that Vault Key, so it remains relevant to any future ciphertext encrypted under it. Vault Key rotation is not implemented and was not approved as part of 1U-2.
- User-facing synchronization does not exist; the core sync logic performs no I/O, and nothing in this section authorizes any sync action.

## Sync binding (Stage 1U-4 through B1j; Windows)

Through B1i this was dormant internal code. Since B1j-2 the initial-binding, status and local-reset workflows are reachable on Windows through registered Tauri commands and a Russian-language dialog; they remain the only binding actions, and none of them synchronizes anything. This section describes the guards that exist in Rust, not a working sync feature. Structure: `@docs/ARCHITECTURE.md`, "Sync binding architecture". The separate encrypted-copy creation guarantees (B2) follow in the next section.

**What is established**
- **Identity.** Vault identity is authenticated by Core: a local and a candidate envelope must both open under the same Vault Key and carry the same vault id. A local path alone is never vault identity; the stored record refers to the vault only through a salted, domain-separated tag that is re-verified against the authenticated id in every unlocked session, and a record for another vault or location is reported as a mismatch and never used.
- **Initial identical binding** requires exact encrypted byte identity: equal raw-envelope SHA-256 fingerprints and authenticated schema-3 revisions on both sides, decided by Core at confirmation.
- **Physical identity.** On Windows the target is checked from an open handle (volume + 128-bit file id, hard-link count, delete-pending, filesystem, local disk) so that a second name for the primary vault, such as a hard link, is not accepted. Only local NTFS/ReFS can pass; anything uncertain is refused.
- **Explicit approval.** Initial binding needs a Rust-owned, session-bound, one-time approval. A prepared approval expires after 120 seconds, is spent by the first confirm, is dropped with the session, and is revalidated against fresh evidence at confirmation. Binding reset uses a separate approval with the same properties; the two exclude each other.
- **State is never silently defaulted.** `NotConfigured` is returned only when absence is confirmed. Corrupt, unreadable, unsupported-version, locator-mismatched and unresolved-recovery-artifact states are distinct outcomes and are never treated as `NotConfigured`.
- **Reset is explicit and verified.** It removes only the local record and its recognized recovery artifacts, after the user is shown fixed consequences (removes the local binding and trusted sync history; may discard a pending sync intent; keeps the vault, backups and the remote target; does not prove remote content absent; does not enable publication). Removal is guarded by evidence (length and SHA-256 of the exact stored files) captured at preparation and rechecked immediately before the first removal. Unreadable or unverifiable evidence (I/O or permission failure, unexpected object, reparse point, oversized or too many files) blocks reset. A successful reset requires a fresh load that confirms nothing is configured.
- **No silent loss of history.** An older authenticated observation never lowers the stored remote high-water mark (it is reported as a regression instead), a checkpoint's synced revision cannot exceed it, and a pending push must exceed it. The only way local history and a pending push are discarded is the explicit, confirmed reset above.
- **Observation is not adoption.** Recording an authenticated high-water observation does not advance the synced baseline and does not authorize a pull or push.
- **Ambiguous persistence.** If a write or removal may have partly happened, the outcome is reported as ambiguous. It does not authorize a retry, repair, rebind or automatic reset; the next decision starts from a fresh status.
- **Redaction.** Status and `Debug` output of binding types expose no path, identifier, fingerprint or revision, except the target path of a verified linked binding, which exists for display.

**Known limitations (not claimed away)**
- **TOCTOU.** Filesystem checks hold only at the instants they ran. A hard link, redirection or replacement created later is not prevented, and there is no snapshot isolation.
- **No general cross-process CAS.** Store replacement and deletion are narrowed read-then-act sequences guarded by evidence, not atomic compare-and-swap; another process that can write the application-data directory can race them.
- **Not tamper-proof.** The state record carries a checksum that detects accidental corruption only; it is not a MAC. An actor who can rewrite local application data can forge or roll back state. The record is not rollback-proof.
- **Durability.** Power-loss durability of the state store and of the underlying filesystem is not universally proven.
- **Local absence is not remote absence.** A file missing in a synchronized folder does not prove the provider has no remote copy, and no initial publication is authorized by it.
- **No cloud freshness or authoritative ancestry.** The high-water mark and revisions are local observations. Whether a candidate is the provider's latest, and its ancestry relative to other devices, are not proven.
- **Placeholders and filesystems.** Cloud placeholder files (reparse points) may be refused rather than hydrated. FAT/exFAT, SMB and other network redirectors, virtual volumes and unidentified filesystems are refused for initial binding, including legitimate ones. ReFS acceptance rests on documentation and has not been exercised on a ReFS volume.
- **Driver trust.** Filesystem name and device characteristics come from the driver stack and are not independently verified.
- **No real sync.** No transport, provider authority, publication, push, pull, adoption, merge or automatic synchronization exists. Binding, status and local reset are user-facing (B1j); none of the others is.
- **Existing B1j reset limitations carry over unchanged:** reset removes only the local record (the vault, backups, the encrypted files and the remote target are untouched and not proven absent), is guarded by evidence that is itself a narrowed read-then-act sequence, and an ambiguous removal is reported as ambiguous rather than retried.

## Encrypted-copy creation (Stage 1U-4 B2a–B2c; Windows)

Structure: `@docs/ARCHITECTURE.md`, "Encrypted-copy creation architecture". B2 writes one new, separate encrypted file. It is not synchronization, backup-to-cloud, binding or publication.

**Implemented guarantees (checked against `vault/session/copy_creation.rs`, `vault/new_copy_file.rs`, `vault/handle_ops.rs`, `commands/copy_creation.rs`)**
- **Explicit, Rust-owned consent.** Preparation (read-only) and confirmation are separate calls owned by the Rust session; the destination comes from a Rust-owned native save dialog, never from the frontend. A selection is never consent. The save dialog only returns a name and is not the no-clobber boundary.
- **One-time, session-bound approval with TTL.** The approval is spent by every confirm call (taken out of the session before anything is checked), expires after 120 seconds, is dropped with the session (lock, expiry, vault switch) and is voided by a newer binding, reset or copy preparation. A stale or failed confirmation cannot be retried against the same preparation. Dialog-attempt ownership prevents an obsolete selection from voiding a newer approval.
- **Authenticated source.** The vault must have no unsaved changes, be schema 3, and match the prepared fingerprint at confirmation; the sync state must be a confirmed `NotConfigured`. The copy holds the exact on-disk encrypted bytes.
- **Local-NTFS-only destination.** The destination directory is pinned by handle and must be a plain, non-reparse directory on a local, non-remote, non-virtual NTFS volume. This is stricter than the B1g identity policy for existing copies (which also recognizes ReFS) and does not change it. UNC paths and the vault's own `.backup`, `.lock` and sync-state files are refused.
- **An existing target is never overwritten.** The target must be absent at preparation and at confirmation, the rename is performed without replace, and the extension is checked. No directory is created.
- **Handle-bound Windows publication.** A hidden staging file is written through its handle, flushed and synced, identity-checked, and renamed by handle into the pinned directory; there is no path-based delete, rename, copy or link.
- **Exact encrypted-byte verification.** After publication an independent path read must return exactly the source bytes, and those bytes must authenticate under the session's Vault Key with the same fingerprint and revision as the vault.
- **Independent physical-identity verification.** The read-back must be the same physical file (identity, one link, local NTFS) and distinct from the vault's own primary.
- **No plaintext publication.** Only encrypted bytes are written; no plaintext, key or password touches the destination or the staging file.
- **No implicit sync-state change and no automatic binding.** The sync state, remote baseline and high-water mark are untouched. Binding the copy remains the separate B1h/B1j flow with its own explicit consent.
- **Definite and ambiguous outcomes are separate.** `Stale`/`Refused` (nothing written); `NotPublished` without leftovers; `NotPublished` with a possible hidden staging leftover; `PublicationUnknown` (the target may or may not exist; nothing was deleted); `CreatedUnverified` (the target exists or may exist and an independent check failed or could not run; it is kept). These keep different codes and messages.
- **No automatic retry of an ambiguous publication.** After `PublicationUnknown` or `CreatedUnverified` there is no retry, cleanup of the target, binding or trust-state change; the user must inspect the location.
- **Redaction.** Errors and `Debug` output carry no path, password, key, fingerprint, revision, file identifier, native status, preparation id or attempt id, except the exact target path returned to the user for display; nothing is logged.

**Known limitations (not claimed away)**
- **Remaining filesystem TOCTOU windows.** The sequence is check-then-use guarded by sharing modes, not an atomic transaction. The staging file is created by path in the pinned directory; a redirection installed between the post-pin ancestor check and that creation could place it elsewhere on the same volume (the handle-bound rename still lands in the pinned directory, and a different volume is refused). Ancestor renames while the pin is held are measured by tests, not assumed; if one occurs the result is `CreatedUnverified`, never success.
- **Trust in Windows/driver-reported facts.** The filesystem name, local-disk and device characteristics come from the driver stack and are not independently verified.
- **No universal guarantee against privileged or malicious interference.** Sharing modes bind ordinary processes only; administrators, backup-privileged processes, kernel components and filesystem filters can bypass them. After the handles close the published file is ordinary user data.
- **Not proven durable.** The directory entry is not flushed; the published name is not claimed to survive sudden power loss.
- **Possible encrypted staging leftover.** A crash or interruption (or an unconfirmed staging delete) can leave a hidden encrypted staging file, reported as `staging_remains` when known. It contains only encrypted bytes.
- **The copy becomes stale.** It keeps the vault's current password wrapper and revision at creation; any later local save makes it stale (binding it would then be refused), and a later master-password change in the session does not update it.
- **Restricted to local NTFS.** Other filesystems (ReFS, FAT/exFAT, SMB/network redirectors, removable or virtual volumes) are refused for creation. Their refusal was not manually tested on those volumes.
- **No remote-provider authority.** A path in a synchronized folder is not evidence that a provider received, accepted or holds the file, or that it is current.
- **No conflict resolution, push or pull.** B2 neither detects nor resolves divergence and transmits nothing.

## Known threat-model limitations

LocalVault does **not** claim to protect against:
- malware running as the user
- keyloggers
- hostile process-memory inspection while the vault is unlocked
- OS compromise
- clipboard observation while secret material is legitimately present
- someone obtaining both an unlocked vault and the user's active session

Storing TOTP in the same encrypted vault as the password improves convenience but is not as independent as keeping the second factor in a physically/logically separate authenticator app. This tradeoff is intentional and should be disclosed to users, not "fixed" by weakening the vault or by silently duplicating the secret elsewhere.

## Android (1T, closed at `7a90301` as an engineering milestone; implemented in detail through 1T-B5c)

**Closeout hardening (source-verified; see `@docs/HANDOFF_1T_COMPLETE.md`).** Not a production-release or certification claim.
- **SAF access:** vaults open read-only by default; writing needs an explicit writable grant, and a save to a provider without a persisted write grant returns `ProviderNotWritable` (`711cda7`). The vault file stays in the user-chosen SAF location; no broad storage permission and no manifest permissions.
- **Enable-editing document check:** "Enable editing" accepts a picker result only if its URI string exactly equals the URI of the recent vault it was launched for; otherwise it refuses before persisting any grant (fail closed, intentionally strict). An intermittent refusal of what the user believes is the same file remains **unresolved and uninvestigated to a root cause**; the strict comparison is deliberately unchanged.
- **Recovery state:** the recovery marker/snapshot store fails closed on filesystem errors (`cd69c4b`); a recent vault is forgotten (grant released, recovery files deleted) only after cleanup is verified (`f7b4633`); in-flight saves block reopen/restore/history cleanup for that vault (`8bfc10d`). Recovery snapshots are ciphertext only.
- **Privacy:** session dialogs are dismissed on lock and input privacy flags are applied to secret fields (`f51190d`); the entry password visibility toggle (`7a90301`) is show/hide of a value already fetched on explicit user action. `allowBackup="false"` plus explicit `backup_rules.xml` and `data_extraction_rules.xml` exclude all app-private storage (recent list, clipboard prefs, recovery snapshots) from cloud backup and device transfer.
- **Residual limits (not verified on a physical device):** process death between marker creation and primary write, or between primary write and verification/cleanup; the full `UNKNOWN_NEEDS_RECOVERY` restore via a real SAF provider; real `AtomicFile` crash behavior; slow-provider in-flight reopen interaction; OEM device-transfer exclusion. JVM tests cover decision logic and failure paths but are not device proof, and no debug fault-injection mechanism exists. Automatic recent-vault eviction after a cleanup failure may leave orphaned encrypted recovery files or persisted grants. If marker cleanup fails after a verified primary write, the user sees a generic failure although the write reached disk (the marker then reconciles as saved on next unlock). The accepted build is a debuggable, debug-signed APK; release signing and non-debug `FLAG_SECURE` behavior are unverified.

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
