# LocalVault 1S Complete Handoff

This document is the authoritative handoff for a fresh engineer, fresh Claude Code session, or fresh ChatGPT conversation picking up work at the start of 1T. Read `@docs/PROJECT_STATUS.md` and `@docs/ROADMAP.md` alongside this file.

## 1. Stage result

- **1S — Multi-platform core preparation is COMPLETE.**
- **1T — Android mobile MVP is the next stage and has NOT started.** No Android project, no Kotlin/Java choice, no JNI/UniFFI choice, no Tauri-Mobile-vs-native choice, no Android filesystem design, and no Android secure-storage design exist yet. All of that belongs to 1T planning/design, not to this handoff.

## 2. Repository baseline

- Branch: `redesign/light-ui-v1.1`
- Production/core implementation checkpoint: `8f0d5a36c73cc8d7bbee936f6df6a55bd1533aff` — `refactor: extract TOTP module into core` (1S-C3, the last commit that touched `localvault-core` or `src-tauri` source)
- Documentation / audit baseline: `962f2a7` — `docs: record completed core extraction checkpoints`. The 1S remaining-work audit was performed against this exact repository state.
- The closure-documentation commit hash is intentionally not embedded in this handoff; obtain it from `git log` after the commit lands. `@docs/PROJECT_STATUS.md` tracks the implementation checkpoint and stage status rather than self-referencing this document's own commit.

## 3. Completed 1S sequence

1. **1S-B1** — `bcdb1ad`: pre-extraction compatibility safety net (`src-tauri/tests/compat_baseline.rs`, committed schema-1/schema-2 fixtures).
2. **Workspace skeleton** — `07e15fd`: added the `localvault-core` workspace member.
3. **1S-C1** — `4721b05`: extracted crypto primitives (Argon2id KDF, XChaCha20-Poly1305 AEAD, key/salt/nonce helpers — kept private) and the authenticated vault envelope/format layer into `localvault-core`.
4. **1S-C2** — `bfd7fec`: extracted the persisted vault domain/data model (`VaultData`, entries, categories, site icons, `TotpConfig`/`TotpAlgorithm`, schema constants/validation, zeroization) into `localvault-core`.
5. **1S-C3** — `8f0d5a3`: extracted the TOTP RFC 6238 parser/generator into `localvault-core`, as a strict mechanical move (no API/behavior redesign).
6. **Documentation sync** — `962f2a7`: recorded the completed core extraction checkpoints.
7. **1S remaining-work audit** — read-only architecture/security audit performed at `962f2a7`, re-verifying the full 1S-A checklist against the post-extraction state. **Decision: A — close 1S now.** Rationale: every requirement that gates Android starting is already satisfied by C1–C3; remaining placement questions are non-blocking.

## 4. Current `localvault-core` boundary

`localvault-core` (no Tauri/platform dependency) owns:

- Private cryptographic primitives: Argon2id KDF, XChaCha20-Poly1305 AEAD, vault-key/salt/nonce generation.
- The authenticated vault envelope/format (`vault::format`: `VaultEnvelope`, create/open/reseal/rewrap).
- The persisted vault data/domain model (`vault::data`: entries, categories, profiles, `SiteIcon` persisted representation, `TotpConfig`/`TotpAlgorithm`, schema constants, validation, zeroization).
- TOTP (`totp`): bare-Base32 and `otpauth://` URI setup parsing, RFC 6238 SHA1/SHA256/SHA512 generation, caller-supplied time (no platform clock ownership).

## 5. Responsibilities intentionally outside core

These remain in `src-tauri` as permanent platform-adapter responsibilities, not "not yet extracted" items: `AppState`/session orchestration, filesystem reads/writes, atomic saves/backups, same-vault OS/session locking, external disk-change detection/orchestration, lifecycle/delete filesystem behavior, clipboard, recent-vault UX state, favicon/network fetching, Tauri IPC/commands, frontend/mobile UI, platform timers, and platform file-picker/storage APIs. Android will implement its own platform-adapter behavior for all of these rather than reuse the Windows-specific I/O/clipboard code.

## 6. Deferred / non-blocking items

Reviewed and consciously left in place — none of these block 1T:

1. **Password generator** (`src-tauri/src/password_generator.rs`) — pure and portable (character-class generation, `getrandom`-backed, zeroizing `Drop`), mechanically extractable later if ever needed. Not part of current 1T MVP scope. No crypto/schema compatibility risk from leaving it desktop-side.
2. **Password health** (`src-tauri/src/app_state/password_health.rs`) — the analysis portion (`analyze_password_health(&VaultData) -> PasswordHealthReport`) is pure and could move later; the `AppState` wrapper stays adapter-side either way. Not part of current 1T MVP scope. No duplicated crypto/schema semantics exist today.
3. **Schema upgrade-on-write helper** — the small legacy-schema-1-to-2 bump currently lives inline in `src-tauri/src/vault/session.rs`'s `save()`/`commit_candidate()`. Does not block Android starting; not redesigned by this handoff.
4. **Sync metadata / merge-conflict semantics** — deliberately deferred; 1S must not implement synchronization prematurely. The current `VaultEnvelope` format does not structurally force a naive last-write-wins design later.

Placement of items 1–3 remains open, not decided to move — do not assume they will move as part of 1T.

## 7. Compatibility / security invariants (unchanged by 1S)

- Schema 1 remains readable only if it carries no TOTP secret; schema 1 cannot carry TOTP.
- Schema 2 is current and supports encrypted TOTP configuration.
- Writes to a legacy schema-1 vault upgrade it to schema 2 (upgrade-on-write, backward-compatible).
- `compat_baseline.rs` fixture coverage (schema-1 and schema-2 fixtures) gates this compatibility through every extraction step.
- TOTP RFC 6238 vectors (SHA1/SHA256/SHA512) remain exact.
- Master password is never stored. Vault Key is a fresh random 256-bit key per vault, wrapped by the Master Key, never stored plaintext.
- Credentials, passwords, profiles, categories, TOTP secrets, and cached site icons are encrypted at rest.
- Generated TOTP codes are never persisted.
- Protected clipboard behavior remains a platform-adapter (Windows) concern, unchanged by 1S.

## 8. Validation baseline

At the 1S-C3 production checkpoint (`8f0d5a3`) — the last checkpoint that changed Rust/frontend source, not rerun by this documentation-only handoff:

- Rust tests: 228 PASS (`localvault-core` lib 43, `localvault` lib 178, `compat_baseline` 6, `data_storage_integration` 1)
- Frontend production build: PASS
- Strict clippy (`-D warnings`, workspace): PASS
- `cargo check` / `cargo check --release` (workspace): PASS
- Working tree: CLEAN

## 9. 1T planning constraints

- Windows desktop remains supported; 1S/1T work must not overwrite or rewrite the existing `v1.0.0` release artifact, tag, or source commit (see `@CLAUDE.md`).
- Android is the next and only currently planned mobile platform. iOS is not in the roadmap.
- No duplicate vault cryptography per platform — the Android adapter must call into the same `localvault-core` as desktop, not reimplement crypto/format/schema/TOTP logic.
- The Android adapter should stay thin: platform UI, filesystem/storage, clipboard, biometrics, autofill, camera-based QR scanning, and secure-storage-for-convenience-unlock all live in the adapter, not in core.
- Do not invent storage abstractions, FFI/binding choices, or sync architecture before the 1T architecture/design audit. Those choices belong to 1T planning and must be justified there.
- No naive "last writer silently overwrites everything" sync design; a sync provider/server must never receive the master password, plaintext Vault Key, plaintext credentials, or plaintext TOTP secrets (see `@docs/SECURITY_MODEL.md`).

## 10. Git policy reminder

Before starting 1T work, a fresh session should run `git branch --show-current`, `git rev-parse HEAD`, `git status --porcelain=v1 -uall`, and `git log -5 --oneline`. Use `@docs/PROJECT_STATUS.md` to confirm the active stage, branch, and last production/core implementation checkpoint; use Git itself as the source of truth for the actual current HEAD. Do not push or tag without explicit request.
