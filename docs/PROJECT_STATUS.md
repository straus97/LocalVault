# Project Status

Authoritative as of the 1T-B4 checkpoint (`4a42ffc`, evaluated against repository state `4a42ffc`). Update this file when the active stage, branch, or implementation checkpoint changes — do not let it drift. For full detail on the current 1T (Android) effort, read `@docs/HANDOFF_1T_PROGRESS.md` alongside this file.

## Branch / implementation checkpoint

- Repository: https://github.com/straus97/LocalVault
- Current development branch: `redesign/light-ui-v1.1`
- Current implementation checkpoint (production/core code, all platforms): `4a42ffc5081a2958f2046132f063e6f9261c3f1b` — `feat: add Android categories and TOTP` (1T-B4, the latest committed Android checkpoint)
- Android checkpoints on this branch, in order: `b72f95d` (1T-B1b, Rust/UniFFI/JNA bridge + real-device proof), `3d1a83d` (1T-B2, open/unlock/list real vaults), `fad2746` (1T-B3, usable reader: search/detail/clipboard/localization), `4a42ffc` (1T-B4, categories + TOTP). 1T-B1a (toolchain/environment proof) produced no commit — see `@docs/HANDOFF_1T_PROGRESS.md` §7.
- 1S checkpoints (unchanged, see below): `8f0d5a3` (1S-C3 TOTP core), `bfd7fec` (1S-C2 data model core), `4721b05` (1S-C1 crypto/format core), `07e15fd` (core workspace skeleton), `bcdb1ad` (1S-B1 compat safety net), `c5eb5e6` (record 1R completion and Android roadmap), `47c2315` (1R frontend), `af1b2e6` (1R backend)
- Working tree at this checkpoint: clean
- Nothing here should be assumed pushed unless `git status`/`git log` against the remote explicitly confirms it.
- **Desktop build caveat:** the user's Desktop shortcut (`C:\Users\nikita\Desktop\LocalVault.exe`) is confirmed by SHA256 to be the original immutable `v1.0.0` executable — it predates the light-UI redesign and TOTP entirely. Current source at HEAD was **not** rolled back and contains both. Launch the current build with `npm run tauri dev` from `D:\LocalVault` (debug target only; never overwrites the preserved `v1.0.0` binaries). Full detail: `@docs/HANDOFF_1T_PROGRESS.md` §16.

## Existing v1.0.0 release (do not overwrite)

- Executable: `D:\LocalVault_Release\LocalVault.exe`
- Version: 1.0.0
- Source commit: `04b6220d96599b96b68135054994b0bc731aa9e4`
- Git tag: `v1.0.0`
- SHA256: `A5707B9901607BD61D7881734478D5D5A2FB3D9CE965D41B7D9863ABF256C481`
- Metadata: FileVersion/ProductVersion 1.0.0, ProductName LocalVault, FileDescription LocalVault, CompanyName Штраус Никита Алексеевич, © 2026
- Authenticode: Not signed
- All redesign work (`redesign/light-ui-v1.1` and beyond) targets v1.1+. Never overwrite or rewrite the v1.0.0 release artifact, tag, or source commit.

## Completed redesign checkpoints

### 1N — light blue/white three-column UI
- Checkpoint: `cb4b4fe0390c9f40224b23a9b8f6c23a15ac039f`

### 1O — Sites & Profiles
- Grouping by normalized domain
- Independent credentials/profiles
- `profileName` backward-compatible model
- Final checkpoint: `96e103e8e059baff73fc62ff8a02c5ce6895d1ad`

### 1P — encrypted local favicon cache
- `7051319e` — encrypted site icon cache model
- `4173891f` — hardened favicon fetcher
- `0a8472b3` — backend integration
- `7687c1918e2b11ae3134a56f71ae7141e23d9fbb` — frontend UI
- Favicon fetching is a narrow, explicit network exception. General vault operation remains local-only.

### 1Q — Password Health
- Backend: `7303319a929737dd37748deeca00225c1e00795f`
- Frontend: `f58e7025202434e6d9f16655c73df9033d92b144`
- Fully local password-health analysis; exact password reuse detection; conservative weak-password heuristics; Security workspace UI
- No password hashes/fingerprints persisted; no raw passwords in health DTOs; no external APIs

### 1R — Local TOTP / 2FA (COMPLETE)
- Backend: `af1b2e657438e94830a941f07ff375103cd65c46`
- Frontend: `47c23158591218131c97d3ab27940cddd5b731c9`
- Full design/QA/security detail: `@docs/HANDOFF_1R_COMPLETE.md`

### 1S — Multi-platform core preparation (COMPLETE)

See `@docs/ROADMAP.md` for full 1S scope and `@docs/HANDOFF_1S_COMPLETE.md` for the closure handoff. Checkpoints landed so far, in order:

- **1S-B1** — `bcdb1ad`: pre-extraction compatibility safety net (`src-tauri/tests/compat_baseline.rs`, committed schema-1/schema-2 fixtures) committed before any code moved, to catch a regression in persisted-format compatibility during extraction.
- **1S-C1** — `4721b05`: extracted crypto primitives (Argon2id KDF, XChaCha20-Poly1305 AEAD, key/salt helpers — kept private) and the authenticated vault envelope/format layer into `localvault-core` (`localvault_core::vault::format`).
- **1S-C2** — `bfd7fec`: extracted the persisted vault domain/data model (`VaultData`, entries, categories, site icons, `TotpConfig`/`TotpAlgorithm`, schema validation, zeroization) into `localvault_core::vault::data`.
- **1S-C3** — `8f0d5a3`: extracted the TOTP RFC 6238 parser/generator into `localvault_core::totp`, as a strict mechanical move (no API/behavior redesign).
- Each C1-C3 checkpoint is a pure ownership/module-boundary move — no cryptographic, parsing, validation, or error-semantics changes; ordinary Rust tests (unit + `compat_baseline` + `data_storage_integration`) were used as the compatibility gate at every step.
- **1S remaining-work audit** — performed at `962f2a7`: re-verified the full 1S-A checklist (module boundaries, core dependencies, `AppState` dependencies, Tauri/Windows-only dependencies, clipboard/filesystem/timing/network/backup boundaries, TOTP placement, reusable-crate boundary, test coverage, mobile constraints, future-sync constraints) against the post-extraction state and found no blocker to starting 1T. Decision: **close 1S now**.
- **Deferred, non-blocking** (long-term placement questions, not 1T prerequisites): password-health placement and password-generator placement remain undecided — both are pure, low-coupling modules that the audit found extractable later, without schema/crypto risk, if and when Android actually needs them. See `@docs/ARCHITECTURE.md` for exactly what remains outside `localvault-core` today.

### 1T — Android mobile MVP (IN PROGRESS)

**1T is not complete.** Android is currently a usable **read-only** LocalVault client, manually verified on a real arm64-v8a device through B1b–B4. See `@docs/HANDOFF_1T_PROGRESS.md` for full detail; only a summary is kept here.

- **1T-B1a** — read-only toolchain/environment proof (no commit): installed and pinned the Android Rust target (`aarch64-linux-android`), NDK `27.2.12479018` (r27c), and `cargo-ndk`; confirmed unmodified `localvault-core` checks and builds for Android ARM64.
- **1T-B1b** — `b72f95d`: first Android architecture proof — native Kotlin UI → stable UniFFI `=0.32.0` Kotlin/JNA bindings → new `crates/localvault-android-bridge` → `localvault-core`, exercised end to end (positive and negative auth paths) against the committed compat fixture on a real device, with no secret logcat leakage.
- **1T-B2** — `3d1a83d`: real vertical slice — SAF `ACTION_OPEN_DOCUMENT` vault selection, real master-password unlock through a Rust-owned `VaultSession`, real entry list, explicit lock, immediate lock on backgrounding. Read-only.
- **1T-B3** — `fad2746`: usable reader — Russian + English UI, recent-vault history (persisted read-only URI grants, non-secret metadata only), search, entry detail, password show/hide, username/password copy through a protected, ownership-verified Android clipboard, debug-screenshots-allowed/non-debug-`FLAG_SECURE` policy. Manually QA'd on a real device.
- **1T-B4** — `4a42ffc`: category browsing/filtering, TOTP display with live local rotation/countdown (smooth `ValueAnimator`-based progress, no per-frame regeneration) and copy, TOTP generated by `localvault-core` only. Manually QA'd on a real device.
- **Remaining before 1T can close:** Android write/save, safe SAF replacement/recovery semantics, vault creation, entry/profile/category mutation, TOTP setup/edit/remove, `applicationId`/package cleanup, site/profile grouping decision, large-vault list optimization, and the release `panic = "abort"` blocker (see `@docs/HANDOFF_1T_PROGRESS.md` §20–22). **Do not treat 1T as done.**

## Test / gate status

**Android bridge, at the 1T-B4 checkpoint (`4a42ffc`):** `localvault-android-bridge` 24 tests PASS; strict clippy PASS; Android debug build PASS (no compatibility fixture bundled in the APK).

**Shared/desktop, at the 1S-C3 checkpoint (`8f0d5a3`, unaffected by 1T Android work since no `localvault-core`/`src-tauri`/`src` source has changed since):**
- Frontend production build: PASS
- Rust tests: 228 PASS (`localvault-core` lib 43, `localvault` lib 178, `compat_baseline` 6, `data_storage_integration` 1)
- Strict clippy (`-D warnings`, workspace): PASS
- `cargo check` / `cargo check --release` (workspace): PASS
- Working tree: CLEAN

Re-run `localvault-core`/`compat_baseline`/`data_storage_integration` against current HEAD rather than trusting these exact historical counts once further core changes land.

## Vault schema

- Current schema: 2
- Legacy readable schema: 1
- Schema 1 remains readable only if it contains no TOTP; it cannot carry a TOTP secret.
- Schema 2 supports encrypted TOTP configuration.
- Writes upgrade legacy schema 1 vaults to schema 2.

## Immediate next phase

**1S is complete.** Crypto/vault-format (1S-C1), persisted vault data (1S-C2), and TOTP (1S-C3) are extracted into `localvault-core`, and the 1S remaining-work audit confirmed no further extraction is required before Android work begins. Password-health placement and password-generator placement remain deferred, non-blocking long-term questions — see `@docs/ARCHITECTURE.md` for the current (not merely target) module boundary.

**1T (Android mobile MVP) is in progress, not complete.** B1a through B4 are done (see above) and Android is a usable, manually-verified, read-only LocalVault client. **Next: 1T-B5 — safe Android write/create/CRUD foundation.** This is the next major implementation task and must start in a **new** Claude chat with a focused security/storage architecture review before any source edits — see `@docs/HANDOFF_1T_PROGRESS.md` for the exact scope, constraints, and startup checklist. `@docs/HANDOFF_1S_COMPLETE.md` remains the closure handoff for 1S; `@docs/HANDOFF_1R_COMPLETE.md` remains useful for pre-1S historical context only.
