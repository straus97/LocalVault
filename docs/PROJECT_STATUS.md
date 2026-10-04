# Project Status

Authoritative as of the 1T-B5c-2 checkpoint (`4d75bb8`) plus the two B5 correctness follow-up fixes (`cfe9e6f`, `d1a85e4`), evaluated against repository state `d1a85e4`. Update this file when the active stage, branch, or implementation checkpoint changes — do not let it drift. For full detail on the current 1T (Android) effort, read `@docs/HANDOFF_1T_PROGRESS.md` alongside this file.

## Branch / implementation checkpoint

- Repository: https://github.com/straus97/LocalVault
- Current development branch: `redesign/light-ui-v1.1`
- Current implementation checkpoint (production/core code, all platforms): `d1a85e44a0e45fddc7973ed88cb36ae034dea050` — `fix: refresh Android entry cache after stale completion`, preceded by `cfe9e6f24be55e3ebc6889f209f7141db22938b4` — `fix: discard Android staged save after write failure`. These are the two B5 correctness follow-ups (not a new named stage); the last named Android stage checkpoint remains `4d75bb81042dfcf339073240472b2129265f23e1` — `feat: add Android TOTP management UI (1T-B5c-2)`, which completes 1T-B5c.
- Android checkpoints on this branch, in order: `b72f95d` (1T-B1b, Rust/UniFFI/JNA bridge + real-device proof), `3d1a83d` (1T-B2, open/unlock/list real vaults), `fad2746` (1T-B3, usable reader: search/detail/clipboard/localization), `4a42ffc` (1T-B4, categories + TOTP), then the 1T-B5 write/CRUD series: `1abf5e4` (B5a), `5c20513` (B5b-1), `3ebbed5` (B5b-2), `60e26c4` (B5b-3), `18a0034` (B5b-4), `32a0754` (B5b-5), `0224fee` (B5b-6 hardening), `9f8f6411f2dd0303458bb541c8a0a401c5f813ce` (B5c-1), `4d75bb81042dfcf339073240472b2129265f23e1` (B5c-2); followed by two unnamed B5 correctness fixes, `cfe9e6f` and `d1a85e4` (see 1T below). 1T-B1a (toolchain/environment proof) produced no commit — see `@docs/HANDOFF_1T_PROGRESS.md` §7.
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

**1T is not complete.** Android is now a usable **read/write** LocalVault client: B1b–B4 delivered the read-only client, and the B5 series (through B5c, complete) added transactional SAF saving, vault creation, entry/category CRUD and TOTP set/replace/remove. See `@docs/HANDOFF_1T_PROGRESS.md` for full detail; only a summary is kept here.

- **1T-B1a** — read-only toolchain/environment proof (no commit): installed and pinned the Android Rust target (`aarch64-linux-android`), NDK `27.2.12479018` (r27c), and `cargo-ndk`; confirmed unmodified `localvault-core` checks and builds for Android ARM64.
- **1T-B1b** — `b72f95d`: first Android architecture proof — native Kotlin UI → stable UniFFI `=0.32.0` Kotlin/JNA bindings → new `crates/localvault-android-bridge` → `localvault-core`, exercised end to end (positive and negative auth paths) against the committed compat fixture on a real device, with no secret logcat leakage.
- **1T-B2** — `3d1a83d`: real vertical slice — SAF `ACTION_OPEN_DOCUMENT` vault selection, real master-password unlock through a Rust-owned `VaultSession`, real entry list, explicit lock, immediate lock on backgrounding. Read-only.
- **1T-B3** — `fad2746`: usable reader — Russian + English UI, recent-vault history (persisted read-only URI grants, non-secret metadata only), search, entry detail, password show/hide, username/password copy through a protected, ownership-verified Android clipboard, debug-screenshots-allowed/non-debug-`FLAG_SECURE` policy. Manually QA'd on a real device.
- **1T-B4** — `4a42ffc`: category browsing/filtering, TOTP display with live local rotation/countdown (smooth `ValueAnimator`-based progress, no per-frame regeneration) and copy, TOTP generated by `localvault-core` only. Manually QA'd on a real device.
- **1T-B5a** — `1abf5e4`: transactional SAF save infrastructure (write-capability/save coordinator, recovery snapshot/marker, unlock-time reconciliation).
- **1T-B5b-1 … B5b-6** — `5c20513` (category CRUD + entry create/delete mutations in the bridge), `3ebbed5` (generalized save coordinator), `60e26c4` (vault creation flow), `18a0034` (entry CRUD UI), `32a0754` (category CRUD UI), `0224fee` (save-recovery hardening; closes B5b-6). Per-step detail is in the commit history; it was not previously recorded in these docs.
- **1T-B5c (COMPLETE)** — TOTP set/replace/remove on Android:
  - **B5c-1** — `9f8f6411f2dd0303458bb541c8a0a401c5f813ce`: Rust/UniFFI TOTP mutation API (`stage_set_entry_totp`, `stage_remove_entry_totp`) plus thin Kotlin `VaultSaveCoordinator` wrappers (`saveSetEntryTotp`, `saveRemoveEntryTotp`) on the same transactional SAF save pipeline.
  - **B5c-2** — `4d75bb81042dfcf339073240472b2129265f23e1`: Android TOTP management UI (dedicated TOTP setup screen entered from detail; set / replace / remove with explicit remove confirmation) and real-device acceptance. Source scope was four files (`MainActivity.kt`, EN/RU `strings.xml`, new `TotpMutationUiTest.kt`).
  - Not part of B5c: QR setup/scanning (deferred to 1W); create-with-TOTP (deliberately not added — create the entry first, then configure TOTP from detail).
  - Full detail: `@docs/HANDOFF_1T_PROGRESS.md` §31.
- **B5 correctness follow-ups (both CLOSED; not a new named stage):**
  - **Staged candidate after `WriteFailed`** — `cfe9e6f24be55e3ebc6889f209f7141db22938b4`: `VaultSaveCoordinator` now discards the Rust staged candidate before returning `WriteFailed` on any of the three failed/unverified primary-write paths (write throws; readback throws; readback bytes differ from staged bytes). The recovery marker and encrypted pre-write snapshot are untouched, `baselineSha256` is not advanced, and no new lock is introduced; a retry is still guarded by stale check #1 (if the failed write changed the primary, the retry returns `ChangedExternally` and recovery state stays available for reconciliation). Only `IllegalStateException` (concurrent-close race) is swallowed; other bridge failures propagate. No Rust production code changed; one Rust regression test was added.
  - **Cache refresh after stale entry completion** — `d1a85e44a0e45fddc7973ed88cb36ae034dea050`: `finishEntrySave`/`finishEntryDelete` now receive the mutation's owning `VaultSaveCoordinator` and, on a successful completion, refresh the session-derived Kotlin caches whenever that coordinator is still the live `saveCoordinator`, even if the UI generation went stale. A stale completion redraws only LIST, CATEGORY_MANAGE, or DETAIL for the same existing mutated entry; it never redraws ENTRY_EDIT or TOTP_SETUP and does not clear edit state, overwrite status, toast, or wipe newer input. `ChangedExternally` (entry save/delete and, with the same gate, `finishCategoryMutation`) locks only if the Activity is alive and the coordinator still owns the live session, so a callback from a replaced/closed coordinator cannot lock a newer session. TOTP already followed this ownership pattern.
  - No real-device QA was required for either fix; the stale-completion race was covered by JVM tests only and was not reproduced on a device, and `ProviderNotWritable` was not re-tested on a device.
- **Remaining before 1T can close:** `applicationId`/package cleanup (`com.localvault.android.proof`), site/profile grouping decision (Android vs. desktop UX model), large-vault list performance measurement/optimization, the release `panic = "abort"` blocker, known visual polish (including the DETAIL top-action overflow/cutoff), and the final Android security/UX/regression pass (see `@docs/HANDOFF_1T_PROGRESS.md` §20–22). A later dedicated desktop + Android design/UX pass is still planned; the current UI is not considered final. **Do not treat 1T as done.**

## Test / gate status

**Android, at the B5 correctness follow-up commits:**
- `cfe9e6f` (staged discard after `WriteFailed`): `localvault-android-bridge` 78 tests PASS; desktop `localvault` lib: 178 tests PASS; full Android JVM suite PASS (`VaultSaveCoordinatorTest` ran 44 tests); `cargo fmt --check` PASS; `cargo clippy --all-targets --all-features -- -D warnings` PASS for workspace targets; targeted `cargo check -p localvault-android-bridge` and `cargo clippy -p localvault-android-bridge --all-targets --all-features -- -D warnings` PASS; `cargo check` and `cargo check --release` PASS; full `android/scripts/build-android-debug.ps1` PASS; `git diff --check` PASS; immutable Windows `v1.0.0` executables unchanged.
- `d1a85e4` (cache refresh after stale entry completion): `EntryMutationStaleCompletionTest` 18 tests PASS; `CategoryMutationRedrawTest` 4 tests PASS; `TotpMutationUiTest` 17 tests PASS; full Android JVM suite 145 tests PASS (0 failures/errors/skips); full `android/scripts/build-android-debug.ps1` PASS; `git diff --check` PASS; immutable Windows `v1.0.0` executables unchanged.
- No real-device QA was required for either fix. The stale-completion race was not reproduced on a device, and `ProviderNotWritable` was not re-tested on a device.

**Android, at the 1T-B5c checkpoints:**
- B5c-1 (`9f8f641`): `localvault-android-bridge` 77 tests PASS; desktop `localvault` lib: 178 tests PASS; clippy / `cargo check` / `cargo check --release` PASS; schema 1 → 2 TOTP mutation path covered; coordinator tests cover success, validation errors, `ProviderNotWritable`, stale-check #1/#2, snapshot failure, write failure and readback failure; immutable Windows `v1.0.0` executables unchanged.
- B5c-2 (`4d75bb8`): Android debug build PASS; UniFFI generation PASS; targeted `TotpMutationUiTest` PASS; full Android JVM suite PASS; immutable `v1.0.0` executables unchanged.
- Real-device QA (Android 16 / SDK 36): see `@docs/HANDOFF_1T_PROGRESS.md` §31. `ProviderNotWritable` was not re-tested on a device for B5c — that SAF path was proven in B5b device QA and the B5c wrappers inherit it (covered by coordinator tests).

**Android bridge, at the earlier 1T-B4 checkpoint (`4a42ffc`):** `localvault-android-bridge` 24 tests PASS; strict clippy PASS; Android debug build PASS (no compatibility fixture bundled in the APK).

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

**1T (Android mobile MVP) is in progress, not complete.** B1a through B4 delivered a read-only client; the B5 write/CRUD series is now complete through **B5c** (`4d75bb8`), so Android can create vaults, save safely through SAF, mutate entries/categories, and set/replace/remove TOTP. The two B5 correctness follow-ups (`cfe9e6f`, `d1a85e4`) are also closed. **There is no further named 1T-B stage in the roadmap.** The next 1T task is chosen from the remaining-work list above (`applicationId`/package cleanup, grouping decision, large-vault optimization, release `panic = "abort"` blocker, known Android visual polish including the DETAIL top-action overflow/cutoff, then the final Android security/UX/regression pass). A later dedicated desktop + Android design/UX pass is still planned, not yet implemented; the current UI is not considered final. Confirm the choice with the user at the start of the next session. Sync (1U/1V) and QR/biometrics/Autofill (1W) stay out of 1T. `@docs/HANDOFF_1S_COMPLETE.md` remains the closure handoff for 1S; `@docs/HANDOFF_1R_COMPLETE.md` remains useful for pre-1S historical context only.
