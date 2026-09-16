# Project Status

Authoritative as of Stage 1S closure (1S remaining-work audit, evaluated against repository state `962f2a7`). Update this file when the active stage, branch, or implementation checkpoint changes — do not let it drift.

## Branch / implementation checkpoint

- Repository: https://github.com/straus97/LocalVault
- Current development branch: `redesign/light-ui-v1.1`
- Current implementation checkpoint (production/core code): `8f0d5a36c73cc8d7bbee936f6df6a55bd1533aff` — `refactor: extract TOTP module into core` (1S-C3, the last checkpoint that touched `localvault-core` or `src-tauri` source)
- Documentation/audit baseline: `962f2a7` — `docs: record completed core extraction checkpoints`. The 1S remaining-work audit was performed against this repository state and concluded Stage 1S is complete (decision A — close 1S now). The closure-documentation commit hash is intentionally not embedded in this file; obtain it from `git log` after the commit lands.
- Preceding checkpoints on this branch: `bfd7fec` (extract persisted vault data into core, 1S-C2), `4721b05` (extract crypto and vault format into core, 1S-C1), `07e15fd` (add LocalVault core workspace skeleton), `bcdb1ad` (add pre-extraction compatibility safety net, 1S-B1), `c5eb5e6` (record 1R completion and Android roadmap), `47c2315` (1R frontend), `af1b2e6` (1R backend)
- Working tree at this checkpoint: clean
- Nothing here should be assumed pushed unless `git status`/`git log` against the remote explicitly confirms it.

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
- **1T (Android) has not started.**

## Test / gate status (at the 1S-C3 checkpoint)

- Frontend production build: PASS
- Rust tests: 228 PASS (`localvault-core` lib 43, `localvault` lib 178, `compat_baseline` 6, `data_storage_integration` 1)
- Strict clippy (`-D warnings`, workspace): PASS
- `cargo check` / `cargo check --release` (workspace): PASS
- Working tree: CLEAN

## Vault schema

- Current schema: 2
- Legacy readable schema: 1
- Schema 1 remains readable only if it contains no TOTP; it cannot carry a TOTP secret.
- Schema 2 supports encrypted TOTP configuration.
- Writes upgrade legacy schema 1 vaults to schema 2.

## Immediate next phase

**1S is complete.** Crypto/vault-format (1S-C1), persisted vault data (1S-C2), and TOTP (1S-C3) are extracted into `localvault-core`, and the 1S remaining-work audit confirmed no further extraction is required before Android work begins. Password-health placement and password-generator placement remain deferred, non-blocking long-term questions — see `@docs/ARCHITECTURE.md` for the current (not merely target) module boundary.

**Next stage: 1T — Android mobile MVP architecture/bootstrap.** 1T has **not** started; no Android project, language/FFI binding (Kotlin/JNI/UniFFI), Tauri-Mobile-vs-native choice, or Android filesystem/secure-storage design exists yet. See `@docs/ROADMAP.md` for 1T scope and `@docs/HANDOFF_1S_COMPLETE.md` for the closure handoff a fresh 1T planning session should start from. `@docs/HANDOFF_1R_COMPLETE.md` remains useful for pre-1S historical context only.
