# Project Status

Authoritative as of the 1R (local TOTP) checkpoint. Update this file whenever a checkpoint, branch, or HEAD changes — do not let it drift.

## Branch / HEAD

- Repository: https://github.com/straus97/LocalVault
- Current development branch: `redesign/light-ui-v1.1`
- Current authoritative HEAD: `47c23158591218131c97d3ab27940cddd5b731c9` — `feat: add local TOTP authentication UI`
- Previous commit: `af1b2e657438e94830a941f07ff375103cd65c46` — `feat: add local TOTP authentication backend`
- Working tree at the 1R checkpoint: clean
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

## Test / gate status (at 1R checkpoint)

- Frontend production build: PASS
- Rust tests: 222 PASS
- Strict clippy (`-D warnings`): PASS
- `cargo check`: PASS
- `cargo check --release`: PASS
- Manual TOTP QA: PASS
- Working tree: CLEAN

## Vault schema

- Current schema: 2
- Legacy readable schema: 1
- Schema 1 remains readable only if it contains no TOTP; it cannot carry a TOTP secret.
- Schema 2 supports encrypted TOTP configuration.
- Writes upgrade legacy schema 1 vaults to schema 2.

## Immediate next phase

**1S — Multi-platform core preparation**, starting with **1S-A: architecture audit** (audit/design only, no large refactor yet). See `@docs/ROADMAP.md` for full scope and `@docs/ARCHITECTURE.md` for the target module boundary. See `@docs/HANDOFF_1R_COMPLETE.md` for the exact handoff state and audit checklist for 1S-A.
