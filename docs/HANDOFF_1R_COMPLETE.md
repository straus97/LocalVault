# Handoff: 1R Complete (Local TOTP / 2FA)

This document is the authoritative handoff for a fresh engineer, fresh Claude Code session, or fresh ChatGPT conversation picking up work right after 1R. Read `@docs/PROJECT_STATUS.md` and `@docs/ROADMAP.md` alongside this file.

## Checkpoint identity

- Branch: `redesign/light-ui-v1.1`
- Backend commit: `af1b2e657438e94830a941f07ff375103cd65c46` — `feat: add local TOTP authentication backend`
- Frontend commit (current HEAD): `47c23158591218131c97d3ab27940cddd5b731c9` — `feat: add local TOTP authentication UI`
- Working tree at this checkpoint: clean

## What 1R delivered

Local TOTP (RFC 6238) two-factor code generation and setup, fully offline:

- Algorithms: SHA1, SHA256, SHA512
- Digit lengths: 6 or 8
- Configurable period, up to 300 seconds
- Defaults: SHA1 / 6 digits / 30 seconds
- Setup via bare Base32 secret or `otpauth://totp/...` URI
- HOTP explicitly rejected
- QR scanning intentionally deferred to 1W (needs camera access, a platform-adapter concern)

Security properties delivered (full detail in `@docs/SECURITY_MODEL.md`):
- TOTP generation is entirely local; no TOTP network path.
- Setup secret stored only in the encrypted vault payload.
- Raw TOTP secret is not returned to the frontend after save.
- Generated TOTP code is not persisted.
- Protected clipboard computes/copies the code in Rust.
- Passive code refresh does not extend the inactivity auto-lock; explicit copy does count as activity.
- Frontend clears derived TOTP state on secret-view close, selection change, or lock.
- Setup input kept outside React state; DOM value cleared before awaiting IPC where practical.

Vault schema:
- Bumped to schema 2 (from schema 1) to support encrypted TOTP configuration.
- Schema 1 remains readable only if it carries no TOTP secret.
- Writes to a legacy schema 1 vault upgrade it to schema 2.

## Final gate results (all PASS at this checkpoint)

- Frontend production build: PASS
- Rust tests: 222 PASS
- Strict clippy (`-D warnings`): PASS
- `cargo check`: PASS
- `cargo check --release`: PASS
- Manual TOTP QA: PASS
- Working tree: CLEAN

## Do not confuse with the v1.0.0 release

The shipped Windows release (`D:\LocalVault_Release\LocalVault.exe`, tag `v1.0.0`, source commit `04b6220d96599b96b68135054994b0bc731aa9e4`, SHA256 `A5707B9901607BD61D7881734478D5D5A2FB3D9CE965D41B7D9863ABF256C481`) predates all of 1N–1R and must never be overwritten by this branch's work. 1R and everything after it targets a future v1.1+ release.

## Next task: 1S-A (architecture audit)

The next stage is **1S — multi-platform core preparation**, and it must start with **1S-A: architecture audit** — audit and design only, no large refactor yet. Full checklist in `@docs/ROADMAP.md`; target boundary described in `@docs/ARCHITECTURE.md`.

Before starting 1S-A, a fresh session should:
1. Run `git branch --show-current`, `git rev-parse HEAD`, `git status --porcelain=v1 -uall` and confirm they match this document's "Checkpoint identity" section (or `@docs/PROJECT_STATUS.md` if it has since been updated with a newer checkpoint).
2. Read `@CLAUDE.md` for the non-negotiable security and workflow rules that apply to all further work.
3. Treat 1S-A as audit/design output (a proposed extraction plan), not code changes to `src-tauri`.

## Known open questions carried into 1S

- The `localvault-core` crate name is a working name only — 1S-A must check repository/crate-registry conventions before finalizing it (see `@docs/ARCHITECTURE.md`).
- Sync direction (1U) intentionally avoids requiring a paid LocalVault-owned server; provider choice (WebDAV, existing cloud storage, OS-synced folder, provider APIs) is deferred until 1U and must not be hard-coded during 1S.
- QR scanning for TOTP setup remains deferred to 1W and is out of scope until then.
