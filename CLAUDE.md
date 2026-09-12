# CLAUDE.md

Stable rules for working on LocalVault. This file intentionally does not contain history, checkpoint detail, or roadmap content — those live in the linked docs below. Read the relevant file with an explicit `@` reference before starting a task; do not rely on conversation memory across sessions.

## Required reading by task type

- Starting any task: `@docs/PROJECT_STATUS.md` (current branch/HEAD, what's done, what's next)
- Planning new work / sequencing stages: `@docs/ROADMAP.md`
- Touching module boundaries, crate structure, or mobile/sync prep: `@docs/ARCHITECTURE.md`
- Touching crypto, clipboard, lock behavior, TOTP, or anything secret-handling: `@docs/SECURITY_MODEL.md`
- Resuming after the 1R TOTP milestone / starting 1S: `@docs/HANDOFF_1R_COMPLETE.md`

## What LocalVault is

A local-first encrypted password manager. Frontend: Tauri 2 + React + TypeScript. Backend/security core: Rust. Currently Windows desktop only; Android and encrypted multi-device synchronization are planned (see ROADMAP.md). The existing `v1.0.0` Windows release (`D:\LocalVault_Release\LocalVault.exe`, tag `v1.0.0`, commit `04b6220`) must never be overwritten or rewritten by redesign work.

## Non-negotiable security rules

- Never weaken cryptography for convenience; never invent custom cryptographic primitives.
- Vault cryptography stays in Rust. Never move encryption, key handling, or KDF logic into React/TypeScript.
- Never store the master password. Never store TOTP setup secrets in React state. Never persist generated TOTP codes.
- Never add a network dependency to vault or TOTP code paths. The only sanctioned network exception is the favicon fetcher, and it must stay narrowly scoped.
- Never silently change the vault format or schema compatibility. Migrations must be explicit and backward-compatible where documented.
- Never expose secret-bearing errors to the frontend.
- Fail closed on external vault-file changes or unexpected state.
- Full detail: `@docs/SECURITY_MODEL.md`.

## Platform / core separation rule

LocalVault must not duplicate vault cryptography per platform. The target architecture is a shared `localvault-core` Rust library holding vault format, encryption, KDF, data model, migrations, password health, and TOTP, with thin platform adapters (Tauri/desktop, Android) handling only OS-specific concerns (clipboard, filesystem/dialogs, biometrics, autofill, camera, secure storage). Do not add platform-specific code to shared logic, and do not add core logic to an adapter. Full detail: `@docs/ARCHITECTURE.md`.

## Dependencies

Do not add a dependency without explaining why it's necessary. Prefer existing, widely audited crates over new/obscure ones, especially for anything crypto-adjacent.

## Git / task workflow

- Every implementation task starts with: `git branch --show-current`, `git rev-parse HEAD`, `git status --porcelain=v1 -uall`. Confirm these match expectations before making changes.
- Keep the staging area empty until implementation and tests are accepted.
- Do not commit unless explicitly requested. Do not push, ever, unless explicitly requested. Do not create tags or releases unless explicitly requested.
- For high-risk or architectural work: audit first, design second, implementation third. Don't jump straight to a large refactor.
- Don't mix unrelated features in one task/commit.
- Prefer small, reviewable steps.

## Test / gate requirements

Before considering implementation work done, run as appropriate:

```
npm run build
cargo fmt --check
cargo test --lib
cargo clippy --all-targets --all-features -- -D warnings
cargo check
cargo check --release
git diff --check
git status --porcelain=v1 -uall
```

For documentation-only work: skip the full build/test gate, just run `git diff --check` and show the exact changed-file scope.

## PowerShell / patching notes

Development happens from Windows PowerShell. When patching files programmatically: inspect exact markers first, transform in memory, validate before writing, write UTF-8 without BOM, preserve trailing newline. If a script fails before the write stage, no files changed — say so plainly. If it fails after writing, inspect current state and do a targeted recovery rather than blindly rerunning. Use `git status --porcelain=v1 -uall` to detect untracked files — `git diff --stat` will not show them. Cargo may be missing from a stale shell's PATH; use `$env:USERPROFILE\.cargo\bin\cargo.exe` explicitly if needed.
