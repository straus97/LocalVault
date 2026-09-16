# Roadmap

Stages 1S through 1X. Each stage depends on the prior stage's exit criteria being met — do not skip ahead or parallelize stages that share a dependency below.

## 1S — Multi-platform core preparation (COMPLETE)

**Goal:** prepare LocalVault's architecture for Windows + Android before any mobile UI work begins.

**First substage (required, blocking): 1S-A — architecture audit.** Audit and design only — do not perform a large refactor as part of 1S-A.

1S-A must audit:
- `src-tauri` module boundaries
- vault core dependencies
- `AppState` dependencies
- Tauri-specific dependencies
- Windows-only dependencies
- clipboard boundary
- filesystem boundary
- timing/clock dependencies
- favicon network boundary
- backup/restore boundary
- password-health placement
- TOTP placement
- potential reusable crate boundary
- current tests and what can move with the core
- mobile constraints
- future sync constraints

Output of 1S-A was a low-risk extraction plan for the reusable Rust crate/library now established as `localvault-core`. 1S must also prepare for future sync metadata but must **not** implement synchronization prematurely.

**Depends on:** 1R (complete). **Stage status:** 1S complete; 1T is next and has not started.

**Progress (extraction checkpoints, in order):** `localvault-core` exists as a workspace member (`bcdb1ad` compatibility safety net, `07e15fd` workspace skeleton), and three low-risk mechanical extractions have landed into it: crypto primitives + vault envelope/format (1S-C1, `4721b05`), the persisted vault domain/data model (1S-C2, `bfd7fec`), and the TOTP RFC 6238 parser/generator (1S-C3, `8f0d5a3`). These are ownership/module-boundary moves only, with no cryptographic or behavioral changes. A subsequent remaining-work audit (performed at `962f2a7`) re-verified the full 1S-A checklist above — including `AppState` dependencies, filesystem boundary, mobile constraints, and future sync constraints — against the post-extraction state, and found no blocker to starting 1T. **Stage 1S is complete.** Password-health placement and password-generator placement remain undecided long-term architecture questions, but neither is a 1T prerequisite: both are pure, low-coupling modules the audit found extractable later without schema/crypto risk if and when Android actually needs them. See `@docs/HANDOFF_1S_COMPLETE.md` for the closure handoff. 1T has not started.

## 1T — Android mobile MVP

Android is the first and only planned mobile implementation.

Scope:
- create/open vault
- unlock/lock
- list/search entries
- display username/password
- protected copy
- categories
- site profiles
- TOTP display
- local TOTP rotation
- basic mobile UX

**Depends on:** 1S (complete — see the 1S section above and `@docs/HANDOFF_1S_COMPLETE.md`).

## 1U — Sync foundation

Design and implement:
- provider abstraction
- encrypted sync state
- revision semantics
- conflict detection
- offline-first workflow
- safe atomic updates
- recovery path

A paid LocalVault-owned server is **not** required for the first sync implementation. Preferred initial direction: an existing storage/sync provider or a generic provider abstraction, transporting only encrypted LocalVault state. Provider candidates (WebDAV, existing user cloud storage, OS-synchronized folder, provider APIs) should be evaluated at this stage rather than hard-coded earlier. Do not implement naive "last writer silently overwrites everything" sync. A custom zero-knowledge LocalVault sync service may be considered later but is not required for the first mobile/sync milestone.

**Depends on:** 1S core extraction (sync metadata needs a stable core data model) and benefits from 1T existing (a second real platform to validate sync against), though sync design work can start once the core is stable.

## 1V — Multi-device sync hardening

- multiple devices
- concurrent edits
- conflict UX
- interrupted sync
- stale copies
- corruption handling
- rollback/recovery
- backup interaction

**Depends on:** 1U sync foundation.

## 1W — Android security / UX

- TOTP QR scanning
- biometric unlock where platform security permits
- Android Autofill
- Android secure clipboard behavior
- Android secure-storage integration where justified for approved convenience-unlock mechanisms

**Depends on:** 1T (Android MVP).

## 1X — Final product hardening / release

- full migration matrix
- corrupted vault tests
- backwards compatibility tests
- release builds
- packaging/signing
- threat model documentation
- end-user documentation
- Windows v1.1/v2 release
- Android release

**Depends on:** all prior stages relevant to the platforms being released.

## Cross-cutting constraints (apply to every stage above)

- Do not duplicate vault cryptography independently per platform — see `@docs/ARCHITECTURE.md`.
- Do not weaken crypto, invent primitives, or move crypto into non-Rust code.
- Do not implement sync before its documented prerequisites (stable vault identity, revision/version semantics, device identity where required, conflict detection, atomic update rules, offline-first behavior, recovery strategy, backup interaction, migration/version compatibility) are defined.
- See `@docs/SECURITY_MODEL.md` for security invariants that must hold across mobile and sync work.
