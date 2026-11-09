# LocalVault 1U Handoff (sync foundation, in progress)

## 0. How to use this file

Self-contained handoff for a **new ChatGPT or Claude conversation**. It is a living document: each major 1U milestone must update it (and `@docs/PROJECT_STATUS.md`) as part of its closure. Git history and current source are the authority; where this file disagrees with `git log` or the code, Git and the code win, and the discrepancy should be reported.

- Source baseline audited for 1U-DOCSYNC: `4dd1ba639c9e80ee9e690f1e10c6bc6cf9821626` (`fix(desktop): exclude unsafe legacy sync-state replace from production`, branch `redesign/light-ui-v1.1`).
- This is **not** a statement of the current HEAD. A docs-only commit on top of that baseline will have a different hash, and a stored hash is never proof that the worktree is unchanged. Always run `git rev-parse HEAD` and `git status --porcelain=v1 -uall` (section 17).
- Evidence classes used below: **SOURCE** (checked against the code at the baseline), **GIT** (checked against commit history), **REPORTED** (stated by the user or an implementing session, not re-verified here), **UNRESOLVED** (no evidence available in the repository).
- Related canonical documents: `@docs/PROJECT_STATUS.md` (checkpoints), `@docs/ROADMAP.md` (sequencing), `@docs/ARCHITECTURE.md` (boundaries and format versions), `@docs/SECURITY_MODEL.md` (guarantees, limits, gate and decision registry). Historical, not a starting point: `@docs/HANDOFF_1T_COMPLETE.md` (Android 1T closeout), `@docs/HANDOFF_1T_PROGRESS.md`, `@docs/HANDOFF_1S_COMPLETE.md`, `@docs/HANDOFF_1R_COMPLETE.md`.

## 1. Project purpose and scope

LocalVault is a local-first encrypted password manager. Frontend: Tauri 2 + React + TypeScript (`src/`). Security core and adapters: Rust. Windows desktop is the primary client; an Android client exists as a debug-signed engineering milestone (1T, not a release). **Synchronization does not exist.** There is no transport, provider, push, pull, adoption, publication or automatic sync. Stage order: 1U sync foundation (in progress) -> 1V multi-device hardening -> 1W Android QR/biometrics/Autofill -> 1X release. Details: `@docs/ROADMAP.md`.

## 2. Repository, branch, baseline

- Repository `D:\LocalVault` (remote `https://github.com/straus97/LocalVault`), branch `redesign/light-ui-v1.1`, base branch `main`.
- The shipped Windows `v1.0.0` (tag `v1.0.0`, source commit `04b6220`) is immutable and separate from this branch; see section 14.
- Application version strings (`package.json`, `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`) are still `1.0.0`; release versioning belongs to 1X. (SOURCE)

## 3. Source map

| Path | Role |
|---|---|
| `crates/localvault-core/src/` | Platform-neutral Rust core: `crypto/` (private: KDF, AEAD, `state_mac.rs` HKDF/HMAC for sync-state records), `vault/format.rs`, `vault/data.rs` (schema 3 + revision), `sync.rs` (fingerprints, classifier, authenticated inspection), `sync_state.rs` (sync-state model, codecs v1-v4, pure transitions), `site.rs`, `totp.rs`. No I/O in `sync*`. |
| `src-tauri/src/vault/` | Windows adapter: `session.rs` and `session/` (unlocked session, approvals, B2 copy creation, dormant B3 assessments), `sync_state_store.rs` (device-local record store), `sync_file_adapter.rs`, `file_identity.rs`, `handle_ops.rs`, `held_removal.rs`, `new_copy_file.rs`, `target_exchange.rs` (dormant), and test-only `legacy_record_exchange.rs`, `legacy_layout_assessment.rs`. |
| `src-tauri/src/commands/` | Tauri command glue. Sync-related: `sync_binding.rs` (7 commands), `copy_creation.rs` (3 commands). Registered in `src-tauri/src/lib.rs`. |
| `src/` | React UI. Sync-related: `SyncBindingDialog.tsx`, `CopyCreationFlow.tsx`. |
| `crates/localvault-android-bridge/`, `android/` | Android adapter (UniFFI/Kotlin). Not touched by 1U sync slices. |
| `src-tauri/tests/` | `compat_baseline.rs` (11 tests, committed schema-1/2 fixtures), `data_storage_integration.rs`. |

## 4. What works today (production-reachable)

- All pre-1U features: encrypted vaults, entries, categories, sites/profiles, favicon cache (the only sanctioned network path), password health, TOTP, backups, protected clipboard, auto-lock; Android read/write client. (`@docs/PROJECT_STATUS.md`)
- Vault schema 3 with an authenticated `revision: u64` (1U-2); legacy schemas 1/2 readable, migrated only by a committed write.
- **Windows "Связь с копией" dialog, ten registered commands, exactly three user actions:**
  1. Bind an **existing** byte-identical encrypted copy (one-time Rust-owned approval, 120 s).
  2. Show binding status and perform a **local** reset of the binding (removes only the device-local record; handle-bound since B3c-3b-2d-1).
  3. Create one **new, separate** encrypted copy on local NTFS (no replace, handle-bound publication, exact-byte verification). Creating a copy never binds it.
- Legacy (v1) sync-state store behaviours reachable through those actions: `load`, `create` (initial binding), evidence capture and handle-bound `delete`; all guarded by the refuse-only compatibility gate. (SOURCE)
- None of these synchronizes, uploads, publishes or updates an already bound target. A copy in a synchronized folder is only a local file.

## 5. Milestone history (commit references)

Slices B1-B2 and the earlier stages are listed in `@docs/PROJECT_STATUS.md`. Slices after B2c, in commit order (GIT, with module headers SOURCE-checked):

| Slice | Commit | What it is | Reachability |
|---|---|---|---|
| B2 close (docs) | `0cc28bf` | Closed B2; architecture docs. | docs |
| B3a | `59c9914` | Read-only "would an update be allowed" diagnostic (`session/target_update.rs`, `AppState::assess_bound_target_update`). Not an authorization. | Compiled, no command or UI caller; exercised by tests only. |
| B3b-1 | `e72f927` | Held-handle NTFS exchange experiment (`target_exchange.rs`): old file renamed aside, new file renamed in, never replace. | Compiled as dead code (`allow(dead_code)`), unreachable; a test scans for references. |
| B3b-2p | `ad74542` | Guarded NTFS directory identity (`file_identity.rs`). | Internal helper. |
| B3b-2a | `459ebd5` | Read-only interrupted-exchange classifier (`session/exchange_recovery.rs`). | Compiled, no caller. Grants no recovery authority. |
| B3c-1 | `505d221` | Dormant sync-state **v2** (exchange record) codec in core. | No caller. |
| B3c-2a | `691d3f9` | Dormant authenticated sync-state **v3** codec (HMAC-SHA256 under an HKDF key derived from the Vault Key). Adds the `hkdf` crate (`=0.12.4`) to core. | No caller. |
| B3c-2 | `5e1c165` | Dormant pure exchange transitions (`begin_exchange`, `finalize_exchange`, `clear_exchange`). | No caller. |
| B3c-3a | `69be22e` | Dormant authenticated v3 loading (`session/authenticated_state.rs`, read-only). | No command caller. |
| B3c-3b-1 | `ce81aac` | Dormant v3 artifact/layout diagnostic (`inspect_v3_layout`, `assess_authenticated_sync_state`). | No production caller. |
| B3c-3b-2a | `f074991` | **Legacy compatibility gate**: the v1 store refuses when newer-state evidence sits beside the record. Adds fixed UI status text. | **Production-reachable** (refuse-only). |
| B3c-3b-2d-1 | `24fc685` | **Handle-bound legacy reset** (`held_removal.rs`); closes G12-reset in code. | **Production-reachable**. |
| G12-reset tests | `61decb7` | Session-level refusal tests for external hard links. | Tests. |
| G12R-1 | `ee87f0a` | Held-handle legacy v1 record **exchange** experiment (`legacy_record_exchange.rs`). | `cfg(all(test, windows))` only. |
| G12R-R1 | `f592e61` | Read-only interrupted-layout classifier (`legacy_layout_assessment.rs`). | `cfg(all(test, windows))` only. |
| G2-P1 | `a962da3` | Dormant authenticated sync-state **v4** succession codec in core. | No caller. |
| D4 | `4dd1ba6` | Legacy `SyncStateStore::replace` and its dependent wrappers excluded from non-test builds. | Production mutation authority removed. |

## 6. Dormant and test-only components

- **Dormant but compiled** into normal builds (no caller; cannot be reached from a command or the UI): B3a assessment, B3b-1 exchange experiment, B3b-2a classifier, core codecs v2/v3/v4 and exchange transitions, authenticated v3 loader/diagnostic. Being compiled does not mean being enabled. Do not wire any of them to a command without an approved slice.
- **Test-only (`cfg(test)`, not in normal or release builds):** the legacy `SyncStateStore::replace` (and `check_replacement`, and the wrappers `record_remote_observation` / `observe_remote_target` in the session and `AppState`, plus the dependent file-adapter observation path, per D4), `legacy_record_exchange.rs` (G12R-1), `legacy_layout_assessment.rs` (G12R-R1). They are measurements and characterizations, and authorize nothing.
- The unit test that reproduces the legacy foreign-overwrite race is **intentionally kept**; it documents the unrepaired algorithm.
- Production code must not call a dormant or test-only component without a new, explicitly approved slice. Test-only code must not be promoted by moving a `cfg` attribute.

## 7. Sync-state formats and trust boundaries

Authority: `crates/localvault-core/src/sync_state.rs`, `crypto/state_mac.rs`, `src-tauri/src/vault/sync_state_store.rs`. Format string `localvault-sync-state`, JSON wrapper, `MAX_SYNC_STATE_BYTES` 65,536. (SOURCE)

| Ver | Wire shape | Integrity | Role and reachability |
|---|---|---|---|
| 1 | `{format, version:1, body_sha256, body}` | SHA-256 checksum of the body: accidental corruption only, **not a MAC**. | The only version the production store reads and writes (device-local record `<key>.json`, plus `<key>.<32 hex>.tmp` staging names). Unauthenticated, forgeable and rollbackable by anyone who can rewrite local app data. |
| 2 | `{format, version:2, body_sha256, body}`; body adds `exchange` and `retained_previous` | Checksum only. | Dormant explicit codec (`encode_exchange_record`). `decode` and the store report it as an unsupported version; the production store neither loads nor writes it. |
| 3 | `{format, version:3, body, mac}` | HMAC-SHA256; key = HKDF-SHA256(Vault Key, info `LocalVault/sync-state-mac-key/v1`); MAC input covers domain, format, version, the **authenticated** vault id and the body, length-prefixed; verified before the body is parsed. | Dormant. Authenticity and integrity only. No production writer. |
| 4 | v3 wrapper; body adds required `succession {generation, publication_id, predecessor}`; predecessor is a genesis marker or a domain-separated SHA-256 of the **exact bytes** of the predecessor record | HMAC as v3 (version inside the MAC input). | Dormant, pure (`encode_genesis_record`, `encode_successor_record`, `SuccessionRecord::decode`, `verify_succession`). No caller. v3 stays frozen; no other decoder accepts v4. |

Authentication and authenticated predecessor succession do **not** establish: freshness, non-rollback, completed publication, user consent, physical durability, or recovery authority. A locally stored generation counter is not an independent anti-rollback anchor while all relevant local state can be replayed together. Two valid successors may name one predecessor; nothing says which was published. Anyone holding the Vault Key can forge a record, and the Vault Key is never rotated. **No production v3 or v4 writer is enabled, and none may be added without an approved decision (D9 and the gates below).**

Other trust boundaries: a local synchronized folder is not an authoritative provider; the vault `revision` is a write counter, not a freshness proof; the envelope SHA-256 proves byte identity only. Full list: `@docs/SECURITY_MODEL.md`.

## 8. Production reachability summary

Reachable: the ten commands above, the legacy v1 store (`load`, `create`, handle-bound `delete`, evidence), the compatibility gate, the read-only file adapter, B2 copy creation. **Not reachable and must stay so:** any record replacement, high-water persistence, v2/v3/v4 reading or writing, bound-target update, exchange, recovery mutation, migration, publication, push, pull, adoption, provider or network access for sync.

Still prohibited (no code, no flag, no "temporary" shortcut): overwriting a bound target; automatic recovery or cleanup of sync-state artifacts; automatic retry of an ambiguous outcome; treating a file name, hash or generation as authority; converting a legacy v1 record into trusted history.

## 9. Security guarantees (established)

All SOURCE unless marked. Detail and limits in `@docs/SECURITY_MODEL.md`.

- Vault cryptography stays in Rust; the master password is never stored; TOTP stays offline.
- Vault identity is authenticated by core (same Vault Key and vault id), never by path.
- Binding, reset and copy creation each need a Rust-owned, session-bound, one-time approval (120 s), re-validated against fresh evidence at confirmation; the frontend never supplies a path or mints an approval.
- B2 copy creation: local NTFS only, no replace, handle-bound publication, exact-byte and physical-identity verification, no sync-state change.
- Reset removes only handle-held, byte-verified files; a mark counts only if verified through the same handle (G12-reset, section 11).
- The legacy store refuses (never silently ignores) newer-state evidence; absence is `NotConfigured` only when confirmed.
- Ambiguous outcomes are reported as ambiguous and never retried automatically.
- Normal and release builds contain no sync-state record replacement (D4).

## 10. Guarantees that are NOT proven

- Anti-rollback, freshness, cloud/provider ancestry; v1 state is not tamper-proof or rollback-proof.
- Power-loss durability of any file or directory entry; crash-safe publication.
- Protection against administrators, backup-privileged processes, kernel components or filter drivers (sharing modes bind ordinary processes only).
- Filesystems other than local NTFS for creation (ReFS recognized for binding by documentation only; FAT/exFAT/SMB/virtual volumes refused, refusal not manually tested).
- Remaining TOCTOU windows around opens by path (SECURITY_MODEL).
- G12-temp (next target, section 12) is unfixed.
- Android: the six device-only fault tests in `@docs/HANDOFF_1T_COMPLETE.md` section 6 remain unverified; the SAF intermittent wrong-document refusal is unresolved.

## 11. Gates and decisions

Authoritative registry with evidence classes: `@docs/SECURITY_MODEL.md`, "Production gates and open decisions". Summary at the baseline:

| Item | Status | Class |
|---|---|---|
| G12-reset | **CLOSED** within the documented supported local Windows NTFS threat model (handle-bound code `24fc685`, hard-link tests `61decb7`, C: acceptance run). | GIT + REPORTED (acceptance evidence archive checked, section 14) |
| C: NTFS synthetic acceptance | 136 tests passed in six groups (28 + 39 + 6 + 22 + 15 + 26), 0 failed, 0 ignored. Run was at `24fc685`; the file-symlink subcases could not run (account cannot create file symlinks). | REPORTED, archive summary read |
| G12R-1 | **CLOSED** as a TEST-ONLY held-handle legacy record exchange experiment. | GIT + SOURCE |
| G12R-R1 | **CLOSED** as a TEST-ONLY read-only interrupted-layout classifier. | GIT + SOURCE |
| G12R-R2 | **NO-GO**: unauthenticated legacy v1 candidates must not be promoted to historical trusted records without independent trusted evidence. | REPORTED (analysis decision; no commit) |
| G2-P1 | **CLOSED**: dormant authenticated v4 succession codec. | GIT + SOURCE |
| G2 overall | **OPEN**. | SOURCE (module and SECURITY_MODEL text) |
| D4 | **CLOSED by compile-time exclusion**, not repair. | GIT + SOURCE |
| G12-replace | Closed for normal/release builds by exclusion; algorithm unrepaired. | SOURCE |
| G12-temp | **OPEN** (section 12). | SOURCE |
| G12 overall | **OPEN**. | SOURCE |
| G-AUTH | Unresolved (cited in `exchange_recovery.rs`; v1 records are unauthenticated). | SOURCE |
| G1, G3-G11, G13 | **NOT CLOSED.** No definition exists in the repository docs or code (code comments using "G1/G2/G3" in `legacy_layout_assessment.rs` are local classifier priorities, not production gates). Historical working descriptions from the earlier architecture reviews (REPORTED / HISTORICAL, not a verified canonical registry): G1 physical sync-state publication strategy and no-clobber protocol; G2 authentication, trust and legacy/new-format interoperability; G3 retention of previous versions; G4 user-approved authenticated creation or re-establishment; G5 physical trusted-anchor policy; G6 actual state-volume and NTFS requirements; G7 fault injection, cross-process and interruption testing; G8 security documentation; G9 missing-primary recovery; G10 historical lineage and authenticated succession; G11 older-client compatibility; G12 foreign-file race and mutation safety (reset, replace, temporary files); G13 staging namespace and artifact reservation. Existing tests, experiments or dormant code do not close any of them; the successful `C:` reset acceptance does not close G6 for production publication. Per-label table: `@docs/SECURITY_MODEL.md`. | REPORTED / HISTORICAL |

Decisions (REPORTED / HISTORICAL: the repository defines no D1-D9 list and records no decision dates or approvals; these meanings come from the architecture design reviews. D2 and D3 are kept together because their exact individual meanings could not be verified. Source comments use a different label family, `U2` and `U9`, for decisions inside slice B3c-3b-2a, plus `D4` as a slice name). None is approved by this documentation task.

| ID | Subject | State | Class |
|---|---|---|---|
| D1 | Separate v4 format | Approved; implemented dormant as G2-P1. | REPORTED + GIT |
| D2/D3 | Freshness and rollback policy | **OPEN**. | REPORTED |
| D4 | Legacy v1 replacement | Retired from normal/release builds. | GIT + SOURCE |
| D5 | Legacy migration | **OPEN**; no migration exists. | REPORTED |
| D6 | Retention policy | **OPEN**; `MAX_RETAINED_PREVIOUS = 8` is a technical bound only. | SOURCE |
| D7 | Older-client handling | **OPEN**; older binaries are not gated. | REPORTED + SOURCE |
| D8 | Recovery mutation | **OPEN**; no recovery authority exists. | REPORTED |
| D9 | Production publication | **OPEN**; nothing publishes authenticated state. | REPORTED |
| U2, U9 (source labels) | Unrecognized key-prefixed entries refuse; `.v3stage` name reserved, nothing creates it. | Implemented (refuse-only). | SOURCE |

## 12. Next development target: G12-temp

**Verified in source at the baseline (SOURCE):** `SyncStateStore::create` (`sync_state_store.rs`) calls `write_temp`, publishes with `fs::hard_link(&temp, &record)`, then removes the staging name with `let _ = fs::remove_file(&temp)`. `write_temp` itself calls `fs::remove_file(&path)` on a failed write. `create_temp` opens the staging file by path with `create_new`. `create` is reached through initial binding (`UnlockedVaultSession` initial-binding confirmation), which is a registered user action.

**The risk:** the staging pathname is checked or created, the file is later removed **by pathname**. A different process able to write the sync-state directory can swap in a foreign object between the moment our file object was verified and the moment the pathname is used for removal, so the removal can hit a file we never verified. The distinction to keep: *a file object previously verified* versus *a pathname later used for mutation*. Reset already closed the same class of problem with held handles; `create` has not.

**Task for the next stage (not authorized by 1U-DOCSYNC):** audit first, then design, then implement; investigate and eliminate these production-reachable path-based mutations, with the usual evidence (tests that reproduce the race first, then handle-bound behaviour), without changing the v1 wire format, enabling any writer of v3/v4, or repairing `replace`. G12 stays OPEN until G12-temp is closed and accepted. Other gates (G2, G-AUTH, D2-D3, D5-D9) are sequencing context, not part of this stage.

## 13. Tests and validation

Gate commands (`CLAUDE.md`): `npm run build`; `cargo fmt --check`; `cargo test --lib`; `cargo clippy --all-targets --all-features -- -D warnings`; `cargo check`; `cargo check --release`; `git diff --check`; `git status --porcelain=v1 -uall`. `cargo check --release` is allowed; `cargo build --release` is not (section 14).

Latest complete validation after D4, **REPORTED by the implementing session and the task prompt; not re-executed by 1U-DOCSYNC and not independently verified:**

| Suite | Result |
|---|---|
| `localvault-core` library | 460 passed |
| `localvault-core` doc-tests | 17 passed |
| Desktop library (`localvault_lib`) | 1147 passed, 1 ignored |
| `compat_baseline` | 11 passed |
| `data_storage_integration` | 1 passed |
| `cargo fmt --check`, `cargo clippy -D warnings`, `cargo check`, `cargo check --release`, `npm run build`, `git diff --check` | PASS |

The single ignored test is `real_process_exit_child` in `legacy_record_exchange.rs`: a controlled child-process entry point that does nothing unless a parent test spawns it with a stage selector in its environment. It is not a skipped failure. (SOURCE: `#[ignore = "REAL PROCESS EXIT child: ..."]`.)

Re-run the gates against the real HEAD before claiming anything about a later commit. Android gates are in `@docs/HANDOFF_1T_COMPLETE.md`.

## 14. Protected files and environment safety

| Artifact | Location | SHA-256 |
|---|---|---|
| Windows v1.0.0 executable (Desktop copy) | `%USERPROFILE%\Desktop\LocalVault.exe` | `A5707B9901607BD61D7881734478D5D5A2FB3D9CE965D41B7D9863ABF256C481` |
| Windows v1.0.0 executable (build output copy) | `src-tauri\target\release\LocalVault.exe` | `A5707B9901607BD61D7881734478D5D5A2FB3D9CE965D41B7D9863ABF256C481` |
| Android QA master (synthetic, 300 entries) | `.qa-local\LocalVault-Android-Smoke-300.lvault` | `96D26061A44AD53ABA883BEE113F7F4AE847D28CD4FBB50289AACC848FB388FE` |
| C: acceptance evidence archive | `%LOCALAPPDATA%\LocalVault-G12-Reset-Acceptance\g12-reset-acceptance-20261107-164813-fa4ab0cb-evidence.zip` | `B9935B2646F412574D8E2A8EE5B692FD710BAD04F323166E424989C9454A7F67` |

All four hashes were recomputed (read-only) during 1U-DOCSYNC and matched. **The two executables were not rebuilt** and are the preserved `v1.0.0` build: they do **not** contain D4, the v4 codec or any other later source change. Statements in this file that something is "excluded from normal and release builds" (D4, `cfg(test)` modules) describe the current source and build configuration only; the current development build and the preserved release executable are different artifacts. Rules:

- Never overwrite either executable. Do **not** run `cargo build --release` or `tauri build` unless a separate, explicitly approved release task requires it. `npm run tauri dev` (debug) is the way to run current source.
- Never modify, delete or regenerate the QA master, the evidence archive, or the preserved B1/B2/B3 synthetic fixtures under `.qa-local`. The Android external-change test file there is intentionally altered; never reuse it as a healthy vault.
- Never touch real user vault data during synthetic acceptance. Never terminate the user's running debug application without approval.
- Synthetic test scratch belongs under `.qa-local` (git-ignored), never `%TEMP%`.
- `D:\LocalVault_Release` (named in older documents) **does not exist**. Do not create it. The `v1.0.0` identity is the tag and the executable hashes above.
- No Android build or ADB unless the task is an Android task.
- Prefer `%USERPROFILE%`, `%LOCALAPPDATA%` and repository-relative paths in committed text. Never put passwords, keys, recovery secrets, real `.lvault` contents or tokens in docs.

## 15. Safe Git and development workflow

1. Start every implementation task with `git branch --show-current`, `git rev-parse HEAD`, `git status --porcelain=v1 -uall`; confirm they match expectations.
2. Keep staging empty until implementation and tests are accepted. No commit, push, tag or release unless explicitly requested.
3. High-risk work: audit first, design second, implement third. One concern per task and per commit. Small reviewable steps.
4. No new dependency without a written justification (the last one was `hkdf` in `691d3f9`, for the dormant MAC key derivation).
5. Never weaken cryptography, add crypto to React/TypeScript, add a network dependency to vault/TOTP/sync-state paths, change the vault format or schema silently, or expose secret-bearing errors to the frontend. Fail closed.
6. Docs-only tasks: skip the build/test gate, run `git diff --check`, and show the exact changed-file scope. Detect untracked files with `git status --porcelain=v1 -uall` (`git diff --stat` does not show them).
7. PowerShell patching: inspect markers, transform in memory, validate, write UTF-8 without BOM, keep the trailing newline. Cargo may be missing from a stale PATH; use `$env:USERPROFILE\.cargo\bin\cargo.exe`.

## 16. Restrictions on Claude Code and automated source changes

- A documentation task changes Markdown only. A source task changes only the files its scope names; no opportunistic refactors, no formatting sweeps over large files.
- Do not touch `cfg` attributes on test-only or dormant modules, the v1 wire format, `Cargo.toml`/`Cargo.lock`, or protected artifacts as a side effect.
- Do not promote a dormant or test-only component to production, and do not describe one as available. Do not mark a gate closed without evidence in Git, source or a preserved acceptance archive.
- Do not invent test results, milestones or decisions. Report uncertainty instead.
- Do not copy local planning scratch (for example under `.claude` or the session scratchpad) into the repository.

## 17. How to verify the current HEAD

```
git branch --show-current          # expect redesign/light-ui-v1.1
git rev-parse HEAD                 # compare with the audited baseline 4dd1ba6...; later commits are normal
git log --oneline 4dd1ba6..HEAD    # what changed since the audited baseline (empty or docs-only means the audit still applies)
git diff --stat 4dd1ba6 HEAD -- src-tauri crates src   # any source drift since the audit
git status --porcelain=v1 -uall    # expect clean
```

If source drifted since `4dd1ba6`, treat the reachability statements in sections 4-8 as needing re-verification.

## 18. Continuing in a future ChatGPT or Claude conversation

Give the new assistant: this file, `@docs/PROJECT_STATUS.md`, `@docs/SECURITY_MODEL.md` and, for planning, `@docs/ROADMAP.md`; plus `CLAUDE.md` for Claude Code. The source and Git history are authoritative. When a milestone closes, update this file's tables (sections 5, 11, 12), `PROJECT_STATUS.md` and the registry in `SECURITY_MODEL.md` in the same change, so no chat history is needed.

### Copyable starter (Russian, for ChatGPT or Claude)

```
Это проект LocalVault — локальный зашифрованный менеджер паролей (Tauri 2 + React/TypeScript, ядро на Rust, Windows + Android; репозиторий D:\LocalVault, ветка redesign/light-ui-v1.1).

1. Прочитай текущий handoff docs/HANDOFF_1U_PROGRESS.md, затем docs/PROJECT_STATUS.md и docs/SECURITY_MODEL.md (и docs/ROADMAP.md, docs/ARCHITECTURE.md при планировании).
2. Источник истины — исходный код и история Git. Если документы расходятся с кодом, прав код; сообщи о расхождении.
3. Сначала проверь HEAD: git branch --show-current, git rev-parse HEAD, git status --porcelain=v1 -uall. Аудированная база: 4dd1ba639c9e80ee9e690f1e10c6bc6cf9821626; более поздние коммиты проверь через git log 4dd1ba6..HEAD.
4. Соблюдай gates безопасности. Не включай production-писатели sync-state v3/v4. Не продвигай dormant и test-only компоненты в production. Не закрывай gate без доказательств. Решения D2/D3, D5–D9 остаются открытыми и мной не одобрены.
5. Не изменяй защищённые артефакты (exe v1.0.0 с хешем A5707B99…C481, QA-мастер Android, архив evidence) и не запускай cargo build --release / tauri build. Тестовый scratch — только в .qa-local, не в %TEMP%. Реальные хранилища пользователя не трогай.
6. Без моего прямого запроса: не коммить, не пушь, не ставь теги. Сначала аудит, потом дизайн, потом реализация.
7. Текущая цель разработки — G12-temp: убрать оставшиеся production-достижимые операции удаления по пути (SyncStateStore::create и write_temp) на этапе первоначальной привязки. G12 в целом остаётся ОТКРЫТЫМ. Начни с аудита, без реализации, пока я не подтвержу.
8. Запрашивай недостающие доказательства только если их действительно нет в документах (определения гейтов G1–G13 и решений D1–D9 в репозитории нет: это REPORTED / HISTORICAL метки из архитектурных ревью, см. docs/SECURITY_MODEL.md; не считай их source-confirmed требованиями и не закрывай ни один гейт только потому, что есть тесты или эксперименты).
```

## 19. Documents to read next

`@docs/PROJECT_STATUS.md` (checkpoints and the 1U slice list), `@docs/SECURITY_MODEL.md` (registry, formats, limits), `@docs/ARCHITECTURE.md` ("Sync-state formats and dormant exchange components"), `@docs/ROADMAP.md` (1U sequencing), then the module headers of `sync_state_store.rs`, `held_removal.rs` and `sync_state.rs` before touching G12-temp.

## 20. Known outstanding documentation discrepancies (as of 1U-DOCSYNC)

- G1-G13 (except G2 and G12, which appear in code) and D1-D9 are not defined anywhere in the repository; they are recorded as REPORTED / HISTORICAL labels from the architecture reviews, not a canonical registry. The individual meanings of D2 and D3 are unverified. Whether `G-AUTH` in source corresponds to G2 is unknown.
- Test counts in section 13 are REPORTED, not re-run; the older per-checkpoint counts in `PROJECT_STATUS.md` (664 desktop tests at `e4c06f5`, 228 at `8f0d5a3`) are historical and stale.
- `docs/HANDOFF_1T_COMPLETE.md` and `docs/HANDOFF_1R_COMPLETE.md` still name `D:\LocalVault_Release\LocalVault.exe`; they are historical records and were intentionally not rewritten. Do not follow that path.
- The C: acceptance run predates D4 and `61decb7`; it evidences the reset path at `24fc685`, not the HEAD.
- `target_exchange.rs`, `session/target_update.rs`, `session/exchange_recovery.rs` and the authenticated-state modules are compiled into normal builds as dormant code (not `cfg(test)`). This is by design; it is noted so nobody reads "dormant" as "excluded".
