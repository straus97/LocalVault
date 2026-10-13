# LocalVault 1T Complete Handoff (Android MVP closeout)

## 1. Purpose and authority

Closeout handoff for **Android 1T**, written for a fresh Claude Code conversation. Git history and current source are the authority; where this file disagrees with `git log` or the code, Git and the code win. `@docs/HANDOFF_1T_PROGRESS.md` is a **historical B4-era narrative** (with appended §31–§35 updates) and must not override anything here or in `@docs/PROJECT_STATUS.md`.

Read alongside `@docs/PROJECT_STATUS.md`, `@docs/ROADMAP.md`, `@docs/ARCHITECTURE.md`, `@docs/SECURITY_MODEL.md`.

## 2. What "1T complete" means

1T is closed as an **engineering implementation and current-acceptance milestone with explicitly documented residual testing limitations** (§6). It is **not**:

- a production release, a signed release APK, or a certified/audited build;
- exhaustively fault-injection tested on a physical device;
- a claim that biometric unlock, QR scanning, Autofill or synchronization exist (none do — they are 1W / 1U–1V).

The tested device APK was built with Rust profile `android-release` and Gradle `assembleDebug` (a debug-signed, debuggable APK). Release packaging/signing is unimplemented and belongs to 1X.

## 3. Checkpoint

- Repository `D:\LocalVault`, branch `redesign/light-ui-v1.1`.
- HEAD at closeout (before this docs commit): `7a90301e7b24e190e9a551bda6662ddf8e54f57c` — `feat(android): add entry password visibility toggle`; origin was identical.
- Verify with `git branch --show-current`, `git rev-parse HEAD`, `git status --porcelain=v1 -uall` at the start of any session.
- Windows `v1.0.0` (`D:\LocalVault_Release\LocalVault.exe`, tag `v1.0.0`, commit `04b6220`) stays immutable and separate from v1.1 source. SHA256 of `C:\Users\nikita\Desktop\LocalVault.exe` and `src-tauri\target\release\LocalVault.exe`: `A5707B9901607BD61D7881734478D5D5A2FB3D9CE965D41B7D9863ABF256C481`. Never overwrite them; never run `cargo build --release` or `tauri build`.

## 4. Accepted Android implementation

Architecture: native Kotlin UI (framework views, no Compose/AndroidX) → UniFFI exactly `0.32.0` Kotlin/JNA bindings → `crates/localvault-android-bridge` → shared `localvault-core`. SAF document storage. Crypto, vault format, schema and TOTP live only in `localvault-core`; Kotlin never owns key material, parses TOTP, or normalizes URLs. Decrypted `VaultData` and the Vault Key stay inside the Rust-owned `VaultSession` and never cross FFI.

Implemented (each traced to Git/source):

| Area | Commits |
|---|---|
| Bridge + open/unlock/list, Rust-owned session, immediate lock on `onStop` | `b72f95d`, `3d1a83d` |
| Reader: search, detail, protected clipboard, RU/EN, recent history | `fad2746` |
| Categories, TOTP display/rotation | `4a42ffc` |
| Transactional SAF save, vault creation, entry/category CRUD | `1abf5e4` … `0224fee` |
| TOTP set/replace/remove | `9f8f641`, `4d75bb8` |
| Save correctness follow-ups | `cfe9e6f`, `d1a85e4` |
| Package identity `com.localvault.android` | `a59313d` |
| Large-vault virtualized `ListView` | `a3cd2fe`, `7c73715` |
| Site grouping (core-owned `site_key`) | `5a6c664`, `5634eec` |
| `android-release` unwind panic profile | `0e44311` |
| Wrapping action rows | `7c8b253` |
| SAF read-only default + explicit writable grant UX | `711cda7` |
| In-flight save / reopen / restore / history-cleanup guards | `8bfc10d` |
| Recovery marker filesystem hardening, fail closed | `cd69c4b` |
| Verified recovery cleanup before forgetting a vault | `f7b4633` |
| Session dialogs, input privacy, backup/data-extraction exclusion | `f51190d` |
| Entry password visibility toggle | `7a90301` |

Not implemented: biometrics, QR scanning, Autofill, secure-storage convenience unlock, sync, release signing, "New profile for this site", the coordinated desktop + Android design pass.

## 5. Validation evidence (as reported; not re-run for the docs closeout)

- Android JVM suite (last reported): 355 tests reported, 0 failures, 0 errors, **1 skipped** (a benchmark — **not** a pass).
- Android debug APK build: PASS (Rust `android-release` profile + `assembleDebug`).
- Physical device QA — Xiaomi 24115RA8EG, Android 16 / SDK 36:
  - SAF read-only opening and explicit editing grant;
  - synthetic 300-entry vault open and persistence;
  - entry create / edit / delete;
  - password show/hide and cursor behavior;
  - category operations;
  - immediate lock and dialog dismissal;
  - recent-vault removal, re-adding and reopening, with identical encrypted-file SHA256 before and after history removal;
  - external-change detection: the save returned the localized `ChangedExternally` message and the externally altered file's SHA256 was unchanged after the rejected save.
- The disposable external-change test file is intentionally altered; **never reuse it as a healthy vault**.
- Preserved synthetic QA master (outside Git, do not modify/delete/regenerate): `D:\LocalVault\.qa-local\LocalVault-Android-Smoke-300.lvault`, SHA256 `96D26061A44AD53ABA883BEE113F7F4AE847D28CD4FBB50289AACC848FB388FE`.

## 6. Residual limitations (kept visible; none converted to PASS)

Not verified on a physical Android device:

1. Process death after recovery-marker creation but before the primary write (`NOT_SAVED`).
2. Process death after the primary write but before verification/cleanup (`SAVED`).
3. The full `UNKNOWN_NEEDS_RECOVERY` screen, confirmation and restore through a real SAF provider.
4. Real `AtomicFile` crash behavior across devices.
5. `MainActivity` in-flight `reopenBlocked` interaction with a deliberately slow SAF provider.
6. Xiaomi/OEM device-transfer exclusion behavior (the `data_extraction_rules.xml` / `backup_rules.xml` exclusions are unit-tested for content only).

Decision logic and failure paths have meaningful JVM coverage; that is **not** device proof. `VaultSaveCoordinator` exposes optional `onAfterMarkerWritten` / `onAfterPrimaryWrite` hooks, but production `MainActivity` constructs the coordinator without them, and **no debug-only fault-injection mechanism exists**.

Source-verified caveats:

- Automatic recent-vault eviction (`evictionOutcomeFor` → `RELEASE_AND_FORGET`) is skipped only while a marker is unresolved or a save is in flight; if cleanup then fails, orphaned encrypted recovery files or persisted SAF grants may remain.
- In `VaultSaveCoordinator.runStagedSave`, if `recovery.clearMarker` throws after a verified primary write, the caller sees a generic failure although the bytes reached disk; the baseline is deliberately not advanced and the lingering marker reconciles as `SAVED` on next unlock.
- Non-panic aborts (OOM, stack overflow) remain possible; no Rust panic was injected on-device.
- Non-debug `FLAG_SECURE` behavior has not been exercised in an actual release build.
- 50,000-entry text search is still O(n) (~229 ms frame median) and not optimized.
- Device-specific and release-signing verification are separate from the current debug acceptance.
- Pending release metadata cleanup: `android/app/build.gradle*` still has `versionName = "1t-b3"`. This is version housekeeping for the release stage (1X), not a reason to reopen 1T engineering acceptance; it was deliberately not changed in the closeout.

## 7. Roadmap (unchanged; no new stages)

Stage order stays 1U sync foundation → 1V multi-device sync hardening → 1W Android security/UX (QR, biometrics, Autofill, secure storage) → 1X final hardening/release (packaging/signing, Android release, Windows v1.1/v2). The "coordinated desktop + Android design/UX pass" is a planned, un-numbered item. Do not mix sync into Android work, and do not invent stages.

## 8. Startup checklist for the next session

1. `git branch --show-current`, `git rev-parse HEAD`, `git status --porcelain=v1 -uall`; confirm expectations.
2. Read `@docs/PROJECT_STATUS.md`, then the doc for your task type (`CLAUDE.md`).
3. Respect `CLAUDE.md`: no commit/push/tag unless asked; keep staging empty; no weakening crypto; no network in vault/TOTP paths.
4. Gates for code work: `npm run build`, `cargo fmt --check`, `cargo test --lib`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo check`, `cargo check --release`, `git diff --check`; Android: full JVM suite and `android\scripts\build-android-debug.ps1 -RustProfile android-release`. **Never `--release` for the Android bridge.**
5. Choose the next task with the user (candidates: closing §6 device tests, design/UX pass, 1U design).
