# Project Status

Authoritative as of the Stage 1U documentation refresh. The latest completed **code** checkpoint at the time of this refresh is `a1a94aaff61841769ee3b1ff084e0af4c890a80d` (`feat(desktop): add guarded sync binding status and reset`, 1U-4 B1i); a later docs-only commit may sit on top of it, so verify the real HEAD with Git rather than reading it from this file. **Android 1T remains closed** as an engineering implementation and current-acceptance milestone with documented residual testing limitations — not a production release (closeout checkpoint `7a90301e7b24e190e9a551bda6662ddf8e54f57c`). **Stage 1U (sync foundation) is underway: 1U-1 through 1U-3 and 1U-4 slices A1–B1i are complete and committed; the next slice is 1U-4 B1j (Windows Tauri commands and Russian-language binding-management UI). Synchronization itself is not implemented, and no sync capability is reachable by an end user — B1h and B1i are dormant internal Rust infrastructure.** Start with `@docs/HANDOFF_1T_COMPLETE.md` (a historical 1T completion checkpoint that is deliberately not rewritten for 1U); `@docs/HANDOFF_1T_PROGRESS.md` is a historical B4-era narrative (plus §31–§35 updates) and does not override it. Update this file when the active stage, branch, or implementation checkpoint changes — do not let it drift.

## Branch / implementation checkpoint

- Repository: https://github.com/straus97/LocalVault
- Current development branch: `redesign/light-ui-v1.1`
- Latest completed code checkpoint (all platforms), at the time of this refresh: `a1a94aaff61841769ee3b1ff084e0af4c890a80d` — `feat(desktop): add guarded sync binding status and reset` (1U-4 B1i; local and `origin/redesign/light-ui-v1.1` identical when verified). The 1U commits (listed in the 1U section) are Rust `localvault-core` and Windows `src-tauri` changes, plus the shared schema-3 rule that the Android bridge calls (1U-2); no 1U commit changed Android Kotlin or the frontend. This is a dated checkpoint, not an eternally current repository HEAD.
- Android 1T closeout checkpoint: `7a90301e7b24e190e9a551bda6662ddf8e54f57c` — `feat(android): add entry password visibility toggle` (docs closeout `1207c07`). The last named Android stage checkpoint remains `4d75bb81042dfcf339073240472b2129265f23e1` — `feat: add Android TOTP management UI (1T-B5c-2)`; everything after it (B5 follow-ups `cfe9e6f`/`d1a85e4`, package cleanup, list virtualization, grouping, panic profile, and the SAF/recovery/privacy hardening listed under 1T below) is unnamed stabilization work, not new stages.
- Android checkpoints on this branch, in order: `b72f95d` (1T-B1b, Rust/UniFFI/JNA bridge + real-device proof), `3d1a83d` (1T-B2, open/unlock/list real vaults), `fad2746` (1T-B3, usable reader: search/detail/clipboard/localization), `4a42ffc` (1T-B4, categories + TOTP), then the 1T-B5 write/CRUD series: `1abf5e4` (B5a), `5c20513` (B5b-1), `3ebbed5` (B5b-2), `60e26c4` (B5b-3), `18a0034` (B5b-4), `32a0754` (B5b-5), `0224fee` (B5b-6 hardening), `9f8f6411f2dd0303458bb541c8a0a401c5f813ce` (B5c-1), `4d75bb81042dfcf339073240472b2129265f23e1` (B5c-2); followed by two unnamed B5 correctness fixes, `cfe9e6f` and `d1a85e4` (see 1T below). 1T-B1a (toolchain/environment proof) produced no commit — see `@docs/HANDOFF_1T_PROGRESS.md` §7.
- 1S checkpoints (unchanged, see below): `8f0d5a3` (1S-C3 TOTP core), `bfd7fec` (1S-C2 data model core), `4721b05` (1S-C1 crypto/format core), `07e15fd` (core workspace skeleton), `bcdb1ad` (1S-B1 compat safety net), `c5eb5e6` (record 1R completion and Android roadmap), `47c2315` (1R frontend), `af1b2e6` (1R backend)
- Working tree at the 1U-4 B1i code checkpoint: clean (uncommitted documentation edits may exist on top of it)
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

### 1T — Android mobile MVP (COMPLETE as an engineering/acceptance milestone, with documented limits)

**1T engineering implementation and current acceptance are complete; Android is not production-released.** Android is a usable **read/write** LocalVault client: B1b–B4 delivered the read-only client, the B5 series added transactional SAF saving, vault creation, entry/category CRUD and TOTP set/replace/remove, and later stabilization added grouping, list virtualization, SAF read-only/editing UX, recovery fail-closed hardening, session-dialog/input privacy and backup exclusion, and a password visibility toggle. Closeout summary and startup checklist: `@docs/HANDOFF_1T_COMPLETE.md`. Older per-stage detail: `@docs/HANDOFF_1T_PROGRESS.md`.

**Closeout stabilization commits (after grouping `5a6c664`/`5634eec`):** `0e44311` (`android-release` unwind panic profile, committed), `7c8b253` (wrapping action rows), `711cda7` (SAF read-only and explicit editing flow), `8bfc10d` (in-flight save/recovery guards), `cd69c4b` (recovery marker fail-closed), `f7b4633` (verified recovery cleanup before forgetting a vault), `f51190d` (session dialogs, input privacy, backup/data-extraction rules), `7a90301` (entry password visibility).

**Closeout validation (as reported; not re-run for the docs closeout):** Android JVM suite 355 tests reported, 0 failures, 0 errors, **1 skipped** (a benchmark — not a pass); Android debug APK build PASS (Rust profile `android-release` + Gradle `assembleDebug` — **not** a signed release APK). Physical QA on Xiaomi 24115RA8EG (Android 16 / SDK 36) confirmed: SAF read-only open and explicit editing grants; 300-entry synthetic vault open and persistence; entry create/edit/delete; password show/hide and cursor behavior; category operations; immediate lock and dialog dismissal; recent-vault removal/re-add/reopen with identical encrypted-file SHA256; external-change detection returning the localized `ChangedExternally` message with the external file's SHA256 unchanged after the rejected save. The disposable external-change test file is intentionally altered and must not be reused as a healthy vault.

**Residual limitations (still open, not PASS):** not verified on a physical device — (1) process death after marker creation before the primary write, (2) process death after the primary write before verification/cleanup, (3) the full `UNKNOWN_NEEDS_RECOVERY` screen/confirmation/restore through a real SAF provider, (4) real `AtomicFile` crash behavior across devices, (5) `MainActivity` in-flight `reopenBlocked` with a deliberately slow SAF provider, (6) Xiaomi/OEM device-transfer exclusion. JVM tests cover the decision logic and failure paths but are not device proof. Production `MainActivity` does not wire the coordinator's optional fault-injection hooks and no debug-only fault-injection mechanism exists. Caveats: automatic recent-vault eviction after a cleanup failure may leave orphaned encrypted recovery files or persisted grants; a failed marker cleanup after a successful primary write surfaces a generic failure although the write reached disk. Device-specific and release-signing verification are separate from this debug acceptance. Details: `@docs/HANDOFF_1T_COMPLETE.md` §6, `@docs/SECURITY_MODEL.md`.

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
- **`applicationId`/package cleanup (CLOSED; not a new named stage):** the temporary Android identity `com.localvault.android.proof` was replaced by the production identity `com.localvault.android` — Gradle `namespace` and `applicationId`, all Kotlin package declarations (main and JVM tests), and the source directories (`android/app/src/{main,test}/java/com/localvault/android/`, moved with `git mv`). The manifest needed no change (`.MainActivity` is relative to `namespace`). No behavior, UI, vault/storage/crypto/session/save, permission or lifecycle change; the UniFFI bridge namespace `uniffi.localvault_android_bridge`, UniFFI/JNA versions and bridge crate names are untouched. A build with the new `applicationId` installs as a different app from one built with the old identity (no shared private data or persisted SAF grants). Validated by the full Android JVM suite and the full `android/scripts/build-android-debug.ps1`; no device QA was required.
- **Android LIST virtualization (ACCEPTED; not a new named stage):** large-vault performance was measured on a real device (Xiaomi 24115RA8EG, SDK 36, 256 MiB max heap) *before* optimizing, using a committed benchmark (`a3cd2fe`). The old `ScrollView` + `LinearLayout` list, which removed and recreated every matching entry's View on each refresh, was shown to be unacceptable (1,000 entries: 3,909 resident Views, ~13.2 MiB extra heap, ~950–965 ms frames). The LIST is now a framework `ListView` + `BaseAdapter` with `convertView` recycling — no AndroidX, no RecyclerView — and still one logical row per visible entry; filtering still uses the unchanged `EntryListFilter`. Post-change benchmark at 1k/5k/10k/50k completed without OOM: resident Views stay at 59 at every size (1,000 entries: ~0.22 MiB heap delta, initial-list frame 30.29 ms; 50,000 entries: initial-list frame 21.09 ms). **Residual cost, stated honestly:** text filtering is still O(n); at 50,000 entries a `mail` search (3,323 rows) has a ~223 ms frame median and four keystrokes sum to ~817 ms of action time, so 50k text search is not smooth. That is not a blocker for this slice, and no debounce/indexing/caching is planned before grouping (re-evaluate only if still useful once grouping changes the logical-row layer). Manual QA on a synthetic 300-entry vault passed on device (scrolling, recycling with no stale fields, search, categories, category + search, DETAIL and back with scroll restoration, lock/reopen); a very small delay returning from DETAIL to the full list was noticed and is non-blocking. The source change is accepted and committed as `7c73715` (`perf(android): virtualize vault entry list`). Detail and numbers: `@docs/HANDOFF_1T_PROGRESS.md` §33.
- **Android site/profile grouping (ACCEPTED; not a new named stage; committed and pushed in `5a6c664`, `feat(android): group vault entries by site`; local and `origin/redesign/light-ui-v1.1` verified aligned after push; grouping is complete within 1T):**
  - **Architecture:** persisted `VaultData` still has Entry objects only — no persisted Site/Profile entity; one Entry is one account/profile. `localvault-core` owns derived site identity via `localvault_core::site::site_key(url: &str) -> Option<String>`; the Android bridge exposes it as `EntrySummary.site_key`; Kotlin never normalizes URLs and owns only visual grouping and expanded/collapsed UI state. Site groups expand inline; there is no separate Android Site screen. Desktop grouping is unchanged in this slice. "New profile for this site" remains deferred to the later design/UX pass.
  - **`site_key` contract (concise):** input trimmed, blank → `None`; an explicit `<scheme>://` is parsed as an explicit URL, scheme-less host-like values (`example.com`, `www.example.com/path`, `example.com:8080/x`) stay accepted as before; hostname-based, lowercased, exactly one leading `www.` and one trailing root dot stripped; scheme/userinfo/port/path/query/fragment ignored; meaningful subdomains preserved; IPv4/IPv6 supported; IDN yields a stable punycode form; malformed/unusable host → `None`; an explicit empty authority such as `http:///path` is deliberately rejected rather than accepting the URL parser's repair; no fallback id is invented. Full detail: `@docs/HANDOFF_1T_PROGRESS.md` §34.
  - **Grouping semantics:** search/category filtering runs on `EntrySummary` values **before** grouping (category stays per Entry); a site group sits at its first visible appearance; children keep visible entry order; entries without a `site_key` stay standalone rows; a site with one currently visible entry is still a site group; groups are collapsed by default; expansion is keyed by `site_key`, Kotlin-only, never persisted, survives DETAIL round trips and temporary search/category hiding, and is cleared on lock/new vault session. The visible count is the **entry** count, not the adapter row count.
  - **Virtualization intact and measured** (real Xiaomi 24115RA8EG, Android 16 / SDK 36, seed 20260101, warmup 2, 7 iterations; collapsed default): resident Views stay at 69 (ListView children 8) from 1k through 50k with no OOM and no missing frames. 50,000 entries → 29,052 adapter rows / 23,928 site groups, initial-list frame median 53.78 ms, expand-one-group 67.52 ms, collapse 68.44 ms, heap delta 0.96 MiB. **Residual cost, stated honestly:** 50k text search is still O(n) and not smooth (`mail` frame median ~228.63 ms; four-keystroke `mail` final frame ~245.21 ms); it is intentionally not optimized in this slice, is non-blocking for 1T, and no debounce/index/cache is planned until later evidence requires it. Table: `@docs/HANDOFF_1T_PROGRESS.md` §34.
  - **Manual QA PASSED** on the Xiaomi device with the synthetic 300-entry vault (`qa/LocalVault-Android-List-QA-300.lvault`, kept outside Git): grouped rows, inline expand/collapse, child ordering, recycling with no stale state, child DETAIL → back preserving expansion and approximate scroll, search, categories, category + search with no unmatched-sibling leakage, entry-count semantics, lock/reopen resetting expansion, general stability. The known tiny DETAIL → LIST return delay remains non-blocking.
  - Not changed: persisted schema, vault format, crypto, SAF/save, session ownership, lifecycle, TOTP, clipboard, permissions, package identity.
- **Android panic strategy — RESOLVED (configuration level; committed in `0e44311`, see `@docs/HANDOFF_1T_PROGRESS.md` §35):** new Android-only Cargo profile `[profile.android-release]` (`inherits = "release"`, `panic = "unwind"`, `strip = "debuginfo"`) in the root `Cargo.toml`, selected with `android\scripts\build-android-debug.ps1 -RustProfile android-release` (default `debug`; `release` rejected). The global `[profile.release]` still uses `panic = "abort"` and is unchanged, so Windows release semantics are unchanged. Validated: fmt/tests/clippy/check/check --release/profile build; ELF shows the unwind panic runtime and no `panic_abort`; UniFFI metadata extracted before stripping; Kotlin bindings byte-identical to debug; APK carries the stripped native library. Physical-device smoke (Xiaomi 24115RA8EG, Android 16 / SDK 36) passed: a synthetic 300-entry vault opened (browse, grouping, search, categories, detail), and in a separately created vault create/save/lock-reopen/delete/reopen worked with no crash or freeze. **Limitations:** the imported 300-entry vault showed write access unavailable (read-only) — root cause **unverified** (possibly SAF permission/provider capability), so mutation of that vault was **not** tested; no deliberate panic was injected on-device; no final automated logcat gate; out-of-memory/other non-panic aborts remain possible; Android release packaging/signing is not implemented (Gradle still `assembleDebug`).
- **Former "remaining before 1T can close" list — resolved at closeout:** the wrapping action rows (`7c8b253`) target the DETAIL top-action overflow (no separate device re-check of that screen is recorded here), and read-only access to an imported vault is now an explicit, designed state — read-only by default with an explicit writable grant (`711cda7`), confirmed on device; the earlier unverified root-cause question is superseded by that behavior. What remains is **not** a 1T blocker: the device-only stress tests above, and a later dedicated, coordinated desktop + Android design/UX pass (planned, un-numbered, not implemented; the current Android visual design is explicitly not final). Do not describe Android as production-released.

### 1U — Sync foundation (IN PROGRESS: 1U-1 … 1U-3 and 1U-4 A1–B1i complete; 1U-4 B1j next)

**No user-facing synchronization exists.** 1U so far delivered a schema change, pure Rust building blocks in `localvault-core`, and dormant internal Windows infrastructure in `src-tauri`. Roadmap detail: `@docs/ROADMAP.md`; boundaries: `@docs/ARCHITECTURE.md`; security semantics: `@docs/SECURITY_MODEL.md`.

**COMPLETE (committed):**
- **1U-1** — `8d001a1`: `localvault_core::sync` — SHA-256 fingerprints of raw encrypted-envelope bytes (byte identity only), a description-only classifier, push-intent reconciliation.
- **1U-2** — `d7b71a2`: encrypted `VaultData` schema **3** with an authenticated `revision: u64` inside the existing AEAD payload. Schemas 1/2 stay readable (revision 0); opening never migrates; the first committed write gives schema 3 at revision 1 and each later write adds one (checked). The rule is owned by core (`VaultData::prepare_for_write`) and used by the desktop session and the Android bridge. Envelope format and encryption unchanged.
- **1U-3** — `ebe4ae5` (with its follow-up `d4ad19d`, listed as 1U-4 A2a): core authenticates a remote encrypted candidate against the local vault and inspects it, bound to the exact raw envelope bytes.
- **1U-4 A1** — `c9158e5`: validated device-local sync-state model and codec (`localvault_core::sync_state`).
- **1U-4 A2b** — `1f41344`: pure authenticated sync-state transitions; they return proposals and persist nothing.
- **1U-4 B1a** — `b232679`: Windows guarded sync-state file store (`src-tauri/src/vault/sync_state_store.rs`), one record per local vault location.
- **Windows no-clobber hotfix** — `177ce4a`: vault creation no longer overwrites an existing file (`vault/storage.rs`).
- **1U-4 B1b** — `615c69c`: sync state loaded and verified inside an unlocked session against the authenticated vault identity.
- **1U-4 B1c** — `0b4f33b`: authenticated remote high-water observations persisted; an observation does not advance the synced baseline.
- **1U-4 B1d** — `f22dc76`: read-only Windows sync file adapter (`vault/sync_file_adapter.rs`).
- **1U-4 B1e** — `401513d`: session-level observation of a bound target through that adapter.
- **1U-4 B1f** — `5476afb`: internal initial binding to an existing authenticated, byte-identical artifact.
- **1U-4 B1g** — `76af84e`: Windows physical-file identity check (`vault/file_identity.rs`) that rejects an alias (e.g. hard link) of the primary vault as a binding target.
- **1U-4 B1h** — `719e298`: Rust-owned, session-bound, one-time initial-binding approval (prepare → confirm/cancel; a prepared approval expires after 120 seconds).
- **1U-4 B1i** — `a1a94aa`: read-only binding status and a guarded explicit local binding reset (its own 120-second one-time approval; removes only the local record, after an evidence check).

**NOT COMPLETE:**
- Real sync transport; provider authority / cloud freshness.
- Initial publication to an absent remote.
- Actual push and pull; remote-to-local adoption.
- Merge and conflict-resolution workflow; automatic synchronization.
- Android sync-state integration (Android SAF-target adapter).
- User-facing sync binding commands and UI; any production user flow for manual sync.

**B1h and B1i are dormant internal Rust infrastructure.** No Tauri command, `lib.rs` registration or frontend code calls them; an end user cannot create, inspect or reset a binding. Do not describe synchronization, binding or reset as available.

- **Physical cross-platform QA (1U-2; disposable synthetic vault; not a production release):** Android migrated a 300-entry vault to schema 3 by adding one entry (301); the updated Windows development application opened it; Windows added another synthetic entry (302); Android opened the resulting 302-entry vault; SHA256 transfer integrity matched in both directions. The immutable `v1.0.0` Windows binaries were unchanged. No device QA exists for the later 1U-4 slices (Windows-only, not user-reachable).
- **Next: 1U-4 B1j** — Windows Tauri commands and a Russian-language binding-management UI that expose **only** the approved initial-binding / status / reset workflows and do not claim to enable synchronization (see `@docs/ROADMAP.md`). Not started.

**Outstanding limitations (carried, not PASS):**
- Manual sync is not implemented. Remote inspection, binding, status and reset exist only as dormant internal Windows Rust code; there is no transport, provider adapter, publication, push, pull or adoption, and automatic sync is not implemented. The device-local sync-state record is not tamper-proof or rollback-proof (`@docs/SECURITY_MODEL.md`).
- Changing the master password does not rotate the Vault Key (it re-wraps the same key); key rotation is not implemented or approved. Anti-rollback protection is not implemented — the revision is not a freshness proof (`@docs/SECURITY_MODEL.md`).
- Builds that predate schema 3 reject schema-3 vaults; existing backups keep their prior schema.
- **Android SAF intermittent wrong-document refusal remains unresolved.** The strict same-document check (exact URI-string equality, fail closed) is unchanged. A temporary, debug-only diagnostic APK was built and tested on the device; no mismatch occurred during that run, so no root cause was captured. The temporary diagnostic source was then removed from the source tree and archived locally under the git-ignored `.qa-local` storage, which is not a tracked project artifact. This does not reopen 1U-2 migration acceptance.
- The previously documented physical-device crash/fault-test limitations of 1T (`@docs/HANDOFF_1T_COMPLETE.md` §6) remain open.

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

**Shared/desktop, at the 1S-C3 checkpoint (`8f0d5a3`; historical and stale — `localvault-core` and `src-tauri` have changed since in 1U):**
- Frontend production build: PASS
- Rust tests: 228 PASS (`localvault-core` lib 43, `localvault` lib 178, `compat_baseline` 6, `data_storage_integration` 1)
- Strict clippy (`-D warnings`, workspace): PASS
- `cargo check` / `cargo check --release` (workspace): PASS
- Working tree: CLEAN

This documentation refresh ran no build or test. Re-run the gates in `CLAUDE.md` against current HEAD rather than trusting these historical counts.

## Vault schema

- Current schema: 3 (since 1U-2, `d7b71a2`; unchanged by later 1U slices — the sync-state record is a separate device-local file, not part of the vault)
- Legacy readable schemas: 1 and 2
- Schema 1 remains readable only if it contains no TOTP; it cannot carry a TOTP secret.
- Schema 2 supports encrypted TOTP configuration and has no revision (reads as revision 0).
- Schema 3 adds the authenticated `revision: u64`; new vaults start at revision 0.
- Opening never migrates. A committed payload write upgrades a legacy vault to schema 3 at revision 1; each further committed write increments the revision by one.
- Envelope format and encryption are unchanged.

## Immediate next phase

**1S is complete.** Crypto/vault-format (1S-C1), persisted vault data (1S-C2), and TOTP (1S-C3) are extracted into `localvault-core`, and the 1S remaining-work audit confirmed no further extraction is required before Android work begins. Password-health placement and password-generator placement remain deferred, non-blocking long-term questions — see `@docs/ARCHITECTURE.md` for the current (not merely target) module boundary.

**1T (Android mobile MVP) is closed** as an engineering implementation and current-acceptance milestone with the documented residual limits above (see `@docs/HANDOFF_1T_COMPLETE.md`). Android can create/open vaults, save safely through SAF, mutate entries/categories, set/replace/remove TOTP, group by site, and recover from interrupted saves; it is a debug-signed build, not a production release. **There is no further named 1T stage.** The approved roadmap order is unchanged: 1U (sync foundation) → 1V (multi-device sync hardening) → 1W (Android QR/biometrics/Autofill/secure storage) → 1X (final hardening/release, packaging/signing). **Stage 1U is underway** (1U-1 through 1U-3 and 1U-4 A1–B1i complete — see the 1U section above); the next implementation slice is **1U-4 B1j**, Windows Tauri commands and Russian-language binding-management UI (initial binding / status / reset only; it does not enable synchronization). Candidate non-1U tasks, to be confirmed with the user at the start of the next session: closing the device-only stress tests listed above, resolving the Android SAF wrong-document issue, or the coordinated desktop + Android design/UX pass. Synchronization and 1W features do not exist yet; the 1U binding code is dormant and unreachable by users. `@docs/HANDOFF_1S_COMPLETE.md` remains the closure handoff for 1S; `@docs/HANDOFF_1R_COMPLETE.md` remains useful for pre-1S historical context only.
