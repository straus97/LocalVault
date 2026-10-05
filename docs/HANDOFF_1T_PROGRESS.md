# LocalVault 1T Progress Handoff

## 1. Purpose / how to use

This is the authoritative handoff for a **new** Claude chat (or any fresh engineer) picking up LocalVault after 1T-B1 through 1T-B4. It exists because 1T (Android) is still in progress, not complete, and the next task (1T-B5, Android write/create/CRUD) is architecturally significant enough to deserve a clean context rather than continuing in a chat that has accumulated a long implementation history.

Read this alongside `@docs/PROJECT_STATUS.md`, `@docs/ROADMAP.md`, `@docs/ARCHITECTURE.md`, and `@docs/SECURITY_MODEL.md` — this file is the detailed narrative; those are the concise, authoritative current-state documents. Where anything here conflicts with those four files or with Git itself, **Git and those four files win** — this handoff is a snapshot written at the 1T-B4 checkpoint and will age.

Do not rely on old conversational memory from any prior Claude chat. Repository docs + Git history are authoritative.

## 2. Authoritative checkpoint

- Repository: `D:\LocalVault`
- Branch: `redesign/light-ui-v1.1`
- HEAD at the time this handoff was written: `4a42ffc5081a2958f2046132f063e6f9261c3f1b` — `feat: add Android categories and TOTP` (1T-B4)
- Working tree at that HEAD: clean
- **Update (after B5c and the two B5 correctness follow-ups):** the sections below are the original B4-era snapshot and are intentionally left as written. The B5 write/CRUD series has since landed and is summarized in **§31**; the last named stage checkpoint is B5c-2 `4d75bb81042dfcf339073240472b2129265f23e1`. Current HEAD (before the docs-closeout commit that records this update) is `d1a85e44a0e45fddc7973ed88cb36ae034dea050` — `fix: refresh Android entry cache after stale completion`, preceded by `cfe9e6f24be55e3ebc6889f209f7141db22938b4` — `fix: discard Android staged save after write failure` (both closed follow-ups are in §31). Where §12/§14/§22/§23 below say Android is read-only or B5 is next, §31 supersedes them.
- **Do not trust this hash blindly** — re-verify with `git rev-parse HEAD` at the start of any new session (see §29).

## 3. Immutable v1.0.0 (do not touch)

- Source commit: `04b6220d96599b96b68135054994b0bc731aa9e4`, tag `v1.0.0`
- Known executable SHA256: `A5707B9901607BD61D7881734478D5D5A2FB3D9CE965D41B7D9863ABF256C481`
- This exact binary was found, during 1T-era diagnostics, at both `C:\Users\nikita\Desktop\LocalVault.exe` and `src-tauri\target\release\LocalVault.exe` (the latter apparently never rebuilt since the `v1.0.0` commit). **Never overwrite, rewrite, or replace either of those with a new release build without the user's explicit request** — see §16 for the safe way to run a current build instead.
- All redesign/Android work targets `v1.1+`.

## 4. History through 1S (brief — full detail in `@docs/HANDOFF_1S_COMPLETE.md`)

- 1N–1Q: light UI, sites/profiles, encrypted favicon cache, password health.
- 1R (`af1b2e6` backend, `47c2315` frontend, closed at `c5eb5e6`): local TOTP/2FA on desktop.
- 1S (closed at `5a39a8a`, audited at `962f2a7`): extracted crypto/vault-format (`4721b05`), persisted data model (`bfd7fec`), and TOTP (`8f0d5a3`) into the new `localvault-core` crate, behind a pre-extraction compatibility safety net (`bcdb1ad`, `src-tauri/tests/compat_baseline.rs` + committed schema-1/schema-2 fixtures). Purely mechanical moves — no crypto/behavior change. Password-health and password-generator placement remain deliberately undecided (non-blocking).
- **1S is complete.** 1T is not.

## 5. 1T architecture (approved, implemented)

Chosen by the 1T-A and 1T-A2 read-only architecture audits (see git history / prior chat transcripts for the full audit reports if ever needed — not reproduced here):

```
Native Android Kotlin UI (plain framework views; no Compose, no AndroidX added for this)
    ->
stable UniFFI 0.32.0 Kotlin/JNA generated bindings
    ->
crates/localvault-android-bridge  (Rust, depends only on localvault-core)
    ->
localvault-core  (unchanged — same crypto/format/schema/TOTP as desktop)
```

**Explicitly rejected/not used, and must not be reintroduced without a fresh deliberate decision:**
- the experimental `uniffi-bindgen-kotlin-jni` backend (upstream describes it as fresh/experimental/use-at-your-own-risk, with at least one known async-continuation deadlock/ANR report) — the stable Kotlin/JNA path is used instead;
- hand-written direct JNI;
- Tauri Mobile;
- async UniFFI / Kotlin coroutines across the FFI boundary.

**Why native + UniFFI/JNA over Tauri Mobile:** clean additive isolation from the existing Windows `src-tauri` adapter (zero changes required to ship Android), native Android lifecycle/API access, a credible future path to Autofill (which a WebView-hosted Tauri Mobile shell cannot realistically support), and no need to retrofit the desktop adapter's Windows-only dependencies for a second platform.

## 6. Android toolchain (pinned)

| Component | Version / value |
|---|---|
| Rust | 1.98.1 (at 1T-B1a) |
| Rust target | `aarch64-linux-android` |
| Android ABI shipped | `arm64-v8a` only |
| Java | JDK 17.0.12 |
| Android SDK root | `C:\Users\nikita\AppData\Local\Android\Sdk` |
| Android NDK | `27.2.12479018` (r27c) |
| cargo-ndk | 4.1.2 |
| UniFFI | `=0.32.0` exactly — do not float |
| JNA | `5.19.1`, Android/Gradle-side only — never a Rust dependency |
| AGP | 9.2.0 |
| Gradle | 9.4.1 (wrapper committed) |
| Kotlin | 2.4.20 (AGP 9's built-in Kotlin support — no separate `org.jetbrains.kotlin.android` plugin) |
| compileSdk / targetSdk | 36 / 36 |
| minSdk | 26 (**bootstrap baseline only — not a final long-term support decision**) |

Build pipeline: `android/scripts/build-android-debug.ps1` — verifies toolchain paths, resets generated output dirs, `cargo ndk` builds the bridge cdylib for arm64-v8a, builds a host-only `uniffi-bindgen` (feature-gated, never linked into the shipped `.so`) and generates Kotlin bindings in library mode directly from the cross-compiled `.so` (verified byte-identical to generating from a host build — UniFFI 0.32.0's embedded metadata is architecture-agnostic), places the `.so` and generated Kotlin into ignored `android/app/build/generated/` paths, runs `gradlew assembleDebug`, and verifies the resulting APK bundles no compatibility fixture. Generated `.so`/Kotlin/APK/Gradle build output are never committed (`android/.gitignore`).

## 7. 1T-B1a — toolchain/environment proof (no commit)

Read-only-ish setup task (with explicit user-approved installation): installed and pinned the Android Rust target, NDK, and `cargo-ndk`; proved `cargo ndk -t arm64-v8a build -p localvault-core` succeeds unmodified. No FFI, no Android project, nothing committed — pure environment/compatibility verification.

## 8. 1T-B1b — `b72f95de465f7f548575ba28a4fbc49d72e9d453`

First real architecture proof, on a real arm64-v8a phone:
- New crate `crates/localvault-android-bridge` (UniFFI 0.32.0 proc-macro interface, no UDL, no build.rs).
- One proof function (`verify_compatibility_fixture`, since replaced by the real B2 session API — see §9) exercised end to end: Kotlin → generated UniFFI/JNA binding → bridge → `localvault-core` → the committed schema-2 compat fixture.
- Positive (correct password) and negative (wrong password → `AuthenticationFailed`) paths both verified on-device, with logcat inspected and confirmed to contain zero secret material.
- Minimal native Kotlin proof app (single Activity), no Compose/AndroidX.
- A UI-recovery follow-up in the same task fixed a blank-screen bug caused by the ActionBar overlapping the body under `targetSdk 36`'s enforced edge-to-edge window — fixed by dropping the ActionBar and adding explicit `WindowInsets` handling. This insets fix has been preserved through every subsequent Android UI change (B2–B4) and must not be regressed.

## 9. 1T-B2 — `3d1a83d5c50c8fd8afefe8720bdc513a191352ab`

First real user-facing vertical slice, replacing the B1b proof screen:
- SAF `ACTION_OPEN_DOCUMENT` vault selection (broad `*/*` MIME type; no custom `.lvault` MIME registration assumed).
- The bridge grew a real session API: `open_vault(envelope_bytes, master_password) -> VaultSession` (a UniFFI object wrapping `Mutex<Option<VaultData>>`), `VaultSession::list_entries()`, `VaultSession::lock()`. The old one-shot proof function was removed.
- Real master-password unlock (real Argon2id cost — measured ~3s on the test phone) run on a dedicated background `Thread`, never the Android main thread; the "Unlocking..." state renders immediately and the UI stays responsive during the KDF.
- Real entry list rendered from `EntrySummary` (id/title/profile/url/username — no password/notes/TOTP).
- Explicit Lock button; immediate lock on `onStop` (backgrounding); process death naturally destroys the Rust session.
- **Read-only**: the vault file is only ever read via `ContentResolver`, never written.

## 10. 1T-B3 — `fad27461b2f80a2dc8cfcccedf857589a6c08d08`

Turned the reader into something usable, plus a security follow-up:
- Full Russian (`values-ru/strings.xml`) + English (`values/strings.xml`) localization; no hard-coded visible strings.
- Recent-vault history: `RecentVaultStore` (SharedPreferences-backed), storing only `{uri, display name}` per entry, capped at 5, most-recent-first. A **persisted read-only** URI grant (`takePersistableUriPermission(FLAG_GRANT_READ_URI_PERMISSION)`) is taken only when Android actually grants the persistable flag; stale/revoked grants are detected and the item is safely removed with a generic message, never a raw exception. No write permission requested.
- Local case-insensitive search over title/username/url/profile — no Rust/core change needed.
- Entry detail screen: title/profile/url/username, password hidden by default, explicit Show/Hide, explicit Copy username/Copy password.
- **Protected Android clipboard** (`SecureClipboard.kt`) — see §13 for the full model. This went through one real bug and fix in-session: the first version's 30-second cleanup timer silently gave up when it fired while LocalVault was backgrounded (Android 10+ denies clipboard reads to unfocused apps, indistinguishable from an empty clipboard) and never retried. Fixed by tracking only a non-secret ownership token + expiry, and retrying cleanup on `onResume`/regained window focus rather than only from the original timer.
- Screenshot policy: `FLAG_SECURE` is set unless the app's real `ApplicationInfo.FLAG_DEBUGGABLE` is true (never a hard-coded boolean) — debug builds allow screenshots for development, non-debug builds block them.
- A separate UI-recovery pass fixed a long vault filename (e.g. `LocalSave.lvault.backup`) wrapping badly next to the Lock button in the list header — fixed by giving the filename its own single, end-ellipsized line below a stable heading.
- Manually verified end-to-end on a real device, including all three clipboard scenarios (foreground clear, background-then-return clear, unrelated-copy preserved).

## 11. 1T-B4 — `4a42ffc5081a2958f2046132f063e6f9261c3f1b`

Categories and TOTP, plus a visual polish follow-up:
- Bridge additions: `EntrySummary.category_id: Option<String>`, `EntryDetails.totp_enabled: bool`, `VaultSession::list_categories() -> Vec<CategorySummary>` (`{id, name, entry_count}`), `VaultSession::totp_status(entry_id, unix_time_seconds) -> TotpStatus` (`{code, remaining_seconds, period_seconds}`), new structured errors `EntryNotFound`, `TotpNotConfigured`, `InvalidTotpConfiguration`. All built directly on existing `localvault-core` APIs (`VaultData.categories`, `VaultEntry.category_id`, `localvault_core::totp::generate_totp`) — no core change.
- Android category UI: a horizontal chip row ("Все"/"All", each real category in stored order, then a transient "Без категории"/"Uncategorized" filter shown only when applicable) combined with search; result count reflects the currently visible set; selecting a chip never touches passwords/TOTP. No category data is persisted by Android.
- TOTP UI: a "Код 2FA"/"2FA code" card appears on the detail screen only when `totp_enabled`; live rotating code + countdown text, driven by a once-per-second `Handler` tick that calls `totp_status` (code regeneration only happens on that tick, never per animation frame); Copy Code goes through the same `SecureClipboard` as passwords, marked sensitive.
- **Follow-up fix in the same task:** the initial progress bar stepped visibly once per second (it used an integer `max = periodSeconds` scale). Replaced with a native `ValueAnimator` + `LinearInterpolator` animating a fine-grained (10,000-step) progress value, restarted only when a fresh `totp_status` fetch establishes a new wall-clock-derived expiry (screen entry, resume, or period rollover) — never per animation frame. The animation is cancelled everywhere the old ticker already was (leaving detail, Back, Lock, `onStop`, destroy, TOTP failure), so there is no background animation after locking.
- Manually verified on a real device, including the smooth-progress fix after reinstalling.

## 12. Android session / security model (current, summarized — full detail in `@docs/SECURITY_MODEL.md`'s Android section)

- Decrypted `VaultData` is Rust-owned inside `VaultSession`; it never crosses FFI.
- Master Key and Vault Key never cross FFI in plaintext. **Superseded since B5a (B4-era statement kept for history):** B1–B4 used `open_envelope` and retained no key; from B5a, `open_vault` uses `open_envelope_with_key` and the Vault Key is retained Rust-side in `SessionState` (and temporarily in `PendingVaultCreation`) so mutations can reseal without re-running Argon2id. The Master Key is still not retained. Kotlin may receive encrypted `VaultEnvelope` bytes containing the already-wrapped `wrapped_vault_key`, and never owns plaintext cryptographic key material. See §31 and `@docs/SECURITY_MODEL.md`.
- Master password crosses FFI once, wrapped in `Zeroizing` Rust-side as early as practical; the JVM-side `String` copy's zeroization is **not** claimed (JVM strings cannot be deterministically zeroized).
- Individual passwords cross FFI only on explicit show/copy (`entry_password`), never in any list/summary.
- TOTP secret never crosses FFI; only a generated code + timing crosses, and only while the detail screen is visible.
- Wrong-password vs. corrupted-ciphertext indistinguishability is preserved in `BridgeError::AuthenticationFailed` — no finer authentication oracle was added.
- Vault session locks immediately on backgrounding (`onStop`) or explicit Lock/Back from an unlocked screen — Android currently has **no** inactivity-timeout grace period (unlike desktop's 60s); this is intentionally more conservative, not a gap.
- Screenshots: blocked via `FLAG_SECURE` except in debuggable builds. Non-debug/release screenshot-blocking has not been exercised in an actual release build.
- **Open blocker:** workspace `[profile.release]` has `panic = "abort"`, which can prevent UniFFI's panic containment (which expects unwinding) from working in an Android **release** build. Not yet a problem because all Android work so far has used debug builds (default unwind). Must be deliberately resolved — without naively changing the shared release profile, which could affect the Windows release — before any production Android release. **Not solved.**
- `applicationId`/package was `com.localvault.android.proof` — an intentional temporary bootstrap identity at the B4 snapshot; since replaced by `com.localvault.android` (see §32).

## 13. Clipboard model (current, from B3, unchanged by B4's TOTP-copy reuse)

- Intended LocalVault-owned clipboard lifetime: 30 seconds.
- Password and TOTP-code copies are marked with `ClipDescription.EXTRA_IS_SENSITIVE` (honoured on Android 13+; harmlessly ignored on older APIs).
- Each LocalVault copy carries a fresh random **non-secret** ownership token in the clip description extras (never the copied value); a clear only happens if the current clip still carries that exact token.
- Android 10+ denies clipboard reads to an unfocused app. When the 30s timer fires while backgrounded and the clipboard can't be read, LocalVault does **not** blindly clear it (that content might be legitimately unreadable-but-still-ours, or might already be something else) — it defers, keeping only the non-secret token+expiry, and retries on `onResume`/regained window focus.
- If the clipboard is readable and its token doesn't match (or is absent), LocalVault forgets its own ownership and leaves the content untouched — it never erases another app's copy.
- No copied value (password, username, or TOTP code) is ever retained merely to support this cleanup logic.
- Manually verified on a real device across three scenarios: (A) foreground — LocalVault's own value clears after ~30s while the app stays open; (B) background-then-return — an expired LocalVault value that couldn't be cleared while backgrounded is safely cleared on return; (C) ownership — a value copied by another app after LocalVault's copy is never erased.
- **Explicitly not claimed:** the Windows clipboard sequence-number guarantee. Android offers no equivalent, and this must never be described as though it does.

## 14. SAF / recent-vault model (current)

- Vault selection: `Intent.ACTION_OPEN_DOCUMENT` + `CATEGORY_OPENABLE`, broad `*/*` type (no assumption of a registered `.lvault` MIME type).
- No broad storage/filesystem permission is requested; the manifest declares no permissions at all.
- Reads happen once per unlock attempt via `ContentResolver.openInputStream`, bounded to 32 MiB (mirroring the desktop adapter's bound); no silent internal copy of the vault is made.
- Recent-vault history persists only `{uri string, display name}` per entry (max 5, SharedPreferences), alongside a **persisted read-only** URI grant taken only when Android actually returns the persistable flag. Stale/revoked grants are detected on reuse and the item is safely dropped with a generic, non-technical message.
- No master password, decrypted data, or vault content of any kind is ever persisted by the Android app.
- **B1–B4 are strictly read-only.** There is no writable-SAF path, no save/replace, no atomic-update semantics, and no external-change detection on Android yet — all of that is 1T-B5's job, and it must not simply copy the desktop's path-based rename/lock model onto SAF's URI/document model (which doesn't support it the same way). See §22 for the exact open questions 1T-B5 must answer.

## 15. Categories / TOTP (current, from B4 — see §11 for the fuller story)

- Categories: `CategorySummary { id, name, entry_count }` from `VaultSession::list_categories()`, backed directly by `VaultData.categories` and each entry's `category_id: Option<Uuid>` — no new persisted semantics invented. "Uncategorized" is a real state of the existing model (`category_id == None`), surfaced as a transient Android-only filter, never persisted.
- TOTP: `VaultSession::totp_status(entry_id, unix_time_seconds) -> TotpStatus { code, remaining_seconds, period_seconds }`, generated entirely by `localvault_core::totp::generate_totp` for an Android-supplied wall-clock Unix time — no TOTP algorithm exists in Kotlin or in the bridge, and the secret never crosses FFI. UI shows the code only when configured, live-rotates it (regeneration only on the once-per-second tick, never per animation frame), supports copy through the same protected clipboard, and clears fully on leaving detail/lock/background.

## 16. Desktop build caveat (important — read before assuming "the desktop app" means current source)

During 1T-era diagnostics it was discovered that `C:\Users\nikita\Desktop\LocalVault.exe` — the file the user actually double-clicks — is byte-identical (SHA256) to the immutable `v1.0.0` release. It predates the light-UI redesign and TOTP entirely. **Current source at HEAD was not rolled back** — it contains both the light UI (`cb4b4fe`/`a61c466`) and TOTP (`af1b2e6`/`47c2315`) as ancestors; this was confirmed by `git merge-base --is-ancestor` checks, not assumed.

To run the **current** desktop source safely (verified working in-session): from `D:\LocalVault`, run

```
npm run tauri dev
```

This uses the project's own configured dev workflow (`tauri.conf.json`'s `beforeDevCommand: npm run dev` for Vite, then `cargo run` in the default **debug** profile). It builds to `src-tauri\target\debug\localvault.exe` and never touches `src-tauri\target\release\LocalVault.exe` (the file that currently holds the preserved `v1.0.0` binary) or the Desktop shortcut. Confirmed in-session: both preserved `v1.0.0` binaries' hashes were identical before and after running this command.

**Do not run `cargo build --release`** without first explicitly deciding what to do about the `v1.0.0` binary currently sitting at `src-tauri\target\release\LocalVault.exe` — a plain release build would silently overwrite it in place.

## 17. Primary vs. backup vault caveat (important — a real QA confusion, not a data-loss bug)

Two different, confirmed-distinct encrypted files exist at `C:\Users\nikita\Downloads\LocalVault\`:
- **Primary:** `LocalSave.lvault` — the file desktop's recent-vault config (`%APPDATA%\com.localvault.app\recent-vaults.json`) actually points at.
- **Backup:** `LocalSave.lvault.backup` — a different file (different size, different SHA256), written by the same atomic-save operation a few milliseconds before the primary.

During QA, Android's SAF picker had been pointed at the `.backup` file (confirmed by its selected-document display name), while desktop was reading the primary — two genuinely different files, not the same file observed twice. This fully explained an apparent entry-count mismatch between the two platforms without any evidence of data loss or corruption; neither file was decrypted to reach this conclusion, only path/size/hash metadata was compared.

**Do not use `.backup` as the working vault during normal QA** — only re-select it intentionally when specifically testing recovery behavior.

## 18. Desktop vs. Android UX differences (recorded, not yet reconciled)

Desktop groups multiple profiles/accounts under a shared site card; Android (B1–B4) currently renders each profile/account as its own flat row. So desktop may show fewer top-level cards than Android shows rows even when the underlying entry/profile count is identical — **this is a UX/grouping difference, not data loss.** Whether/how Android should adopt desktop's site/profile grouping is an open decision for later Android UX work, not yet scheduled into a specific stage.

## 19. User-requested follow-ups (recorded, not implemented)

1. **Desktop auto-lock timing.** The user reports the current 60-second desktop inactivity lock (see `@docs/SECURITY_MODEL.md`) is too aggressive. Requested: a Settings screen/section with a configurable auto-lock duration, default **5 minutes**, likely options 1/5/15/30 minutes. Do not casually add a "Never" option without a deliberate security decision. This does **not** change Android's immediate background-lock behavior (§12) — that stays as-is regardless of whatever the desktop default becomes.
2. **Desktop button/icon visual polish.** Observed in the current light UI: plus-icon/text alignment, contrast, and spacing issues on buttons such as "Новая запись" ("New entry"), and general primary/secondary/new-profile button consistency. Cosmetic, not scheduled.
3. **Android site/profile grouping mismatch** — see §18.

None of these are blocking or scheduled into a specific stage yet; keep them on the radar but do not let them derail 1T-B5's critical path.

## 20. Known blockers

- **Android release `panic = "abort"`** (see §12) — must be resolved before any production Android release build. Not solved.
- **`applicationId`/package** was `com.localvault.android.proof` (B4-era blocker) — resolved; now `com.localvault.android` (see §32).

## 21. Test baseline at 1T-B4

- `localvault-android-bridge`: 24 tests PASS (categories, TOTP fixed-time generation matching the desktop-pinned RFC 6238 vector, secret-field-exclusion checks, locked-session rejection, schema-1/schema-2 compatibility).
- `localvault-core`: 43 tests PASS.
- `compat_baseline`: 6 tests PASS.
- `data_storage_integration`: 1 test PASS.
- Strict clippy (bridge and workspace default-members): PASS.
- `cargo check` / `cargo check --release` / `cargo check --workspace`: PASS.
- `npm run build` (frontend): PASS.
- Android debug build (`build-android-debug.ps1`): PASS, APK contains no bundled compatibility fixture.
- Real-device manual verification: progressively confirmed through B1b, B2, B3, and B4 (see each section above).

**Do not quote the old 1S-era aggregate ("228 Rust tests PASS") as the current exact total** — it predates the Android bridge crate's own 24 tests and should be re-verified against current HEAD before being cited again.

## 22. What remains in 1T (do not mark 1T complete)

- Android write/save.
- Safe SAF replacement/recovery semantics (this is genuinely different from desktop's path-based atomic rename/lock model — SAF gives you a document `Uri`, not a filesystem path with rename semantics).
- Vault creation on Android.
- Add/edit/delete entries.
- Add/edit/delete profiles, to whatever extent is needed for parity with desktop.
- Category mutation (create/rename/delete/assign).
- TOTP setup/edit/remove (currently Android can only *display* an existing TOTP configuration created on desktop).
- `applicationId`/package cleanup (done since — see §32).
- Site/profile grouping decision (§18).
- Large-vault list performance/optimization decision (currently a plain `LinearLayout`; fine for typical vaults, not validated at scale — e.g. near the core's 50,000-entry cap).
- The Android release `panic = "abort"` blocker (§20).
- A final Android security/UX/regression pass once write support lands.

## 23. Next: 1T-B5 — safe Android write/create/CRUD foundation (historical — B5 is now implemented, see §31)

This is the next major implementation task. **It must not be implemented in the chat that produced this handoff — start it in a new Claude chat.** Before any B5 source edits, that new chat must perform a focused security/storage architecture review (audit-first, per `@CLAUDE.md`'s "for high-risk or architectural work: audit first, design second, implementation third" rule) covering at minimum:

- Writable SAF document access (what grant is actually needed, and only when actually needed — do not request write permission speculatively).
- Rust-owned mutation: how `VaultSession` gains mutation methods without exposing `VaultData` or letting Kotlin construct persisted structures directly.
- Core serialization/encryption reuse (reseal/rewrap paths already exist in `localvault-core::vault::format` — inspect them before assuming anything new is needed there).
- Safe failure behavior on a write (no partial/corrupt vault left behind).
- Backup/recovery semantics appropriate to SAF, not a copy of desktop's filesystem-based backup.
- External-change detection (SAF has no OS-level file-lock equivalent to desktop's).
- Stale-write handling.
- Concurrent-session behavior (what happens if the same document is opened elsewhere).
- Compatibility with the exact same persisted vault format desktop writes — no format fork.

Do not mix sync (1U/1V) into 1T-B5.

## 24. Later roadmap (unchanged, for context only — not started)

- **1U — sync foundation:** provider abstraction, encrypted sync state, revision semantics, conflict detection, offline-first, safe atomic updates, recovery path. No naive last-write-wins. A sync provider/server must never receive the master password, plaintext Vault Key, plaintext credentials, or plaintext TOTP secrets.
- **1V — multi-device sync hardening.**
- **1W — Android security/UX:** TOTP QR scanning, biometric unlock, Android Autofill, Android secure-storage-backed convenience unlock. Depends on 1T (Android MVP) being done — 1T is not done yet.
- **1X — final hardening/release** (both platforms).

## 25. Platform scope

Current and planned platforms: **Windows desktop** and **Android**, plus future encrypted multi-device **sync**. **iOS is not on the roadmap.** Do not propose iPhone/iOS/Xcode/Keychain work unless the roadmap is explicitly changed by the user.

## 26. Claude working protocol

- **Fable is forbidden.** Do not use it, ever, for LocalVault work.
- **Sonnet 5 is the normal development model.** Use Opus 5 only when there is a concrete, stated reason Sonnet 5 is insufficient for the task at hand.
- Do not spend High reasoning effort on trivial tasks.
- **Before every Claude task**, explicitly state: current chat or new chat, model, mode, effort, and a short reason for each choice.
  - Security-sensitive architecture/audit work: Plan mode, usually High effort.
  - Normal implementation: Edit-automatically mode, Medium or High effort depending on complexity.
  - Auto mode is **not** the default for security-sensitive work. "Yes, and auto-accept edits" is a permission setting, not the same thing as choosing model "Auto" — don't conflate them.
- Chat lifecycle: don't open a new chat for every small recovery task; reuse the current chat while its context is still useful. Start a **new** chat at clean stage boundaries or once context has gone stale. **This handoff is exactly that boundary — 1T-B5 must start in a new chat.**

## 27. Phone protocol

The user does not always leave the Android phone connected. Before any task that might need it, explicitly state one of:

- "📱 Телефон сейчас НУЖЕН" (phone needed now)
- "📱 Телефон сейчас НЕ нужен" (phone not needed now)

Do not silently assume `adb`/device availability. Most Android source and build work does **not** require the physical phone (build/test gates all run without it); reserve the phone for final manual device QA when it's genuinely required, and when unavailable, report a pending-device status rather than blocking or fabricating results.

## 28. Git protocol

Before any substantial work:

```
git branch --show-current
git rev-parse HEAD
git status --porcelain=v1 -uall
```

For continuation context: `git log -5 --oneline` (or more, as needed).

- Never assume anything has been pushed — check explicitly against the remote if it matters.
- Keep the staging area empty until implementation and tests are accepted; do not stage speculatively.
- Commit only at explicit, accepted checkpoints. **Never push or tag automatically** — only on explicit user request.
- PowerShell guard/automation scripts must be parser-safe end to end: a parser error partway through a script invalidates any apparent "PASS" output that printed before the error.
- Always review the exact changed-file scope (`git status`, `git diff --name-status`) before declaring a task's git hygiene clean — don't just trust that only the intended files changed.

## 29. Security / dependency rules (recap)

- Add a dependency only when genuinely justified; explain why. No dynamic/floating versions for anything security-relevant (UniFFI stays pinned exactly). Never run a global `cargo update`.
- Crypto-adjacent dependency changes need deliberate review, not a drive-by bump.
- No silent vault-schema/semantic changes.
- No duplicate platform cryptography — `localvault-core` stays platform-neutral and owns all crypto/format/schema/TOTP logic; adapters (desktop `src-tauri`, `android/` + `crates/localvault-android-bridge`) hold only: Tauri IPC, desktop filesystem/storage, Android `ContentResolver`/SAF, clipboard, lifecycle, platform UI, platform timers/clock reads, network/favicon fetching, and platform dialogs.

## 30. New-chat startup checklist

A fresh Claude chat picking up LocalVault work after this handoff should, in order:

1. Read: `@CLAUDE.md`, `@docs/PROJECT_STATUS.md`, `@docs/ROADMAP.md`, `@docs/ARCHITECTURE.md`, `@docs/SECURITY_MODEL.md`, `@docs/HANDOFF_1S_COMPLETE.md`, and this file (`@docs/HANDOFF_1T_PROGRESS.md`).
2. Verify repository state:
   ```
   git branch --show-current
   git rev-parse HEAD
   git status --porcelain=v1 -uall
   git log -5 --oneline
   ```
3. Only then plan 1T-B5 (or whatever the next task actually is by that point — re-check `@docs/PROJECT_STATUS.md` rather than assuming B5 is still next if time has passed and other work may have landed).

Repository docs and Git history are authoritative over any prior chat's conversational memory, including this document once it, too, goes stale.

## 31. Update: 1T-B5 write/CRUD series (complete through B5c)

Added after the B4-era snapshot above; supersedes the "read-only"/"B5 next" statements in §12, §14, §22 and §23. Git and the four concise docs still win.

**Checkpoints (in order):** `1abf5e4` B5a (transactional SAF save infrastructure) · `5c20513` B5b-1 · `3ebbed5` B5b-2 · `60e26c4` B5b-3 (vault creation) · `18a0034` B5b-4 (entry CRUD UI) · `32a0754` B5b-5 (category CRUD UI) · `0224fee` B5b-6 (save-recovery hardening) · `9f8f6411f2dd0303458bb541c8a0a401c5f813ce` B5c-1 · `4d75bb81042dfcf339073240472b2129265f23e1` B5c-2. B5a–B5b per-step detail lives in the commit history and was not recorded in this file before.

**1T-B5c — TOTP set / replace / remove (COMPLETE)**
- **B5c-1:** bridge `stage_set_entry_totp(entry_id, setup_input, now_ms)` and `stage_remove_entry_totp(entry_id, now_ms)` (UniFFI equivalents exposed to Kotlin) and thin `VaultSaveCoordinator.saveSetEntryTotp` / `saveRemoveEntryTotp` wrappers using the same `runStagedSave` pipeline as every other mutation.
- **B5c-2:** Android TOTP management UI in `MainActivity.kt` (+ EN/RU strings, new `TotpMutationUiTest.kt`; exactly four source files). Dedicated `TOTP_SETUP` screen entered from entry detail (set and replace); detail shows a "not set up" card with a set-up action when TOTP is absent, and Replace / Remove next to the existing code card when present; Remove requires an explicit confirmation dialog. TOTP mutations reuse the existing mutation token and `entryMutationGeneration`; the new finisher refreshes the session-derived cache after a success even if the UI moved on, and `ChangedExternally` locks with the existing message.
- **Invariants:** `localvault-core` is the sole owner of TOTP parsing/validation/generation; Kotlin does not parse, normalize or construct TOTP configuration. Raw setup input crosses FFI only as direct mutation input (verbatim). Read/display state exposes only `totp_enabled` plus generated `TotpStatus`, never the secret. The input is not put in snapshots, Bundles, status objects, toasts or logs, and is wiped on cancel / Back / background / lock / destroy. Android `onStop` still locks immediately. Create-with-TOTP was deliberately not added (create the entry, then configure TOTP from detail). QR setup/scanning is not part of B5c and remains deferred to 1W.
- **B5c-1 validation:** bridge 77 tests PASS; desktop `localvault` lib: 178 tests PASS; clippy / `cargo check` / `cargo check --release` PASS; schema 1 → 2 TOTP mutation path covered; coordinator tests cover success, validation errors, `ProviderNotWritable`, stale #1/#2, snapshot failure, write failure and readback failure; immutable Windows `v1.0.0` executables unchanged.
- **B5c-2 validation:** Android debug build PASS; targeted `TotpMutationUiTest` PASS; full Android JVM suite PASS; immutable `v1.0.0` executables unchanged.
- **Real-device QA (Android 16 / SDK 36):** bare Base32 setup succeeded and the generated code matched an independent calculation; invalid replacement input caused no write and the raw input did not appear in logcat; Cancel, system Back, and HOME/`onStop` with unsaved input caused no vault write, and HOME/`onStop` locked immediately and discarded the input; an `otpauth://` replacement (SHA256, 8 digits, 45 s period) succeeded and matched an independent calculation; remove-confirmation Cancel caused no write; a confirmed remove persisted across lock/reopen; `ChangedExternally` was detected before overwrite, forced a safe lock/reopen, and did not overwrite the externally changed primary; no tested TOTP secret/URI/canary appeared in logcat; no crash/ANR in the tested scenarios.
- **Desktop ⇄ Android compatibility (both directions):** an Android-created TOTP vault opened in current desktop source and produced the same independently calculated code; a desktop-created SHA256 / 8-digit / 45 s TOTP vault opened on Android and produced the same code. Vault files were transferred byte-identically; the immutable release executables were not rebuilt or modified.
- **`ProviderNotWritable`:** B5c did **not** repeat a dedicated real-device read-only-grant test. That SAF path was proven during B5b device QA, and the B5c coordinator tests show the new TOTP wrappers inherit it. No QA-only revoke/fault harness was reintroduced into production code to repeat it.

**B5 correctness follow-ups (both CLOSED; not a new named stage).** These were open after B5c and are now implemented and accepted, in this order:

*Follow-up B — staged candidate left pending after `WriteFailed` — `cfe9e6f24be55e3ebc6889f209f7141db22938b4` (`fix: discard Android staged save after write failure`):*
- After any of the three failed/unverified primary-write paths — (1) the primary write throws, (2) the readback throws, (3) the readback bytes do not exactly match the staged bytes — `VaultSaveCoordinator` discards the Rust staged candidate before returning `WriteFailed`, so a later mutation is no longer rejected with `PendingUnsavedChanges`.
- The recovery marker and encrypted pre-write snapshot are untouched; `baselineSha256` is not advanced; no new lock is introduced.
- A retry is still protected by stale check #1: if the failed write changed the primary, the retry returns `ChangedExternally` and recovery state remains available for reconciliation.
- The cleanup catches only `IllegalStateException` (the legitimate concurrent-close race); unrelated bridge/`InternalException` failures are not swallowed.
- Rust production bridge code was not changed; one non-redundant Rust regression test was added.
- Validation: `localvault-android-bridge` 78 tests PASS; desktop `localvault` lib: 178 tests PASS; full Android JVM suite PASS (`VaultSaveCoordinatorTest` ran 44 tests); `cargo fmt --check` PASS; `cargo clippy --all-targets --all-features -- -D warnings` PASS for workspace targets; targeted `cargo check -p localvault-android-bridge` and `cargo clippy -p localvault-android-bridge --all-targets --all-features -- -D warnings` PASS; `cargo check` and `cargo check --release` PASS; full `android/scripts/build-android-debug.ps1` PASS; `git diff --check` PASS; immutable Windows `v1.0.0` executables unchanged.

*Follow-up A — session-derived cache not refreshed after a stale entry save/delete completion — `d1a85e44a0e45fddc7973ed88cb36ae034dea050` (`fix: refresh Android entry cache after stale completion`):*
- The mutation's owning `VaultSaveCoordinator` is passed into `finishEntrySave` / `finishEntryDelete`. A successful completion refreshes the session-derived caches only if that coordinator is still the current live `saveCoordinator`, regardless of UI generation.
- A stale completion does not resurrect or overwrite the current screen: LIST and CATEGORY_MANAGE may redraw after the safe refresh; DETAIL redraws only for the same existing mutated entry; ENTRY_EDIT and TOTP_SETUP are never redrawn by a stale completion. It does not clear edit state, overwrite status, toast stale results, or wipe newer input.
- `ChangedExternally` locks only if the Activity is alive and the mutation's coordinator still owns the current live session. The same coordinator-live gate now also applies to `finishCategoryMutation`, so an old callback from a replaced/closed coordinator cannot lock a newly opened session. TOTP behavior stays consistent with its already-safe ownership pattern.
- Validation: `EntryMutationStaleCompletionTest` 18 tests PASS; `CategoryMutationRedrawTest` 4 tests PASS; `TotpMutationUiTest` 17 tests PASS; full Android JVM suite 145 tests PASS (0 failures/errors/skips); full `android/scripts/build-android-debug.ps1` PASS; `git diff --check` PASS; immutable Windows `v1.0.0` executables unchanged.

*Evidence limits:* no real-device QA was required for either fix. The stale-completion race was not reproduced on a device (JVM tests only), and `ProviderNotWritable` was not re-tested on a device for these follow-ups.

**Vault Key lifetime on Android (documentation correction since B5a — not a newly discovered vulnerability; supersedes the B4-era statement in §12):**
- `open_vault` uses `open_envelope_with_key`; the returned Vault Key (zeroizing `SecretKey`) is stored Rust-side in `SessionState` while the session is unlocked. `PendingVaultCreation` temporarily owns the Vault Key during the create flow until `verify_and_finalize` (moves it into a `SessionState`) or `discard`/drop.
- The Master Key is **not** retained (dropped and zeroized inside `open_envelope_with_key` / `create_envelope_with_key`); the master password is never stored.
- The Vault Key does **not** cross FFI in plaintext. Kotlin receives only opaque UniFFI handles and encrypted `VaultEnvelope` bytes (`wrapped_vault_key` is already wrapped as part of the persisted envelope); decrypted `VaultData` stays Rust-owned; Kotlin never owns cryptographic key material; no plaintext vault data is persisted.
- Purpose: so `stage_*` mutations can reseal the encrypted envelope without storing the master password or re-running Argon2id on every save. This matches the desktop session model conceptually.
- Lock/drop of the session or pending creation drops (zeroizes) the Vault Key along with the rest of the state. While unlocked, the process necessarily holds decrypted secret state and the Vault Key in memory; hostile process-memory inspection while unlocked remains outside the protection boundary in `@docs/SECURITY_MODEL.md`.

**What remains in 1T (do not mark 1T complete; `applicationId`/package cleanup was listed here at the time of writing and is now done — see §32):** site/profile grouping decision / Android vs. desktop UX model (§18), large-vault list performance measurement/optimization, the Android release `panic = "abort"` blocker (§12/§20), known visual polish (including the DETAIL top-action overflow/cutoff), and the final Android security/UX/regression pass. A later dedicated desktop + Android design/UX pass is still planned; the current UI is not considered final. No further named 1T-B stage exists in the roadmap; the next task is chosen from this list and confirmed with the user. Sync (1U/1V) and QR/biometrics/Autofill (1W) stay out of 1T.

## 32. Update: `applicationId`/package cleanup (done; not a new named stage)

- **Old → new identity:** `com.localvault.android.proof` → `com.localvault.android`. No different production identity was documented anywhere in the repo, so the default from the task was used. (Desktop's Tauri identifier `com.localvault.app` is unrelated.)
- **Changed:** `android/app/build.gradle.kts` (`namespace`, `applicationId`); the `package` declaration of all 12 production and 15 JVM-test Kotlin files; the source directories, moved with `git mv` from `.../java/com/localvault/android/proof/` to `.../java/com/localvault/android/` (main and test). `AndroidManifest.xml` needed no change (`.MainActivity` is relative to `namespace`); the build script and no resource referenced the old name.
- **Deliberately untouched:** Rust UniFFI namespace/crate names (`uniffi.localvault_android_bridge`, `localvault-android-bridge`), UniFFI `=0.32.0`, JNA wiring, vault format, permissions (none), lifecycle, UI, and the `SecureClipboard` extras key `com.localvault.android.clip_owner` (a non-secret clip-extras key that never contained `.proof`).
- **Consequence for installed builds:** a build with the new `applicationId` is a different app to Android from a build with the old one. It does not share the old app's private data (recent-vault history, recovery snapshots) or its persisted SAF URI grants; the old proof install may coexist with the new app; if it is no longer wanted, it must be uninstalled separately. The new app must re-select vaults through the picker. Vault files themselves are unaffected.
- **Validation:** full Android JVM suite and the full `android/scripts/build-android-debug.ps1` (see the task report); no device QA required or performed.
- **Still remaining in 1T (do not mark 1T complete):** site/profile grouping decision (§18); large-vault list performance measurement/optimization; the Android release `panic = "abort"` blocker (§12/§20); known visual polish, including the DETAIL top-action overflow/cutoff; the final Android security/UX/regression pass; and a later dedicated desktop + Android design/UX pass (the current UI is not final). No further named 1T-B stage exists; sync (1U/1V) and QR/biometrics/Autofill (1W) stay out of 1T.
