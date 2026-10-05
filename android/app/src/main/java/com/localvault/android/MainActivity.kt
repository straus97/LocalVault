package com.localvault.android

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.animation.ValueAnimator
import android.os.Handler
import android.os.Looper
import android.view.animation.LinearInterpolator
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.text.Editable
import android.text.InputType
import android.text.TextUtils
import android.text.TextWatcher
import android.view.Gravity
import android.view.View
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.window.OnBackInvokedDispatcher
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import java.io.IOException
import uniffi.localvault_android_bridge.EntryInput
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.CategoryInput
import uniffi.localvault_android_bridge.CategorySummary
import uniffi.localvault_android_bridge.EntryDetails
import uniffi.localvault_android_bridge.EntrySummary
import uniffi.localvault_android_bridge.PendingVaultCreationInterface
import uniffi.localvault_android_bridge.VaultSession
import uniffi.localvault_android_bridge.openVault

/**
 * LocalVault Android client: pick or re-open a recent vault, unlock it
 * through localvault-core (via the Rust bridge, off the main thread), search
 * the entry list, open an entry, show/copy its credentials, and lock.
 *
 * Security shape:
 *  - The decrypted vault lives only inside the Rust-owned [VaultSession]. Kotlin
 *    holds only non-secret [EntrySummary]/[EntryDetails] values, and only while
 *    unlocked. Passwords are fetched one at a time, only on an explicit
 *    show/copy, and are never stored in a field, saved, or logged.
 *  - The master password is read from the input, the input is wiped, and the
 *    String is passed straight to the synchronous bridge call on a background
 *    thread. It is never stored, saved, logged or shown.
 *  - The JVM cannot deterministically zeroize Strings (the master password, or
 *    a fetched entry password once it is a Java String or in a TextView), so
 *    no erasure of those copies is claimed; lifetimes are kept narrow instead.
 *  - The vault is locked whenever the Activity leaves the foreground, on Back
 *    from the list, and on explicit Lock -- unconditionally, including while a
 *    save (once one exists) is mid-write; see [VaultSaveCoordinator].
 *  - Only non-secret metadata (document Uri, display name, and a UX-only
 *    write-grant hint) is persisted for the recent-vault list.
 *  - As of 1T-B5a, no UI in this Activity actually writes the vault file yet
 *    (that begins with 1T-B5b's entry/category CRUD screens); this
 *    checkpoint adds the write-capability/save-transaction infrastructure
 *    ([SafDocumentIo], [RecoverySnapshotStore], [VaultSaveCoordinator],
 *    [VaultCreationCoordinator], [runUnlockPreOpenGate]) that those screens will
 *    use, plus the write-grant re-pick flow and the accepted backup-filename
 *    warning, which are both usable standalone.
 */
/**
 * Which screen a stale-generation category mutation completion (see
 * `finishCategoryMutation`) landed on, reduced to only the distinction that
 * decision actually needs. Deliberately not `MainActivity.Screen` itself
 * (private to that class, and this seam has no reason to know about every
 * other screen) -- this is the smallest value that lets the redraw policy
 * below be a plain JVM-testable pure function.
 */
internal enum class CategoryMutationRedrawTarget { LIST, CATEGORY_MANAGE, OTHER }

/**
 * Whether a *stale-generation* category mutation that nonetheless succeeded
 * (and already refreshed the category/entry cache) should force a redraw
 * of [target]. `LIST` and `CATEGORY_MANAGE` are the only two screens whose
 * content depends on that cache; every other screen is left untouched. The
 * `Success`/activity-alive checks stay in `finishCategoryMutation` itself --
 * this helper only ever needs to know the destination.
 */
internal fun shouldRedrawAfterStaleCategoryMutation(target: CategoryMutationRedrawTarget): Boolean =
    target == CategoryMutationRedrawTarget.LIST || target == CategoryMutationRedrawTarget.CATEGORY_MANAGE

/** 1T-B5c-2: which kind of TOTP mutation a completion belongs to. */
internal enum class TotpMutationKind { SET, REMOVE }

/**
 * What `finishTotpMutation` must do for one [SaveOutcome], reduced to a
 * plain value so the mapping is JVM-testable without an Activity or any
 * `R.string` id. Never carries (or derives anything from) the user's setup
 * input -- [SaveOutcome] itself never contains it.
 */
internal enum class TotpOutcomeAction {
    SUCCESS,
    LOCK_CHANGED_EXTERNALLY,
    LOCK_SESSION_LOCKED,
    SHOW_INVALID_KEY,
    SHOW_WRITE_ACCESS_UNAVAILABLE,
    SHOW_GENERIC_FAILURE,
}

/**
 * Only a rejected *setup* input maps to [TotpOutcomeAction.SHOW_INVALID_KEY];
 * every other bridge rejection (including `PendingUnsavedChanges` and, for a
 * remove, `TotpNotConfigured`/`InvalidTotpConfiguration`) is deliberately the
 * generic failure, so the invalid-key wording is never shown for a failure
 * that is not actually about the key the user typed.
 */
internal fun totpOutcomeAction(kind: TotpMutationKind, outcome: SaveOutcome): TotpOutcomeAction =
    when (outcome) {
        SaveOutcome.Success -> TotpOutcomeAction.SUCCESS
        SaveOutcome.ChangedExternally -> TotpOutcomeAction.LOCK_CHANGED_EXTERNALLY
        SaveOutcome.ProviderNotWritable -> TotpOutcomeAction.SHOW_WRITE_ACCESS_UNAVAILABLE
        is SaveOutcome.ValidationFailed ->
            when (outcome.error) {
                is BridgeException.SessionLocked -> TotpOutcomeAction.LOCK_SESSION_LOCKED
                is BridgeException.InvalidTotpConfiguration ->
                    if (kind == TotpMutationKind.SET) {
                        TotpOutcomeAction.SHOW_INVALID_KEY
                    } else {
                        TotpOutcomeAction.SHOW_GENERIC_FAILURE
                    }
                else -> TotpOutcomeAction.SHOW_GENERIC_FAILURE
            }
        SaveOutcome.RecoverySnapshotFailed, SaveOutcome.WriteFailed, is SaveOutcome.UnexpectedError ->
            TotpOutcomeAction.SHOW_GENERIC_FAILURE
    }

/** The screens `finishTotpMutation`'s stale-completion redraw policy distinguishes. */
internal enum class TotpRedrawScreen { LIST, DETAIL, ENTRY_EDIT, TOTP_SETUP, CATEGORY_MANAGE, OTHER }

/**
 * Whether a *stale-generation* TOTP mutation that nonetheless succeeded (and
 * already refreshed the session-derived entry/detail cache) may redraw. Only
 * a DETAIL screen currently showing the very entry that was mutated is ever
 * redrawn -- never TOTP_SETUP (it must not be resurrected or touched), never
 * ENTRY_EDIT, and never a DETAIL for a different entry.
 */
internal fun shouldRedrawAfterStaleTotpMutation(
    currentScreen: TotpRedrawScreen,
    currentDetailEntryId: String?,
    mutatedEntryId: String,
): Boolean = currentScreen == TotpRedrawScreen.DETAIL && currentDetailEntryId == mutatedEntryId

/**
 * Issue 1 (B5 correctness follow-up): whether a finished entry/delete
 * mutation must refresh the session-derived caches (entries, categories,
 * and -- if it is showing the mutated entry -- detail). True only for a
 * persisted `Success` whose [coordinatorLive] flag says the mutating
 * coordinator is still the current `saveCoordinator`. Deliberately independent
 * of the UI generation: a mutation that outlived a navigation has still
 * changed Rust/disk state, so the live session's cache must follow it. A
 * completion from a coordinator that was since locked/replaced must not
 * refresh anything.
 */
internal fun entryMutationRefreshesCache(outcome: SaveOutcome, coordinatorLive: Boolean): Boolean =
    outcome == SaveOutcome.Success && coordinatorLive

/**
 * Whether a `ChangedExternally` completion must lock the session. The
 * mutation's coordinator being still the current `saveCoordinator` means it
 * owns the live session, so that session no longer represents disk truth and
 * must be closed (fail closed). A replaced/dead coordinator belongs to a
 * session that was already locked, so locking again would wrongly close an
 * unrelated newer session. UI generation is intentionally NOT an input:
 * navigating away makes it stale but must never keep a live session open.
 */
internal fun changedExternallyLocksSession(activityAlive: Boolean, coordinatorLive: Boolean): Boolean =
    activityAlive && coordinatorLive

/**
 * Whether a *stale-generation* entry create/update/delete that already
 * refreshed the cache may redraw the user's current screen. Reuses
 * [TotpRedrawScreen]'s screen set. LIST and CATEGORY_MANAGE depend only on
 * the refreshed cache; DETAIL is redrawn only for the very entry that was
 * mutated (a create has no known entry id, so [mutatedEntryId] is null and
 * DETAIL is never redrawn for it). ENTRY_EDIT and TOTP_SETUP are never
 * redrawn: `render()` there would destroy the user's in-progress input.
 */
internal fun shouldRedrawAfterStaleEntryMutation(
    currentScreen: TotpRedrawScreen,
    currentDetailEntryId: String?,
    mutatedEntryId: String?,
): Boolean =
    when (currentScreen) {
        TotpRedrawScreen.LIST, TotpRedrawScreen.CATEGORY_MANAGE -> true
        TotpRedrawScreen.DETAIL -> mutatedEntryId != null && currentDetailEntryId == mutatedEntryId
        TotpRedrawScreen.ENTRY_EDIT, TotpRedrawScreen.TOTP_SETUP, TotpRedrawScreen.OTHER -> false
    }

class MainActivity : Activity() {

    private enum class Screen { NO_FILE, FILE_SELECTED, UNLOCKING, LIST, DETAIL, CREATE_PASSWORD, CREATE_IN_PROGRESS, ENTRY_EDIT, CATEGORY_MANAGE, TOTP_SETUP, RECOVERY_NEEDED }

    private class VaultReadException : Exception()

    /** Transient UI filter; "uncategorized" is a real state of the model (no category id). */
    private sealed class CategoryFilter {
        object All : CategoryFilter()

        object Uncategorized : CategoryFilter()

        class Category(val id: String) : CategoryFilter()
    }

    private companion object {
        const val REQUEST_PICK_VAULT = 1

        // 1T-B5a: re-picking an existing recent vault to obtain a write
        // grant. A distinct request code from REQUEST_PICK_VAULT so
        // onActivityResult can apply the accepted grant-intersection logic
        // (Revision 3, section 3) instead of the plain read-only path.
        const val REQUEST_ENABLE_WRITE = 2

        // 1T-B5b-3: `ACTION_CREATE_DOCUMENT` for a brand-new vault. Distinct
        // from both codes above so onActivityResult can apply the
        // create-specific grant-intersection + live-writability check
        // (section C of the accepted vault-creation-UI task) before ever
        // showing the master-password screen.
        const val REQUEST_CREATE_VAULT = 3

        // Mirrors the desktop adapter's vault file size bound.
        const val MAX_VAULT_FILE_BYTES = 32L * 1024 * 1024

        const val PASSWORD_MASK = "••••••••"

        // Fine-grained so the animated bar has no visible one-second steps.
        const val TOTP_PROGRESS_MAX = 10_000
    }

    private lateinit var content: LinearLayout
    private lateinit var scroll: ScrollView
    private lateinit var recents: RecentVaultStore
    private lateinit var clipboard: SecureClipboard

    // 1T-B5a write-capability infrastructure. Neither holds any secret --
    // documentIo wraps ContentResolver calls, recovery is the durable
    // ciphertext-only pre-write snapshot store. Not yet driving any save
    // (there is no entry-edit UI until 1T-B5b), but reconciliation already
    // runs on every unlock so an interrupted save from a future save path
    // is never silently mis-reported.
    private lateinit var documentIo: SafDocumentIo
    private lateinit var recovery: RecoverySnapshotStore
    private var isDebuggable: Boolean = false

    private var screen = Screen.NO_FILE
    private var vaultUri: Uri? = null
    private var vaultName: String = ""
    private var statusRes: Int = 0

    // RECOVERY_NEEDED state -- see runUnlockPreOpenGate/RecoverySnapshotRestorer.
    // recoveryUnresolvedSha256 is the SHA pinned when this screen was last
    // (re-)entered; it changes only when the screen is left entirely, or
    // when an explicit recheck re-pins it and requires a fresh confirmation
    // -- never merely because a restore attempt failed. See finishUnlock/
    // finishRestore for the exact lifecycle.
    private var recoveryUnresolvedSha256: String? = null
    private var restoring: Boolean = false

    private var session: VaultSession? = null
    private var entries: List<EntrySummary> = emptyList()
    private var categories: List<CategorySummary> = emptyList()
    private var categoryFilter: CategoryFilter = CategoryFilter.All
    private var searchQuery: String = ""
    private var listScrollY: Int = 0
    private var detail: EntryDetails? = null

    // 1T-B5b-3 vault-creation state. Holds only non-secret bookkeeping for
    // the document currently being created: its Uri/display name, and
    // exactly which persistable grant flag(s) THIS creation attempt itself
    // took (so terminal cleanup releases only those, never a merely
    // requested flag -- accepted task section C/F). No master password or
    // Rust secret state is ever held in an Activity field; the master
    // password lives only in the password/confirm EditTexts until the
    // background creation thread reads and discards them, exactly like
    // startUnlock's existing pattern.
    private var createDocumentUri: Uri? = null
    private var createDocumentName: String = ""
    private var createTookPersistableRead: Boolean = false
    private var createTookPersistableWrite: Boolean = false

    // Bumped whenever an in-flight creation attempt is abandoned (onStop or
    // Back while CREATE_IN_PROGRESS, or onDestroy) so a late background
    // result is resolved as abandoned rather than shown -- the same pattern
    // unlockGeneration already uses for runUnlock/finishUnlock.
    private var createGeneration = 0

    // Ownership record for whichever PendingVaultCreation the background
    // creation thread has most recently registered via
    // VaultCreationCoordinator's onPendingCreated hook. Generation-scoped
    // (not a bare reference) and guarded by createLock so that:
    //  - a registration racing behind an onStop/onDestroy-driven
    //    abandonment can never store a pending object for a generation that
    //    is already stale -- it observes the bumped createGeneration under
    //    the same lock and discards immediately instead;
    //  - an onStop/onDestroy abandonment can never miss a pending object
    //    that is registered concurrently -- the two paths take the same
    //    lock, so exactly one of them observes the "current" state and acts
    //    on it, with no window where an abandoned generation's pending
    //    exists but is unreachable by either side;
    //  - a late-finishing OLD attempt's cleanup can only ever detach a slot
    //    that still records its OWN generation, so it can never clear,
    //    discard or overwrite a NEWER attempt's live pending reference.
    // pending.discard() itself (a JNA/native call) is always performed
    // OUTSIDE this lock, once ownership has already been decided under it.
    private class PendingCreationSlot(val generation: Int, val pending: PendingVaultCreationInterface)

    private val createLock = Any()
    private var activePendingSlot: PendingCreationSlot? = null

    // 1T-B5b-4 entry-edit/delete state. entryId == null means create mode.
    // categoryId is preserved verbatim from the entry being edited (or null
    // for a new entry) -- this checkpoint does not add a category picker;
    // that is B5b-5's job (accepted task, section A). editInitialPassword
    // holds the one explicit entryPassword fetch, only long enough to be
    // consumed into the password EditText the moment ENTRY_EDIT is rendered
    // -- it is nulled immediately after (see startEditEntry and
    // renderEntryEdit), and is NEVER included in [EntryEditSnapshot] (see
    // that class's own doc comment).
    private var editEntryId: String? = null
    private var editCategoryId: String? = null
    private var editInitialPassword: String? = null

    // A snapshot of the form's non-password content, captured only when a save
    // attempt fails and the user is kept on ENTRY_EDIT to retry -- render()
    // otherwise always rebuilds the form from [detail] (edit mode) or blank
    // (create mode), which would silently discard whatever the user had just
    // typed. Consumed (and cleared) the next time the form is rendered.
    //
    // Deliberately carries no password field: submitEntryEdit always wipes
    // the password EditText the instant it reads it into the outgoing
    // EntryInput, success or failure, and this snapshot must never become a
    // second place that value survives. A failed save therefore always
    // requires the password to be retyped -- the same accepted-task
    // hygiene rule CREATE_PASSWORD already follows on any failure.
    private data class EntryEditSnapshot(
        val title: String,
        val profileName: String,
        val url: String,
        val username: String,
        val notes: String,
        val tags: String,
        val favorite: Boolean,
    )

    private var editPendingSnapshot: EntryEditSnapshot? = null

    // Bumped whenever DETAIL/ENTRY_EDIT is left without an in-flight
    // create/update/delete resolving first (Back/Cancel, Lock, onStop,
    // onDestroy) so a save/delete that finishes after the fact is silently
    // dropped instead of resurrecting a screen the user already left --
    // mirrors unlockGeneration/createGeneration above. This governs the UI
    // only; it has no bearing on whether the mutation itself is still
    // physically running -- see [activeMutationToken] for that.
    private var entryMutationGeneration = 0

    // 1T-B5b-5: same-purpose generation counter for CATEGORY_MANAGE, bumped
    // wherever that screen is left without an in-flight category
    // create/rename/delete resolving first (Back, Lock, onStop, onDestroy)
    // -- mirrors [entryMutationGeneration] exactly, kept as its own counter
    // only because it governs a different screen. Like its entry
    // counterpart, this governs UI resurrection only; physical mutation
    // ownership is [activeMutationToken] below, shared across both.
    private var categoryMutationGeneration = 0

    // Physical in-flight ownership for entry create/update/delete AND
    // category create/rename/delete, shared across all six so at most one
    // may ever be running at a time against the live session-scoped
    // [saveCoordinator] -- unlike [entryMutationGeneration]/
    // [categoryMutationGeneration] above, this is deliberately NOT reset by
    // navigation (Back/Cancel/Lock): a bare Thread already started cannot be
    // cancelled, and letting a second mutation start against the same
    // coordinator while the first is still running would race
    // VaultSaveCoordinator's own internal baseline-hash state. Only the
    // matching completion callback (finishEntrySave/finishEntryDelete/
    // finishCategoryMutation) may clear ownership, and only if it still
    // holds the exact token it was given -- a late completion from an
    // abandoned attempt can therefore never clear a newer attempt's
    // ownership, because with a single slot a newer attempt could not have
    // started in the first place while the older one still held it.
    private var mutationTokenCounter = 0L
    private var activeMutationToken: Long? = null

    /** Returns a fresh ownership token, or null if a mutation is already in flight. */
    private fun beginMutation(): Long? {
        if (activeMutationToken != null) return null
        val token = ++mutationTokenCounter
        activeMutationToken = token
        return token
    }

    /** No-op unless [token] is still the current owner -- see the field doc comment above. */
    private fun endMutationIfOwned(token: Long) {
        if (activeMutationToken == token) {
            activeMutationToken = null
        }
    }

    // Session-scoped save coordinator (Blocker 1 fix): constructed exactly
    // once per live [session], from the exact ciphertext bytes that produced
    // it (the unlock envelope bytes, or vault-creation's committed readback
    // bytes) -- never rebuilt from a fresh disk read per mutation, which
    // would silently discard the external-change protection
    // VaultSaveCoordinator's own baselineSha256 tracking exists to provide.
    // Always cleared in the same places [session] itself is cleared or
    // replaced (lockVault, onDestroy, a forced reopen after
    // SaveOutcome.ChangedExternally) so it can never outlive the
    // VaultSession it wraps.
    private var saveCoordinator: VaultSaveCoordinator? = null

    // Views that hold user-entered or revealed text; nulled on every render.
    private var passwordField: EditText? = null
    private var confirmPasswordField: EditText? = null
    private var searchField: EditText? = null
    private var rowsContainer: LinearLayout? = null
    private var countView: TextView? = null
    private var passwordValueView: TextView? = null
    private var passwordToggleButton: Button? = null
    private var passwordShown = false
    private var chipsContainer: LinearLayout? = null
    private var editTitleField: EditText? = null
    private var editProfileField: EditText? = null
    private var editUrlField: EditText? = null
    private var editUsernameField: EditText? = null
    private var editPasswordField: EditText? = null
    private var editNotesField: EditText? = null
    private var editTagsField: EditText? = null
    private var editFavoriteCheckbox: CheckBox? = null
    private var editCategorySpinner: Spinner? = null

    // Live TOTP display. Only non-secret timing is kept in fields; the code
    // itself lives solely in the visible view and is cleared with it.
    private val totpHandler = Handler(Looper.getMainLooper())
    private var totpTicker: Runnable? = null
    private var totpCodeView: TextView? = null
    private var totpRemainingView: TextView? = null
    private var totpProgress: ProgressBar? = null
    private var totpProgressAnimator: ValueAnimator? = null
    private var totpExpiresAtMs = 0L
    private var totpPeriodSeconds = 30

    // 1T-B5c-2 TOTP_SETUP state. Deliberately only: which entry is being
    // edited, whether it is a replace, and the live EditText while rendered.
    // The raw setup input (a secret) lives ONLY inside that EditText until
    // submit -- it is never held in a String field, snapshot, Bundle, status
    // or log (see submitTotpSetup). Wiped/nulled by clearTotpSetupState().
    private var totpSetupEntryId: String? = null
    private var totpSetupReplacing: Boolean = false
    private var totpSetupField: EditText? = null

    // The Remove-2FA confirmation dialog, kept only so it can be dismissed
    // on lock/onStop/onDestroy. Carries no secret.
    private var removeTotpDialog: AlertDialog? = null

    // Bumped on every lock/stop/destroy so a late background result for an
    // abandoned unlock is discarded (and its session closed) instead of shown.
    private var unlockGeneration = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Screenshots and recents thumbnails are blocked in every build except
        // a debuggable one (so development screenshots stay possible). This is
        // derived from the app's real debuggable state, not a hard-coded flag.
        isDebuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!isDebuggable) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }

        recents = RecentVaultStore(this)
        clipboard = SecureClipboard.get(this)
        documentIo = ContentResolverSafDocumentIo(this)
        recovery = FileRecoverySnapshotStore(this)

        content = LinearLayout(this)
        content.orientation = LinearLayout.VERTICAL
        content.setPadding(dp(20), dp(16), dp(20), dp(32))

        scroll = ScrollView(this)
        scroll.isFillViewport = true
        scroll.addView(content)

        // Edge-to-edge (targetSdk 36): inset the body by the system bars,
        // display cutout and keyboard so nothing is drawn under them.
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val bars =
                    insets.getInsets(
                        WindowInsets.Type.systemBars() or
                            WindowInsets.Type.displayCutout() or
                            WindowInsets.Type.ime(),
                    )
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            } else {
                @Suppress("DEPRECATION")
                view.setPadding(
                    insets.systemWindowInsetLeft,
                    insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight,
                    insets.systemWindowInsetBottom,
                )
            }
            WindowInsets.CONSUMED
        }

        setContentView(scroll)

        // Predictive back (targetSdk 36) no longer calls onBackPressed().
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            onBackInvokedDispatcher.registerOnBackInvokedCallback(
                OnBackInvokedDispatcher.PRIORITY_DEFAULT,
            ) { handleBack() }
        }

        render()
    }

    @Deprecated("Used only below API 33; newer APIs use OnBackInvokedCallback.")
    @Suppress("OVERRIDE_DEPRECATION")
    override fun onBackPressed() {
        handleBack()
    }

    override fun onResume() {
        super.onResume()

        // Catch-up: if a LocalVault-owned clip expired while the app could not
        // read the clipboard, finish the cleanup now (ownership-verified).
        clipboard.cleanupExpiredOwnedClipIfPossible()
    }

    // Clipboard reads are only possible while the window has focus (Android 10+).
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)

        clipboard.setAppFocused(hasFocus)
    }

    override fun onStop() {
        super.onStop()

        clipboard.setAppFocused(false)

        when (screen) {
            Screen.LIST, Screen.DETAIL, Screen.UNLOCKING, Screen.CATEGORY_MANAGE, Screen.RECOVERY_NEEDED -> lockVault()
            Screen.ENTRY_EDIT -> {
                editPasswordField?.let { wipe(it) }
                lockVault()
            }
            Screen.TOTP_SETUP -> {
                totpSetupField?.let { wipe(it) }
                lockVault()
            }
            Screen.CREATE_IN_PROGRESS -> abandonCreateInProgress()
            else -> {
                // CREATE_PASSWORD included: no Rust secret state exists yet
                // at this screen (PendingVaultCreation is only ever
                // constructed inside submitCreatePassword's background call),
                // so -- like FILE_SELECTED before it -- backgrounding here
                // only needs to wipe the typed-but-uncommitted password
                // text, not abandon the already-created document/grant.
                passwordField?.let { wipe(it) }
                confirmPasswordField?.let { wipe(it) }
            }
        }
    }

    override fun onDestroy() {
        stopTotp()
        unlockGeneration++
        entryMutationGeneration++
        categoryMutationGeneration++
        clearEntryEditState()
        clearTotpSetupState()
        dismissRemoveTotpDialog()
        val current = session
        session = null
        saveCoordinator = null
        entries = emptyList()
        categories = emptyList()
        detail = null
        closeQuietly(current)

        // Defense in depth alongside onStop's abandonCreateInProgress(),
        // which normally already runs first in the ordinary Activity
        // lifecycle: never leave a Rust PendingVaultCreation reachable past
        // this Activity's destruction.
        abandonActivePendingCreation()?.let { discardPendingQuietly(it) }

        super.onDestroy()
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == REQUEST_ENABLE_WRITE) {
            finishEnableWriteAccess(resultCode, data)
            return
        }

        if (requestCode == REQUEST_CREATE_VAULT) {
            finishCreateVaultPicker(resultCode, data)
            return
        }

        if (requestCode != REQUEST_PICK_VAULT || resultCode != RESULT_OK) return
        val uri = data?.data ?: return

        val name = queryDisplayName(uri) ?: getString(R.string.default_vault_name)

        // Remember the vault only if a persistable READ grant was actually
        // taken; otherwise the Uri would just go stale after a restart.
        if (takePersistableRead(uri, data.flags)) {
            rememberVault(RecentVault(uri, name))
        }

        selectVault(uri, name)
    }

    /**
     * 1T-B5a: re-pick result for upgrading an existing recent vault to
     * write access (accepted review, Revision 3, section 3).
     *
     * By the time this runs, launching the picker has already put this
     * Activity through the ordinary `onStop`/lock path if a session
     * happened to be open -- nothing here special-cases or works around
     * that. Only the grant is handled; the user must explicitly re-unlock
     * before editing if a session was dropped.
     */
    private fun finishEnableWriteAccess(resultCode: Int, data: Intent?) {
        if (resultCode != RESULT_OK) return
        val uri = data?.data ?: return

        val granted = grantedPermissionsFrom(data.flags)
        val grant = takeGrantedPersistablePermissions(contentResolver, uri, granted)

        recents.updateGrant(uri, grant)
        statusRes = if (grant == VaultGrant.READ_WRITE) 0 else R.string.msg_write_access_not_granted
        render()
    }

    // ---------------------------------------------------------------- back

    private fun handleBack() {
        when (screen) {
            Screen.DETAIL -> closeDetail()
            Screen.LIST, Screen.UNLOCKING, Screen.RECOVERY_NEEDED -> lockVault()
            Screen.CREATE_IN_PROGRESS -> abandonCreateInProgress()
            Screen.CREATE_PASSWORD -> cancelCreatePassword()
            Screen.ENTRY_EDIT -> cancelEntryEdit()
            Screen.CATEGORY_MANAGE -> closeCategoryManage()
            Screen.TOTP_SETUP -> cancelTotpSetup()
            Screen.FILE_SELECTED -> {
                vaultUri = null
                vaultName = ""
                statusRes = 0
                screen = Screen.NO_FILE
                render()
            }
            Screen.NO_FILE -> finish()
        }
    }

    // ---------------------------------------------------------------- vault choice

    @Suppress("DEPRECATION")
    private fun openPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        // Read access only; ask for a grant that survives process restarts.
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        startActivityForResult(intent, REQUEST_PICK_VAULT)
    }

    /**
     * 1T-B5a: re-invoke the system picker to upgrade [vault] from read-only
     * to a write-capable grant. Does not require, and does not assume, a
     * currently-live unlocked session for this vault (accepted review,
     * Revision 3, section 3) -- launching this picker may drop one via the
     * ordinary `onStop` lock path exactly like any other backgrounding.
     */
    @Suppress("DEPRECATION")
    private fun requestWriteAccess(vault: RecentVault) {
        // SAF has no reliable, cross-provider way to pre-navigate the
        // picker to a specific document, so the user must reselect it
        // manually -- tell them which file, since selecting a different one
        // creates a distinct grant rather than "upgrading" this entry.
        Toast.makeText(
            this,
            getString(R.string.msg_reselect_for_write, vault.name.ifEmpty { getString(R.string.default_vault_name) }),
            Toast.LENGTH_LONG,
        ).show()

        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        intent.addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
        )
        startActivityForResult(intent, REQUEST_ENABLE_WRITE)
    }

    private fun selectVault(uri: Uri, name: String) {
        vaultUri = uri
        vaultName = name
        statusRes = 0
        screen = Screen.FILE_SELECTED
        render()
    }

    private fun selectRecent(vault: RecentVault) {
        val stillGranted =
            contentResolver.persistedUriPermissions.any { it.uri == vault.uri && it.isReadPermission }

        if (!stillGranted) {
            forgetVault(vault.uri)
            statusRes = R.string.msg_recent_unavailable
            render()
            return
        }

        rememberVault(vault)
        selectVault(vault.uri, vault.name)
    }

    private fun takePersistableRead(uri: Uri, flags: Int): Boolean {
        if ((flags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION) == 0) return false

        return try {
            contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            true
        } catch (error: Exception) {
            false
        }
    }

    /**
     * 1T-B5a post-QA fix: an automatically-evicted vault (the recent list's
     * 5-item cap pushing out its oldest entry) is not equivalent to
     * explicitly forgetting it. Its grant/recovery state is only released
     * and cleaned up when nothing is unresolved for it; a genuinely
     * unresolved save is left fully intact -- grant and recovery state both
     * -- so it stays reachable/reconcilable despite falling out of the
     * visible recent list (see [evictionOutcomeFor]).
     */
    private fun rememberVault(vault: RecentVault) {
        for (evicted in recents.promote(vault)) {
            val outcome = evictionOutcomeFor(recovery.hasUnresolvedMarker(evicted.uri.toString()))
            if (outcome == EvictionOutcome.RELEASE_AND_FORGET) {
                releaseGrant(evicted.uri)
                recovery.forget(evicted.uri.toString())
            }
        }
    }

    private fun forgetVault(uri: Uri) {
        recents.remove(uri)
        releaseGrant(uri)
        recovery.forget(uri.toString())
    }

    /**
     * 1T-B5a: "forget vault" cleanup with the accepted unresolved-marker
     * warning (Revision 3, section 7). Removing a vault that has no
     * unresolved save in flight behaves exactly as before -- no dialog, no
     * behavior change for the overwhelming majority of vaults, since B5a
     * introduces no UI that can actually leave a save unresolved yet.
     */
    private fun confirmForgetVault(vault: RecentVault) {
        if (!recovery.hasUnresolvedMarker(vault.uri.toString())) {
            forgetVault(vault.uri)
            statusRes = 0
            render()
            return
        }

        AlertDialog.Builder(this)
            .setTitle(R.string.forget_vault_unresolved_title)
            .setMessage(R.string.forget_vault_unresolved_message)
            .setPositiveButton(android.R.string.ok) { _, _ ->
                forgetVault(vault.uri)
                statusRes = 0
                render()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun releaseGrant(uri: Uri) {
        try {
            contentResolver.releasePersistableUriPermission(
                uri,
                Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
            )
        } catch (ignored: Exception) {
        }
    }

    // ---------------------------------------------------------------- vault creation
    //
    // 1T-B5b-3. Hard ordering invariant (accepted task, section A): the
    // picker launches with NO master password collected and NO Rust secret
    // state of any kind constructed; only after it returns, the app is
    // foreground again, and this specific attempt has proven a durable
    // persisted write grant plus a live writable document, is the password
    // screen ever shown; only then is begin_create_vault ever called.

    @Suppress("DEPRECATION")
    private fun startCreateVault() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        intent.putExtra(Intent.EXTRA_TITLE, getString(R.string.default_new_vault_filename))
        intent.addFlags(
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION,
        )
        startActivityForResult(intent, REQUEST_CREATE_VAULT)
    }

    /**
     * Picker result for a brand-new document (section C). Evaluated only
     * from the ACTUAL returned `Intent` flags -- never assumed from what was
     * requested. A cancelled/no-result picker is a pure no-op: nothing was
     * created, nothing to clean up.
     */
    private fun finishCreateVaultPicker(resultCode: Int, data: Intent?) {
        if (resultCode != RESULT_OK) return
        val uri = data?.data ?: return

        val granted = grantedPermissionsFrom(data.flags)
        val tookRead = granted.persistable && granted.read && tryTakeCreatedPersistable(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        val tookWrite = granted.persistable && granted.write && tryTakeCreatedPersistable(uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION)

        // Both a durable persisted write grant actually taken by THIS
        // attempt, and a live provider write-capability check, are required
        // before the password screen may ever appear (section C).
        if (!tookWrite || !documentIo.supportsWrite(uri.toString())) {
            cleanUpFailedCreation(
                uri,
                queryDisplayName(uri) ?: getString(R.string.default_vault_name),
                tookRead,
                tookWrite,
                failureMessageRes = R.string.msg_create_vault_not_writable,
            )
            screen = if (vaultUri != null) Screen.FILE_SELECTED else Screen.NO_FILE
            render()
            return
        }

        createDocumentUri = uri
        createDocumentName = queryDisplayName(uri) ?: getString(R.string.default_vault_name)
        createTookPersistableRead = tookRead
        createTookPersistableWrite = tookWrite
        statusRes = 0
        screen = Screen.CREATE_PASSWORD
        render()
    }

    private fun tryTakeCreatedPersistable(uri: Uri, flag: Int): Boolean {
        return try {
            contentResolver.takePersistableUriPermission(uri, flag)
            true
        } catch (ignored: SecurityException) {
            false
        }
    }

    private fun cancelCreatePassword() {
        val uri = createDocumentUri
        if (uri != null) {
            cleanUpFailedCreation(uri, createDocumentName, createTookPersistableRead, createTookPersistableWrite)
        }
        clearCreateState()
        screen = if (vaultUri != null) Screen.FILE_SELECTED else Screen.NO_FILE
        render()
    }

    private fun submitCreatePassword() {
        val uri = createDocumentUri ?: return
        val pwField = passwordField ?: return
        val confirmField = confirmPasswordField ?: return

        val password = pwField.text.toString()
        val confirm = confirmField.text.toString()

        // UI-level-only validation (section D): purely local, no bridge
        // call, same document/grant retained, stays on CREATE_PASSWORD.
        // Matching "empty master password" client-side is deliberate here,
        // not an invented policy -- localvault-core's create_envelope_with_key
        // already rejects an empty master password unconditionally
        // (VaultError::EmptyMasterPassword), so this only avoids a doomed
        // round trip; no password-strength rule beyond emptiness is added.
        if (password.isEmpty()) {
            wipeCreatePasswordFields()
            statusRes = R.string.msg_empty_password
            render()
            return
        }
        if (password != confirm) {
            wipeCreatePasswordFields()
            statusRes = R.string.msg_password_mismatch
            render()
            return
        }

        wipeCreatePasswordFields()

        val name = createDocumentName
        val tookRead = createTookPersistableRead
        val tookWrite = createTookPersistableWrite

        val generation = synchronized(createLock) { ++createGeneration }
        statusRes = 0
        screen = Screen.CREATE_IN_PROGRESS
        render()

        Thread {
            val outcome =
                try {
                    VaultCreationCoordinator(documentIo).createVault(
                        uri.toString(),
                        password,
                        System.currentTimeMillis(),
                        onPendingCreated = { pending -> registerPendingCreation(generation, pending) },
                    )
                } catch (error: Exception) {
                    CreateVaultOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishCreateVault(generation, uri, name, tookRead, tookWrite, outcome) }
        }.start()
    }

    /**
     * [VaultCreationCoordinator]'s `onPendingCreated` hook, invoked from the
     * background creation thread the instant a real `PendingVaultCreation`
     * exists -- possibly well after `begin_create_vault`'s Argon2id
     * derivation, which can outlast an intervening onStop/Back/onDestroy.
     *
     * Registration is atomic with respect to abandonment: both this method
     * and [abandonActivePendingCreation] take [createLock] around their
     * compound check-and-mutate step, so exactly one of "this generation is
     * still current, store the slot" or "this generation was already
     * abandoned, discard immediately" is ever true for a given attempt --
     * there is no window where an abandoned generation's pending state
     * exists but is unreachable by both sides. [pending.discard] itself
     * (a JNA/native call) always runs outside the lock.
     */
    private fun registerPendingCreation(generation: Int, pending: PendingVaultCreationInterface) {
        val discardNow =
            synchronized(createLock) {
                if (generation == createGeneration) {
                    activePendingSlot = PendingCreationSlot(generation, pending)
                    false
                } else {
                    // Already abandoned by the time beginCreateVault
                    // returned: never store it as the live in-flight
                    // pending, and never touch activePendingSlot, which may
                    // already legitimately belong to a newer attempt.
                    true
                }
            }
        if (discardNow) discardPendingQuietly(pending)
    }

    /**
     * Resolves one [VaultCreationCoordinator.createVault] result (section E's
     * outcome matrix). [uri]/[name]/[tookRead]/[tookWrite] are exactly the
     * values captured at the start of this specific attempt in
     * [submitCreatePassword] -- never re-read from the current
     * `createDocumentUri` field, which may already belong to a newer
     * attempt by the time this runs.
     *
     * When [generation] no longer matches [createGeneration] (the app was
     * backgrounded or the user pressed Back mid-attempt --
     * [abandonCreateInProgress] already ran), this never re-shows
     * CREATE_PASSWORD/CREATE_IN_PROGRESS or touches the current screen at
     * all: it only disposes of whatever this now-abandoned attempt produced
     * (closes a session that did finalize, or runs the shared cleanup for a
     * document that did not) -- exactly mirroring finishUnlock's existing
     * stale-generation handling for runUnlock.
     */
    private fun finishCreateVault(
        generation: Int,
        uri: Uri,
        name: String,
        tookRead: Boolean,
        tookWrite: Boolean,
        outcome: CreateVaultOutcome,
    ) {
        // Bookkeeping only: this generation's PendingVaultCreation has
        // already been resolved one way or another by the coordinator
        // itself (consumed by verify_and_finalize, or discarded on a
        // failure path) -- or, if abandonment raced ahead first, was never
        // stored here at all. Only detach the slot if it still belongs to
        // THIS generation, so a late-finishing OLD attempt can never clear
        // a NEWER attempt's live pending reference (guarded, not a bare
        // unconditional clear).
        clearPendingCreationSlotIfOwnedBy(generation)
        val stale = generation != createGeneration || isFinishing || isDestroyed
        // Guards state-clearing against a newer attempt already having
        // reused createDocumentUri/grant-tracking fields while this
        // (stale) attempt's background thread was still resolving.
        val sameAttempt = createDocumentUri == uri

        when (outcome) {
            is CreateVaultOutcome.Success -> {
                // Unconditional per the accepted invariant: a vault is
                // added to recents if and only if verify_and_finalize
                // returned success -- independent of whether this Activity
                // is still showing this attempt.
                rememberVault(RecentVault(uri, name, VaultGrant.READ_WRITE))

                if (stale) {
                    // The vault by itself is genuinely valid and durable on
                    // disk; only this Activity's live, unlocked view of it
                    // is dropped -- matching "the vault is locked whenever
                    // the Activity leaves the foreground" unconditionally.
                    closeQuietly(outcome.session)
                    if (sameAttempt) clearCreateState()
                    return
                }

                clearCreateState()
                closeQuietly(session)
                session = outcome.session
                // Blocker 1 fix: constructed from the exact committed
                // ciphertext bytes verify_and_finalize accepted -- see
                // CreateVaultOutcome.Success's own doc comment.
                saveCoordinator = VaultSaveCoordinator(outcome.session, documentIo, recovery, outcome.committedEnvelopeBytes)
                entries = emptyList()
                categories = emptyList()
                categoryFilter = CategoryFilter.All
                searchQuery = ""
                listScrollY = 0
                vaultUri = uri
                vaultName = name
                statusRes = 0
                screen = Screen.LIST
            }

            is CreateVaultOutcome.ValidationFailedBeforeWrite -> {
                // Retryable only for the still-live, non-stale attempt: no
                // document write ever happened, so the same document/grant
                // may safely retry. A stale (abandoned) attempt is always
                // resolved as terminal instead -- it must never resurrect
                // CREATE_PASSWORD after the user has already backed out or
                // backgrounded the app.
                if (!stale) {
                    wipeCreatePasswordFields()
                    statusRes = R.string.msg_create_vault_failed
                    screen = Screen.CREATE_PASSWORD
                } else {
                    cleanUpFailedCreation(uri, name, tookRead, tookWrite)
                    if (sameAttempt) clearCreateState()
                    return
                }
            }

            CreateVaultOutcome.ProviderNotWritable,
            CreateVaultOutcome.WriteFailed,
            is CreateVaultOutcome.ValidationFailedAfterWrite,
            is CreateVaultOutcome.UnexpectedError,
            -> {
                cleanUpFailedCreation(uri, name, tookRead, tookWrite)
                if (sameAttempt) clearCreateState()
                if (stale) return
                screen = if (vaultUri != null) Screen.FILE_SELECTED else Screen.NO_FILE
            }
        }

        render()
    }

    private fun abandonCreateInProgress() {
        abandonActivePendingCreation()?.let { discardPendingQuietly(it) }
        statusRes = 0
        screen = if (vaultUri != null) Screen.FILE_SELECTED else Screen.NO_FILE
        // createDocumentUri/grant-tracking fields are deliberately left set:
        // the (now-invalidated) background attempt still owns resolving the
        // document/grant/recents fate for itself once its outcome is known
        // -- see finishCreateVault's stale branch above.
        render()
    }

    /**
     * Atomically bumps [createGeneration] and detaches whatever
     * [PendingCreationSlot] is currently registered -- which, once the bump
     * has happened under the same lock, necessarily belongs to the now-stale
     * prior generation, never to a generation that has not started yet.
     * Used by both onStop's [abandonCreateInProgress] and `onDestroy`. The
     * returned pending (if any) is discarded by the caller OUTSIDE this
     * lock, per [PendingCreationSlot]'s own documentation.
     */
    private fun abandonActivePendingCreation(): PendingVaultCreationInterface? =
        synchronized(createLock) {
            createGeneration++
            val slot = activePendingSlot
            activePendingSlot = null
            slot?.pending
        }

    private fun clearPendingCreationSlotIfOwnedBy(generation: Int) {
        synchronized(createLock) {
            if (activePendingSlot?.generation == generation) {
                activePendingSlot = null
            }
        }
    }

    private fun discardPendingQuietly(pending: PendingVaultCreationInterface) {
        try {
            pending.discard()
        } catch (ignored: Throwable) {
        }
    }

    /**
     * Shared terminal cleanup (section F): best-effort delete of the newly
     * created document, then release of only the persistable flag(s) THIS
     * attempt itself took -- never a merely requested flag. Never touches
     * recents. Sets [statusRes] to [failureMessageRes] on a successful
     * delete, or shows a manual-cleanup [Toast] naming only the display
     * filename (never secret material) when delete failed or is
     * unsupported -- that message is always the generic one, since a
     * manual-cleanup instruction is itself the more specific, actionable
     * detail at that point.
     */
    private fun cleanUpFailedCreation(
        uri: Uri,
        name: String,
        tookRead: Boolean,
        tookWrite: Boolean,
        failureMessageRes: Int = R.string.msg_create_vault_failed,
    ) {
        val deleted =
            try {
                DocumentsContract.deleteDocument(contentResolver, uri)
            } catch (ignored: Exception) {
                false
            }

        if (tookRead) releaseCreatedGrant(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        if (tookWrite) releaseCreatedGrant(uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION)

        if (deleted) {
            statusRes = failureMessageRes
        } else {
            statusRes = 0
            Toast.makeText(this, getString(R.string.msg_create_vault_manual_cleanup, name), Toast.LENGTH_LONG).show()
        }
    }

    private fun releaseCreatedGrant(uri: Uri, flag: Int) {
        try {
            contentResolver.releasePersistableUriPermission(uri, flag)
        } catch (ignored: Exception) {
        }
    }

    private fun clearCreateState() {
        createDocumentUri = null
        createDocumentName = ""
        createTookPersistableRead = false
        createTookPersistableWrite = false
    }

    private fun wipeCreatePasswordFields() {
        passwordField?.let { wipe(it) }
        confirmPasswordField?.let { wipe(it) }
    }

    // ---------------------------------------------------------------- unlock / lock

    private fun startUnlock() {
        val uri = vaultUri ?: return
        val field = passwordField ?: return

        val password = field.text.toString()
        if (password.isEmpty()) {
            statusRes = R.string.msg_empty_password
            render()
            return
        }

        wipe(field)

        val generation = ++unlockGeneration
        statusRes = 0
        screen = Screen.UNLOCKING
        render()

        Thread { runUnlock(uri, password, generation) }.start()
    }

    /**
     * Runs on a dedicated background thread: file read + Argon2id + list.
     *
     * 1T-B5a/B5b-6 recovery fix: before treating this unlock as normal,
     * [runUnlockPreOpenGate] resolves any unresolved save marker left by an
     * interrupted write against the vault's actual current disk content
     * (accepted review, Revision 3, section 5) -- strictly *before* any
     * attempt to parse/decrypt that content, using the one primary read
     * this function performs. `openVault` is reached only when the gate
     * permits it, with exactly the bytes the gate itself read.
     */
    private fun runUnlock(uri: Uri, password: String, generation: Int) {
        var opened: VaultSession? = null
        var openedEnvelopeBytes: ByteArray? = null
        var rows: List<EntrySummary> = emptyList()
        var cats: List<CategorySummary> = emptyList()
        var messageRes = 0
        var unreadable = false
        var reconciliationOutcome: ReconciliationOutcome? = null
        var recoveryPrimarySha: String? = null

        try {
            when (
                val gateResult = runUnlockPreOpenGate(
                    readMarker = { recovery.readMarker(uri.toString()) },
                    readCurrentBytes = { readVaultBytes(uri) },
                    clearMarker = { recovery.clearMarker(uri.toString()) },
                    openPrimary = { bytes -> openVault(bytes, password) },
                )
            ) {
                is UnlockGateResult.RecoveryNeeded -> {
                    reconciliationOutcome = ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY
                    recoveryPrimarySha = gateResult.unresolvedPrimarySha256
                }
                is UnlockGateResult.Opened -> {
                    opened = gateResult.value
                    openedEnvelopeBytes = gateResult.envelopeBytes
                    reconciliationOutcome = gateResult.reconciliationOutcome
                    rows = opened.listEntries()
                    cats = opened.listCategories()
                }
            }
        } catch (error: BridgeException.AuthenticationFailed) {
            messageRes = R.string.msg_auth
        } catch (error: BridgeException.UnsupportedFormat) {
            messageRes = R.string.msg_format
        } catch (error: VaultReadException) {
            messageRes = R.string.msg_read
            unreadable = true
        } catch (error: IOException) {
            messageRes = R.string.msg_read
            unreadable = true
        } catch (error: SecurityException) {
            messageRes = R.string.msg_read
            unreadable = true
        } catch (error: Throwable) {
            messageRes = R.string.msg_generic
        }

        if (messageRes != 0) {
            closeQuietly(opened)
            opened = null
        }

        val result = opened
        val resultEnvelopeBytes = openedEnvelopeBytes
        runOnUiThread {
            finishUnlock(
                generation,
                uri,
                result,
                resultEnvelopeBytes,
                rows,
                cats,
                messageRes,
                unreadable,
                reconciliationOutcome,
                recoveryPrimarySha,
            )
        }
    }

    private fun readVaultBytes(uri: Uri): ByteArray {
        val stream = contentResolver.openInputStream(uri) ?: throw VaultReadException()

        stream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            var total = 0L

            while (true) {
                val read = input.read(buffer)
                if (read < 0) break

                total += read
                if (total > MAX_VAULT_FILE_BYTES) throw VaultReadException()

                output.write(buffer, 0, read)
            }

            return output.toByteArray()
        }
    }

    /** Back on the main thread. */
    private fun finishUnlock(
        generation: Int,
        uri: Uri,
        opened: VaultSession?,
        openedEnvelopeBytes: ByteArray?,
        rows: List<EntrySummary>,
        cats: List<CategorySummary>,
        messageRes: Int,
        unreadable: Boolean,
        reconciliationOutcome: ReconciliationOutcome? = null,
        recoveryPrimarySha: String? = null,
    ) {
        if (generation != unlockGeneration || screen != Screen.UNLOCKING || isFinishing || isDestroyed) {
            closeQuietly(opened)
            return
        }

        if (reconciliationOutcome == ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY) {
            // runUnlockPreOpenGate never calls openVault in this case, so
            // `opened` is guaranteed null here -- never claims
            // UnsupportedFormat/auth failure, never shows the vault.
            closeQuietly(opened)
            session = null
            saveCoordinator = null
            recoveryUnresolvedSha256 = recoveryPrimarySha
            statusRes = 0
            screen = Screen.RECOVERY_NEEDED
            render()
            return
        }

        if (opened != null && openedEnvelopeBytes != null) {
            session = opened
            // Blocker 1 fix: constructed from the exact ciphertext bytes that
            // produced this session -- never re-read from disk per mutation,
            // so VaultSaveCoordinator's own baseline tracking is the sole
            // source of truth for external-change detection, exactly as
            // 1T-B5a/B5b-2 already proved it.
            saveCoordinator = VaultSaveCoordinator(opened, documentIo, recovery, openedEnvelopeBytes)
            entries = rows
            categories = cats
            categoryFilter = CategoryFilter.All
            searchQuery = ""
            listScrollY = 0
            statusRes = 0
            screen = Screen.LIST
        } else if (unreadable && recents.load().any { it.uri == uri }) {
            // A remembered vault that can no longer be read is stale: forget it.
            forgetVault(uri)
            vaultUri = null
            vaultName = ""
            statusRes = R.string.msg_recent_unavailable
            screen = Screen.NO_FILE
        } else {
            statusRes = if (messageRes != 0) messageRes else R.string.msg_generic
            screen = Screen.FILE_SELECTED
        }

        render()
    }

    /**
     * [messageRes], when non-zero, is shown after locking -- used by the
     * forced-reopen path after [SaveOutcome.ChangedExternally] (Blocker 2) to
     * surface [R.string.msg_vault_changed_externally] without a second,
     * separate status-clearing step. Every ordinary Lock/Back/onStop call
     * site is unaffected (defaults to the existing silent-lock behavior).
     */
    private fun lockVault(messageRes: Int = 0) {
        unlockGeneration++
        entryMutationGeneration++
        categoryMutationGeneration++
        clearEntryEditState()
        clearTotpSetupState()
        dismissRemoveTotpDialog()

        val current = session
        session = null
        saveCoordinator = null
        entries = emptyList()
        categories = emptyList()
        categoryFilter = CategoryFilter.All
        detail = null
        searchQuery = ""
        listScrollY = 0
        clearRevealedPassword()
        recoveryUnresolvedSha256 = null
        restoring = false
        closeQuietly(current)

        statusRes = messageRes
        screen = if (vaultUri != null) Screen.FILE_SELECTED else Screen.NO_FILE
        render()
    }

    private fun closeQuietly(target: VaultSession?) {
        if (target == null) return

        try {
            target.lock()
        } catch (ignored: Throwable) {
        }

        try {
            target.close()
        } catch (ignored: Throwable) {
        }
    }

    // ---------------------------------------------------------------- detail

    private fun openDetail(entryId: String) {
        val current = session ?: return

        try {
            detail = current.entryDetails(entryId)
        } catch (error: BridgeException.SessionLocked) {
            lockVault()
            return
        } catch (error: Throwable) {
            toast(R.string.msg_action_failed)
            return
        }

        listScrollY = scroll.scrollY
        screen = Screen.DETAIL
        render()
    }

    private fun closeDetail() {
        entryMutationGeneration++
        clearRevealedPassword()
        detail = null
        screen = Screen.LIST
        render()
        scroll.post { scroll.scrollTo(0, listScrollY) }
    }

    private fun togglePassword() {
        if (passwordShown) {
            clearRevealedPassword()
            return
        }

        val entryId = detail?.id ?: return
        val view = passwordValueView ?: return

        // Fetched only now, on an explicit Show; it goes straight into the one
        // view and is not kept in any field.
        val revealed = fetchPassword(entryId) ?: return
        view.text = revealed
        passwordShown = true
        passwordToggleButton?.setText(R.string.hide_password)
    }

    private fun copyPassword() {
        val entryId = detail?.id ?: return
        val value = fetchPassword(entryId) ?: return

        clipboard.copy(getString(R.string.app_name), value, sensitive = true)
        confirmCopied()
    }

    private fun copyUsername() {
        val username = detail?.username ?: return
        if (username.isEmpty()) return

        clipboard.copy(getString(R.string.app_name), username, sensitive = false)
        confirmCopied()
    }

    private fun fetchPassword(entryId: String): String? {
        val current = session ?: return null

        return try {
            current.entryPassword(entryId)
        } catch (error: BridgeException.SessionLocked) {
            lockVault()
            null
        } catch (error: Throwable) {
            toast(R.string.msg_action_failed)
            null
        }
    }

    // ---------------------------------------------------------------- entry create/edit/delete
    //
    // 1T-B5b-4. One shared ENTRY_EDIT screen drives both create ([editEntryId]
    // null) and edit (non-null) via VaultSaveCoordinator.saveCreateEntry /
    // saveUpdateEntry, and DETAIL's Delete action drives saveDeleteEntry --
    // never stageCreateEntry/stageUpdateEntry/stageDeleteEntry directly, and
    // never a duplicate write-capability pre-check: SaveOutcome.
    // ProviderNotWritable already reflects the coordinator's own live
    // grant/provider re-check.

    private fun clearEntryEditState() {
        editPasswordField?.let { wipe(it) }
        editEntryId = null
        editCategoryId = null
        editInitialPassword = null
        editPendingSnapshot = null
        // Deliberately does NOT touch activeMutationToken -- see that
        // field's own doc comment: navigation must not let a second
        // mutation start while an earlier one is still physically running
        // against the same session-scoped coordinator.
    }

    private fun startCreateEntry() {
        clearEntryEditState()
        statusRes = 0
        screen = Screen.ENTRY_EDIT
        render()
    }

    /**
     * Prefills the shared editor from the already-fetched [detail] -- no
     * redundant `entryDetails` read -- except for the password, which
     * [EntryDetails] never carries; that one field is fetched here, once,
     * through the same [fetchPassword] path Show/Copy already use.
     */
    private fun startEditEntry() {
        val current = detail ?: return
        val password = fetchPassword(current.id) ?: return

        editEntryId = current.id
        editCategoryId = current.categoryId
        editInitialPassword = password
        editPendingSnapshot = null
        statusRes = 0
        screen = Screen.ENTRY_EDIT
        render()
    }

    private fun cancelEntryEdit() {
        entryMutationGeneration++
        val wasCreate = editEntryId == null
        clearEntryEditState()
        statusRes = 0
        screen = if (wasCreate) Screen.LIST else Screen.DETAIL
        render()
    }

    /** Never includes the password field -- see [EntryEditSnapshot]'s own doc comment. */
    private fun captureEntryEditSnapshot(): EntryEditSnapshot? {
        val title = editTitleField ?: return null
        val profileName = editProfileField ?: return null
        val url = editUrlField ?: return null
        val username = editUsernameField ?: return null
        val notes = editNotesField ?: return null
        val tags = editTagsField ?: return null
        val favorite = editFavoriteCheckbox ?: return null

        return EntryEditSnapshot(
            title = title.text.toString(),
            profileName = profileName.text.toString(),
            url = url.text.toString(),
            username = username.text.toString(),
            notes = notes.text.toString(),
            tags = tags.text.toString(),
            favorite = favorite.isChecked,
        )
    }

    private fun parseTags(raw: String): List<String> =
        raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    private fun submitEntryEdit() {
        val titleField = editTitleField ?: return
        val profileField = editProfileField ?: return
        val urlField = editUrlField ?: return
        val usernameField = editUsernameField ?: return
        val pwField = editPasswordField ?: return
        val notesField = editNotesField ?: return
        val tagsField = editTagsField ?: return
        val favoriteCheckbox = editFavoriteCheckbox ?: return

        val uri = vaultUri ?: return
        val coordinator = saveCoordinator ?: return

        // Conservative fail-closed guard (accepted task section G): never
        // submit a save that would silently drop the entry's real category
        // because it disappeared from the current [categories] list (e.g.
        // deleted by another session) between render and submit.
        if (editCategoryId != null && categories.none { it.id == editCategoryId }) {
            statusRes = R.string.msg_entry_category_missing
            render()
            return
        }

        val token = beginMutation() ?: return

        val input = EntryInput(
            title = titleField.text.toString(),
            profileName = profileField.text.toString(),
            url = urlField.text.toString(),
            username = usernameField.text.toString(),
            password = pwField.text.toString(),
            notes = notesField.text.toString(),
            categoryId = editCategoryId,
            tags = parseTags(tagsField.text.toString()),
            favorite = favoriteCheckbox.isChecked,
        )

        // Security hygiene, matching the CREATE_PASSWORD precedent: never
        // silently retain a just-submitted password in the visible field,
        // success or failure -- a failed attempt requires retyping it. This
        // is also why EntryEditSnapshot never carries a password (Blocker 3).
        wipe(pwField)

        val entryId = editEntryId
        val generation = entryMutationGeneration
        statusRes = 0

        Thread {
            val outcome =
                try {
                    if (entryId == null) {
                        coordinator.saveCreateEntry(uri.toString(), input, System.currentTimeMillis())
                    } else {
                        coordinator.saveUpdateEntry(uri.toString(), entryId, input, System.currentTimeMillis())
                    }
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishEntrySave(generation, token, coordinator, entryId, outcome) }
        }.start()
    }

    private fun refreshEntriesAndCategories() {
        val current = session ?: return

        try {
            entries = current.listEntries()
            categories = current.listCategories()
            normalizeCategoryFilter()
        } catch (error: Throwable) {
            // Best-effort refresh only -- on failure the list simply keeps
            // showing its last-known state until the next successful read.
        }
    }

    /**
     * A successful category delete (or any other refresh) can leave
     * [categoryFilter] pointing at a category id that no longer exists --
     * e.g. LIST was filtered by category X, X had zero entries so its
     * deletion was allowed, and the delete happened from CATEGORY_MANAGE.
     * All/Uncategorized are always valid; only a [CategoryFilter.Category]
     * whose id has disappeared from the just-refreshed [categories] is reset
     * to All so LIST never stays silently filtered by a deleted category
     * with no chip to represent it.
     */
    private fun normalizeCategoryFilter() {
        val filter = categoryFilter
        if (filter is CategoryFilter.Category && categories.none { it.id == filter.id }) {
            categoryFilter = CategoryFilter.All
        }
    }

    /**
     * Shared stale-completion handling for entry create/update/delete (Issue
     * 1). Called when the UI generation went stale or the Activity is no
     * longer alive. Separates three concerns: (1) the session-derived cache
     * refresh, which follows the persisted mutation whenever [coordinatorLive]
     * says it belongs to the current session; (2) the redraw, decided BEFORE
     * the refresh because refreshing may replace/drop [detail]; and (3)
     * suppression of everything else -- no toast, no status, no screen
     * change, no edit/TOTP state touched. [mutatedEntryId] is null for a
     * create.
     */
    private fun finishStaleEntryMutation(
        outcome: SaveOutcome,
        coordinatorLive: Boolean,
        activityAlive: Boolean,
        mutatedEntryId: String?,
    ) {
        if (!entryMutationRefreshesCache(outcome, coordinatorLive)) return

        val redrawAllowed =
            activityAlive &&
                shouldRedrawAfterStaleEntryMutation(currentTotpRedrawScreen(), detail?.id, mutatedEntryId)

        refreshEntriesAndCategories()
        if (mutatedEntryId != null && !refreshDetailIfCurrent(mutatedEntryId)) return

        if (redrawAllowed) render()
    }

    /**
     * Back on the main thread. Handles create/update outcomes identically per section E.
     * [coordinator] is the exact [VaultSaveCoordinator] that performed this
     * attempt (captured in submitEntryEdit), never re-read from the current
     * [saveCoordinator] field, so a completion can tell whether it still
     * belongs to the live session.
     */
    private fun finishEntrySave(
        generation: Int,
        token: Long,
        coordinator: VaultSaveCoordinator,
        entryId: String?,
        outcome: SaveOutcome,
    ) {
        endMutationIfOwned(token)

        val activityAlive = !isFinishing && !isDestroyed
        val coordinatorLive = coordinator === saveCoordinator

        // Blocker 2: ChangedExternally means the live session no longer
        // represents disk truth -- a security-relevant fact independent of
        // whether the user already navigated away from this specific
        // attempt, so it is handled before, and regardless of, the
        // generation-staleness gate below (which governs UI-only outcomes).
        // Never adopt the externally changed bytes into the old session,
        // never auto-retry -- force the user back through FILE_SELECTED to
        // re-unlock. Only the coordinator that still owns the live session
        // may lock it: an old attempt whose session was already locked must
        // not close a newer, unrelated session.
        if (outcome == SaveOutcome.ChangedExternally) {
            if (changedExternallyLocksSession(activityAlive, coordinatorLive)) {
                lockVault(R.string.msg_vault_changed_externally)
            }
            return
        }

        if (generation != entryMutationGeneration || !activityAlive) {
            // ENTRY_EDIT was already left (Back/Lock/onStop/onDestroy) before
            // this resolved. The mutation itself cannot be undone from here,
            // and this Activity's UI has already moved on -- never resurrect
            // ENTRY_EDIT/DETAIL/LIST for a stale result. A persisted success
            // against the still-live session must nevertheless refresh the
            // session-derived cache so LIST/DETAIL/a later Edit never show
            // pre-save values.
            finishStaleEntryMutation(outcome, coordinatorLive, activityAlive, entryId)
            return
        }

        when (outcome) {
            SaveOutcome.Success -> {
                refreshEntriesAndCategories()
                clearEntryEditState()
                toast(R.string.msg_entry_saved)

                if (entryId == null) {
                    statusRes = 0
                    screen = Screen.LIST
                } else {
                    val refreshed =
                        try {
                            session?.entryDetails(entryId)
                        } catch (error: Throwable) {
                            null
                        }
                    if (refreshed != null) {
                        detail = refreshed
                        statusRes = 0
                        screen = Screen.DETAIL
                    } else {
                        detail = null
                        statusRes = 0
                        screen = Screen.LIST
                    }
                }
            }

            // Handled unconditionally above, before the staleness gate --
            // never reached here.
            SaveOutcome.ChangedExternally -> Unit

            SaveOutcome.ProviderNotWritable -> {
                editPendingSnapshot = captureEntryEditSnapshot()
                statusRes = R.string.msg_write_access_unavailable
            }

            is SaveOutcome.ValidationFailed -> {
                editPendingSnapshot = captureEntryEditSnapshot()
                statusRes = R.string.msg_invalid_entry
            }

            SaveOutcome.RecoverySnapshotFailed, SaveOutcome.WriteFailed -> {
                editPendingSnapshot = captureEntryEditSnapshot()
                statusRes = R.string.msg_action_failed
            }

            is SaveOutcome.UnexpectedError -> {
                editPendingSnapshot = captureEntryEditSnapshot()
                statusRes = R.string.msg_action_failed
            }
        }

        render()
    }

    private fun confirmDeleteEntry() {
        val entryId = detail?.id ?: return
        val title = detail?.title ?: ""

        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_delete_entry_title)
            .setMessage(getString(R.string.confirm_delete_entry_message, title))
            .setPositiveButton(R.string.delete) { _, _ -> startDeleteEntry(entryId) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun startDeleteEntry(entryId: String) {
        val uri = vaultUri ?: return
        val coordinator = saveCoordinator ?: return
        val token = beginMutation() ?: return

        val generation = entryMutationGeneration
        statusRes = 0

        Thread {
            val outcome =
                try {
                    coordinator.saveDeleteEntry(uri.toString(), entryId, System.currentTimeMillis())
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishEntryDelete(generation, token, coordinator, entryId, outcome) }
        }.start()
    }

    private fun finishEntryDelete(
        generation: Int,
        token: Long,
        coordinator: VaultSaveCoordinator,
        entryId: String,
        outcome: SaveOutcome,
    ) {
        endMutationIfOwned(token)

        val activityAlive = !isFinishing && !isDestroyed
        val coordinatorLive = coordinator === saveCoordinator

        // See finishEntrySave's identical handling for why this precedes,
        // is independent of the generation-staleness gate below, and is
        // gated on coordinator ownership.
        if (outcome == SaveOutcome.ChangedExternally) {
            if (changedExternallyLocksSession(activityAlive, coordinatorLive)) {
                lockVault(R.string.msg_vault_changed_externally)
            }
            return
        }

        if (generation != entryMutationGeneration || !activityAlive) {
            // See finishEntrySave: a persisted delete against the live
            // session still refreshes the cache (detail becomes null if it
            // was the deleted entry) without touching unrelated UI state.
            finishStaleEntryMutation(outcome, coordinatorLive, activityAlive, entryId)
            return
        }

        when (outcome) {
            SaveOutcome.Success -> {
                refreshEntriesAndCategories()
                clearEntryEditState()
                detail = null
                toast(R.string.msg_entry_deleted)
                statusRes = 0
                screen = Screen.LIST
            }

            // Handled unconditionally above; never reached here.
            SaveOutcome.ChangedExternally -> Unit

            SaveOutcome.ProviderNotWritable -> statusRes = R.string.msg_write_access_unavailable
            is SaveOutcome.ValidationFailed -> statusRes = R.string.msg_invalid_entry
            SaveOutcome.RecoverySnapshotFailed, SaveOutcome.WriteFailed -> statusRes = R.string.msg_action_failed
            is SaveOutcome.UnexpectedError -> statusRes = R.string.msg_action_failed
        }

        render()
    }

    // ---------------------------------------------------------------- category management
    //
    // 1T-B5b-5. CATEGORY_MANAGE drives saveCreateCategory/saveUpdateCategory/
    // saveDeleteCategory through the same session-scoped [saveCoordinator]
    // and the same shared [beginMutation]/[endMutationIfOwned] ownership
    // token entry mutations already use (accepted task section F) -- never
    // a separate category-only busy flag, so an entry mutation and a
    // category mutation can never overlap. [categoryMutationGeneration]
    // mirrors [entryMutationGeneration]: it governs only whether a late
    // completion may resurrect CATEGORY_MANAGE, never whether the mutation
    // itself is still physically running.

    private fun startCategoryManage() {
        statusRes = 0
        screen = Screen.CATEGORY_MANAGE
        render()
    }

    private fun closeCategoryManage() {
        categoryMutationGeneration++
        statusRes = 0
        screen = Screen.LIST
        render()
    }

    /** One-EditText AlertDialog, matching the existing grant-request dialog convention. */
    private fun newDialogField(initialText: String = ""): EditText {
        val field = newField()
        field.hint = getString(R.string.category_name_hint)
        field.setText(initialText)
        field.setSelection(field.text.length)
        return field
    }

    private fun dialogFieldWrapper(field: EditText): View {
        val wrapper = FrameLayout(this)
        val params = FrameLayout.LayoutParams(FrameLayout.LayoutParams.MATCH_PARENT, FrameLayout.LayoutParams.WRAP_CONTENT)
        params.setMargins(dp(24), dp(8), dp(24), dp(8))
        wrapper.addView(field, params)
        return wrapper
    }

    private fun showAddCategoryDialog() {
        val field = newDialogField()
        AlertDialog.Builder(this)
            .setTitle(R.string.add_category)
            .setView(dialogFieldWrapper(field))
            .setPositiveButton(R.string.save) { _, _ -> submitCreateCategory(field.text.toString()) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun showRenameCategoryDialog(category: CategorySummary) {
        val field = newDialogField(category.name)
        AlertDialog.Builder(this)
            .setTitle(R.string.rename_category)
            .setView(dialogFieldWrapper(field))
            .setPositiveButton(R.string.save) { _, _ -> submitRenameCategory(category.id, field.text.toString()) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun confirmDeleteCategory(category: CategorySummary) {
        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_delete_category_title)
            .setMessage(getString(R.string.confirm_delete_category_message, category.name))
            .setPositiveButton(R.string.delete) { _, _ -> submitDeleteCategory(category.id) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun submitCreateCategory(name: String) {
        val uri = vaultUri ?: return
        val coordinator = saveCoordinator ?: return
        val token = beginMutation() ?: return

        val generation = categoryMutationGeneration
        statusRes = 0
        val input = CategoryInput(name = name)

        Thread {
            val outcome =
                try {
                    coordinator.saveCreateCategory(uri.toString(), input, System.currentTimeMillis())
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishCategoryMutation(generation, token, coordinator, outcome, R.string.msg_category_created) }
        }.start()
    }

    private fun submitRenameCategory(categoryId: String, name: String) {
        val uri = vaultUri ?: return
        val coordinator = saveCoordinator ?: return
        val token = beginMutation() ?: return

        val generation = categoryMutationGeneration
        statusRes = 0
        val input = CategoryInput(name = name)

        Thread {
            val outcome =
                try {
                    coordinator.saveUpdateCategory(uri.toString(), categoryId, input, System.currentTimeMillis())
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishCategoryMutation(generation, token, coordinator, outcome, R.string.msg_category_renamed) }
        }.start()
    }

    private fun submitDeleteCategory(categoryId: String) {
        val uri = vaultUri ?: return
        val coordinator = saveCoordinator ?: return
        val token = beginMutation() ?: return

        val generation = categoryMutationGeneration
        statusRes = 0

        Thread {
            val outcome =
                try {
                    coordinator.saveDeleteCategory(uri.toString(), categoryId, System.currentTimeMillis())
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishCategoryMutation(generation, token, coordinator, outcome, R.string.msg_category_deleted) }
        }.start()
    }

    /**
     * Back on the main thread. Shared outcome handling for create/rename/
     * delete (accepted task section E): a distinct [R.string.msg_category_in_use]
     * message is surfaced only when the structured [BridgeException.CategoryInUse]
     * variant is present; every other rejection (including
     * [BridgeException.CategoryNotFound]) falls back to the generic invalid-
     * category message. No raw exception text is ever shown.
     *
     * [coordinator] is the exact [VaultSaveCoordinator] this specific attempt
     * was issued against (captured in submitCreateCategory/
     * submitRenameCategory/submitDeleteCategory), never re-read from the
     * current [saveCoordinator] field -- comparing the two by identity is
     * what lets a mutation that outlives a Back-to-LIST navigation still
     * refresh the right (still-current) session's cached data, while a
     * mutation whose session was since locked/replaced can be recognized as
     * belonging to a coordinator that is no longer live and must not refresh
     * anything.
     */
    private fun finishCategoryMutation(
        generation: Int,
        token: Long,
        coordinator: VaultSaveCoordinator,
        outcome: SaveOutcome,
        successMessageRes: Int,
    ) {
        endMutationIfOwned(token)

        val activityAlive = !isFinishing && !isDestroyed
        val coordinatorLive = coordinator === saveCoordinator

        // See finishEntrySave's identical handling for why ChangedExternally
        // precedes, and is independent of, everything below -- including
        // its coordinator-ownership gate.
        if (outcome == SaveOutcome.ChangedExternally) {
            if (changedExternallyLocksSession(activityAlive, coordinatorLive)) {
                lockVault(R.string.msg_vault_changed_externally)
            }
            return
        }

        val generationStale = generation != categoryMutationGeneration

        if (outcome == SaveOutcome.Success && coordinatorLive) {
            // The mutation succeeded against the session that is still the
            // live one -- refresh the cached data unconditionally, even if
            // CATEGORY_MANAGE's own UI generation is already stale, so a
            // successful category create/rename/delete that outlives a Back
            // to LIST is never left invisible on disk-vs-cache alone
            // (Blocker 2). A completion whose [coordinator] no longer
            // matches [saveCoordinator] belongs to a session that was since
            // locked/replaced/re-created -- refreshing from it would read
            // through a coordinator no longer backed by the live
            // VaultSession, so it is skipped entirely.
            refreshEntriesAndCategories()
        }

        if (generationStale || !activityAlive) {
            // CATEGORY_MANAGE (or the Activity itself) was already left
            // before this resolved. Never resurrect CATEGORY_MANAGE and
            // never show its success/failure toast or status for a stale
            // attempt -- but if the refresh above just updated the cached
            // data and the user is sitting on LIST or back on
            // CATEGORY_MANAGE right now (B5b-5/B5b-6 edge case), redraw it
            // so the successful mutation is immediately visible instead of
            // only becoming visible the next time that screen happens to
            // re-render on its own.
            val redrawTarget =
                when (screen) {
                    Screen.LIST -> CategoryMutationRedrawTarget.LIST
                    Screen.CATEGORY_MANAGE -> CategoryMutationRedrawTarget.CATEGORY_MANAGE
                    else -> CategoryMutationRedrawTarget.OTHER
                }
            if (outcome == SaveOutcome.Success && activityAlive && shouldRedrawAfterStaleCategoryMutation(redrawTarget)) {
                render()
            }
            return
        }

        when (outcome) {
            SaveOutcome.Success -> {
                toast(successMessageRes)
                statusRes = 0
            }

            // Handled unconditionally above; never reached here.
            SaveOutcome.ChangedExternally -> Unit

            SaveOutcome.ProviderNotWritable -> statusRes = R.string.msg_write_access_unavailable

            is SaveOutcome.ValidationFailed -> {
                statusRes =
                    if (outcome.error is BridgeException.CategoryInUse) {
                        R.string.msg_category_in_use
                    } else {
                        R.string.msg_invalid_category
                    }
            }

            SaveOutcome.RecoverySnapshotFailed, SaveOutcome.WriteFailed -> statusRes = R.string.msg_action_failed
            is SaveOutcome.UnexpectedError -> statusRes = R.string.msg_action_failed
        }

        render()
    }

    // ---------------------------------------------------------------- TOTP setup / replace / remove
    //
    // 1T-B5c-2. TOTP mutations are entry mutations: they share
    // [beginMutation]/[endMutationIfOwned] and [entryMutationGeneration] with
    // entry create/update/delete -- no third mutation system. All parsing,
    // normalization and validation of the setup input happens in
    // localvault-core via the bridge; nothing in this Activity inspects it.

    /** Wipes the live setup field (if any) and drops all TOTP_SETUP state. Safe to call repeatedly. */
    private fun clearTotpSetupState() {
        totpSetupField?.let { wipe(it) }
        totpSetupField = null
        totpSetupEntryId = null
        totpSetupReplacing = false
        // Deliberately does NOT touch activeMutationToken -- see that
        // field's own doc comment.
    }

    private fun dismissRemoveTotpDialog() {
        val dialog = removeTotpDialog
        removeTotpDialog = null
        try {
            dialog?.dismiss()
        } catch (ignored: Exception) {
        }
    }

    private fun startTotpSetup() {
        val current = detail ?: return
        if (screen != Screen.DETAIL) return

        // Invalidates any UI completion still in flight from this DETAIL
        // (e.g. a Remove): it can no longer claim this screen transition.
        entryMutationGeneration++
        totpSetupEntryId = current.id
        totpSetupReplacing = current.totpEnabled
        statusRes = 0
        screen = Screen.TOTP_SETUP
        render()
    }

    private fun cancelTotpSetup() {
        entryMutationGeneration++
        clearTotpSetupState()
        statusRes = 0
        screen = if (detail != null) Screen.DETAIL else Screen.LIST
        render()
    }

    private fun submitTotpSetup() {
        val field = totpSetupField ?: return
        val entryId = totpSetupEntryId ?: return
        val uri = vaultUri ?: return
        val coordinator = saveCoordinator ?: return
        if (screen != Screen.TOTP_SETUP || session == null) return

        val token = beginMutation() ?: return

        // Captured exactly once and passed VERBATIM -- no trim, case change,
        // regex, Base32/otpauth parsing or any other inspection. The
        // immutable JVM String cannot be zeroized (no such claim is made); it
        // is held only by the worker lambda below for the duration of the
        // UniFFI call, and the visible field is wiped immediately.
        val setupInput = field.text.toString()
        wipe(field)

        val generation = entryMutationGeneration
        statusRes = 0

        Thread {
            val outcome =
                try {
                    coordinator.saveSetEntryTotp(uri.toString(), entryId, setupInput, System.currentTimeMillis())
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishTotpMutation(generation, token, coordinator, entryId, TotpMutationKind.SET, outcome) }
        }.start()
    }

    private fun confirmRemoveTotp() {
        val current = detail ?: return
        if (screen != Screen.DETAIL || !current.totpEnabled) return
        val coordinator = saveCoordinator ?: return
        val entryId = current.id

        dismissRemoveTotpDialog()

        val dialog =
            AlertDialog.Builder(this)
                .setTitle(R.string.confirm_remove_totp_title)
                .setMessage(R.string.confirm_remove_totp_message)
                .setPositiveButton(R.string.totp_remove) { _, _ -> startRemoveTotp(entryId, coordinator) }
                .setNegativeButton(android.R.string.cancel, null)
                .create()
        dialog.setOnDismissListener {
            if (removeTotpDialog === dialog) removeTotpDialog = null
        }
        removeTotpDialog = dialog
        dialog.show()
    }

    /**
     * Re-checks the live state at confirmation time (the dialog may have been
     * open while state moved on): same live session/coordinator, same DETAIL
     * entry, and TOTP still enabled. No secret exists in this flow.
     */
    private fun startRemoveTotp(entryId: String, expectedCoordinator: VaultSaveCoordinator) {
        val coordinator = saveCoordinator ?: return
        if (coordinator !== expectedCoordinator || session == null) return

        val current = detail
        if (screen != Screen.DETAIL || current == null || current.id != entryId || !current.totpEnabled) return

        val uri = vaultUri ?: return
        val token = beginMutation() ?: return

        val generation = entryMutationGeneration
        statusRes = 0

        Thread {
            val outcome =
                try {
                    coordinator.saveRemoveEntryTotp(uri.toString(), entryId, System.currentTimeMillis())
                } catch (error: Exception) {
                    SaveOutcome.UnexpectedError(error)
                }

            runOnUiThread { finishTotpMutation(generation, token, coordinator, entryId, TotpMutationKind.REMOVE, outcome) }
        }.start()
    }

    /**
     * Re-reads [entryId]'s details from the live session iff [detail] is
     * currently that entry, so a later DETAIL render reflects the committed
     * TOTP state. On a failed read [detail] is dropped (renderDetail falls
     * back to LIST). Returns false only if the session turned out to be
     * locked, in which case the vault has already been locked here.
     */
    private fun refreshDetailIfCurrent(entryId: String): Boolean {
        if (detail?.id != entryId) return true
        val current = session ?: return true

        try {
            detail = current.entryDetails(entryId)
        } catch (error: BridgeException.SessionLocked) {
            lockVault()
            return false
        } catch (error: Throwable) {
            detail = null
        }
        return true
    }

    private fun currentTotpRedrawScreen(): TotpRedrawScreen =
        when (screen) {
            Screen.LIST -> TotpRedrawScreen.LIST
            Screen.DETAIL -> TotpRedrawScreen.DETAIL
            Screen.ENTRY_EDIT -> TotpRedrawScreen.ENTRY_EDIT
            Screen.TOTP_SETUP -> TotpRedrawScreen.TOTP_SETUP
            Screen.CATEGORY_MANAGE -> TotpRedrawScreen.CATEGORY_MANAGE
            else -> TotpRedrawScreen.OTHER
        }

    private fun totpFailureMessageRes(action: TotpOutcomeAction): Int =
        when (action) {
            TotpOutcomeAction.SHOW_INVALID_KEY -> R.string.msg_totp_invalid_key
            TotpOutcomeAction.SHOW_WRITE_ACCESS_UNAVAILABLE -> R.string.msg_write_access_unavailable
            else -> R.string.msg_action_failed
        }

    /**
     * Back on the main thread. Uses the finishCategoryMutation pattern (which
     * finishEntrySave/finishEntryDelete now share): a Success against the
     * still-live [coordinator] always refreshes the session-derived caches/detail, even if this
     * attempt's UI generation went stale, so the committed change is never
     * invisible. A stale or dead-Activity completion never toasts, never
     * returns to TOTP_SETUP and never resurrects any secret UI or session;
     * it may only redraw a DETAIL for the same entry.
     */
    private fun finishTotpMutation(
        generation: Int,
        token: Long,
        coordinator: VaultSaveCoordinator,
        entryId: String,
        kind: TotpMutationKind,
        outcome: SaveOutcome,
    ) {
        endMutationIfOwned(token)

        val activityAlive = !isFinishing && !isDestroyed
        val coordinatorLive = coordinator === saveCoordinator
        val action = totpOutcomeAction(kind, outcome)

        // ChangedExternally (and a locked session) take precedence over
        // everything else: the live session no longer represents disk truth
        // / is not usable. Never adopt stale state; only lock if this
        // coordinator is still the live one (otherwise it was already
        // locked/replaced and there is nothing of this attempt left to close).
        if (action == TotpOutcomeAction.LOCK_CHANGED_EXTERNALLY) {
            if (activityAlive && coordinatorLive) lockVault(R.string.msg_vault_changed_externally)
            return
        }
        if (action == TotpOutcomeAction.LOCK_SESSION_LOCKED) {
            if (activityAlive && coordinatorLive) lockVault()
            return
        }

        // Everything about "where is the user right now" is decided BEFORE
        // the refresh below, which may replace/drop [detail].
        val expectedScreen = if (kind == TotpMutationKind.SET) Screen.TOTP_SETUP else Screen.DETAIL
        val expectedEntryId = if (kind == TotpMutationKind.SET) totpSetupEntryId else detail?.id
        val uiCurrent =
            activityAlive &&
                generation == entryMutationGeneration &&
                screen == expectedScreen &&
                expectedEntryId == entryId
        val redrawAllowed = shouldRedrawAfterStaleTotpMutation(currentTotpRedrawScreen(), detail?.id, entryId)

        val succeeded = action == TotpOutcomeAction.SUCCESS
        if (succeeded && coordinatorLive) {
            refreshEntriesAndCategories()
            if (!refreshDetailIfCurrent(entryId)) return
        }

        if (!uiCurrent) {
            if (succeeded && coordinatorLive && activityAlive && redrawAllowed) render()
            return
        }

        if (succeeded) {
            clearTotpSetupState()
            toast(if (kind == TotpMutationKind.SET) R.string.msg_totp_saved else R.string.msg_totp_removed)
            statusRes = 0
            // The existing totp_status/startTotp path in renderDetail shows
            // (or no longer shows) the code from the committed live session.
            screen = if (detail != null) Screen.DETAIL else Screen.LIST
            render()
            return
        }

        val messageRes = totpFailureMessageRes(action)
        if (kind == TotpMutationKind.SET) {
            // Stay on TOTP_SETUP; the field was already wiped at submit, so
            // the key must be re-entered. Never echoes the input.
            statusRes = messageRes
            render()
        } else {
            // DETAIL has no status area; a toast keeps this non-secret
            // message visible without touching the existing detail layout.
            toast(messageRes)
        }
    }

    // ---------------------------------------------------------------- TOTP

    /**
     * Starts the live TOTP display for the visible detail screen.
     *
     * Two independent cadences share the same wall-clock-derived expiry:
     *  - a main-thread Handler ticking about once a second updates the
     *    "Обновление через N с" text and re-fetches the code (through
     *    localvault-core, via the bridge) only when the period rolls over;
     *  - a [ValueAnimator] animates the progress bar continuously between
     *    those fetches, so it shrinks smoothly instead of stepping once a
     *    second. It never decides the code or the expiry -- both remain
     *    derived from the wall clock and the core-reported period.
     *
     * Neither runs off-screen, and passive ticks/frames are deliberately not
     * user activity.
     */
    private fun startTotp(entryId: String) {
        stopTotp()

        val ticker =
            object : Runnable {
                override fun run() {
                    if (screen != Screen.DETAIL || detail?.id != entryId) return

                    val nowMs = System.currentTimeMillis()
                    if (nowMs >= totpExpiresAtMs && !fetchTotp(entryId, nowMs)) return

                    updateTotpCountdown(nowMs)
                    totpHandler.postDelayed(this, 1000L - (System.currentTimeMillis() % 1000L) + 20L)
                }
            }

        totpTicker = ticker
        ticker.run()
    }

    private fun fetchTotp(entryId: String, nowMs: Long): Boolean {
        val current = session ?: return false

        return try {
            val nowSeconds = nowMs / 1000L
            val status = current.totpStatus(entryId, nowSeconds)

            totpExpiresAtMs = (nowSeconds + status.remainingSeconds.toLong()) * 1000L
            totpPeriodSeconds = status.periodSeconds.toInt().coerceAtLeast(1)
            totpCodeView?.text = groupCode(status.code)
            startProgressAnimation(nowMs)
            true
        } catch (error: BridgeException.SessionLocked) {
            lockVault()
            false
        } catch (error: Throwable) {
            cancelProgressAnimation()
            totpCodeView?.text = ""
            totpProgress?.visibility = View.GONE
            totpRemainingView?.setText(R.string.msg_totp_failed)
            false
        }
    }

    /** Text only; changes once a second. The bar's own smooth position comes from [startProgressAnimation]. */
    private fun updateTotpCountdown(nowMs: Long) {
        val remaining = ((totpExpiresAtMs - nowMs + 999L) / 1000L).toInt().coerceIn(0, totpPeriodSeconds)
        totpRemainingView?.text = getString(R.string.totp_refresh_in, remaining)
    }

    /**
     * (Re)starts a linear animation of the progress bar from its exact current
     * wall-clock fraction down to empty, reaching zero exactly at
     * [totpExpiresAtMs]. Called only when a fetch establishes a fresh expiry
     * (entering the screen, resuming, or a period rollover) -- never once per
     * animation frame -- so at a period boundary the freshly-fetched, still
     * (almost) full remaining time naturally makes the bar restart at full.
     */
    private fun startProgressAnimation(nowMs: Long) {
        val progress = totpProgress ?: return
        cancelProgressAnimation()

        val remainingMs = (totpExpiresAtMs - nowMs).coerceAtLeast(0L)
        val periodMs = totpPeriodSeconds * 1000L
        val startValue = ((remainingMs.toDouble() / periodMs) * TOTP_PROGRESS_MAX)
            .toInt()
            .coerceIn(0, TOTP_PROGRESS_MAX)

        progress.visibility = View.VISIBLE
        progress.max = TOTP_PROGRESS_MAX
        progress.progress = startValue

        if (remainingMs <= 0L) return

        val animator = ValueAnimator.ofInt(startValue, 0)
        animator.duration = remainingMs
        animator.interpolator = LinearInterpolator()
        animator.addUpdateListener { progress.progress = it.animatedValue as Int }
        totpProgressAnimator = animator
        animator.start()
    }

    private fun cancelProgressAnimation() {
        totpProgressAnimator?.cancel()
        totpProgressAnimator = null
    }

    /** Stops the ticker and animation and clears the displayed code. Safe to call repeatedly. */
    private fun stopTotp() {
        totpTicker?.let { totpHandler.removeCallbacks(it) }
        totpTicker = null
        cancelProgressAnimation()
        totpCodeView?.text = ""
        totpExpiresAtMs = 0L
    }

    private fun copyTotp() {
        val entryId = detail?.id ?: return
        val current = session ?: return

        val code =
            try {
                current.totpStatus(entryId, System.currentTimeMillis() / 1000L).code
            } catch (error: BridgeException.SessionLocked) {
                lockVault()
                return
            } catch (error: Throwable) {
                toast(R.string.msg_totp_failed)
                return
            }

        // The raw code (no grouping space) goes through the same protected
        // clipboard as passwords; it is not kept after this call.
        clipboard.copy(getString(R.string.app_name), code, sensitive = true)
        confirmCopied()
    }

    private fun groupCode(code: String): String =
        if (code.length >= 6 && code.length % 2 == 0) {
            code.substring(0, code.length / 2) + " " + code.substring(code.length / 2)
        } else {
            code
        }

    /** Hides and clears any revealed password text and drops its UI state. */
    private fun clearRevealedPassword() {
        passwordValueView?.text = PASSWORD_MASK
        passwordToggleButton?.setText(R.string.show_password)
        passwordShown = false
    }

    private fun confirmCopied() {
        // Android 13+ shows its own clipboard confirmation.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) toast(R.string.copied)
    }

    private fun toast(messageRes: Int) {
        Toast.makeText(this, messageRes, Toast.LENGTH_SHORT).show()
    }

    // ---------------------------------------------------------------- helpers

    private fun queryDisplayName(uri: Uri): String? =
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (column >= 0 && cursor.moveToFirst()) cursor.getString(column) else null
            }
        } catch (error: Exception) {
            null
        }

    /** Best-effort overwrite of the typed characters; not a zeroization claim. */
    private fun wipe(field: EditText) {
        val editable = field.text ?: return
        val length = editable.length
        if (length > 0) editable.replace(0, length, " ".repeat(length))
        editable.clear()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun matchesCategory(entry: EntrySummary): Boolean =
        when (val filter = categoryFilter) {
            CategoryFilter.All -> true
            CategoryFilter.Uncategorized -> entry.categoryId == null
            is CategoryFilter.Category -> entry.categoryId == filter.id
        }

    private fun matchesQuery(entry: EntrySummary, query: String): Boolean =
        entry.title.contains(query, ignoreCase = true) ||
            entry.username.contains(query, ignoreCase = true) ||
            entry.url.contains(query, ignoreCase = true) ||
            entry.profileName.contains(query, ignoreCase = true)

    // ---------------------------------------------------------------- render

    private fun render() {
        stopTotp()
        content.removeAllViews()
        passwordField = null
        confirmPasswordField = null
        searchField = null
        rowsContainer = null
        countView = null
        passwordValueView = null
        passwordToggleButton = null
        passwordShown = false
        chipsContainer = null
        totpCodeView = null
        totpRemainingView = null
        totpProgress = null
        editTitleField = null
        editProfileField = null
        editUrlField = null
        editUsernameField = null
        editPasswordField = null
        editNotesField = null
        editTagsField = null
        editFavoriteCheckbox = null
        editCategorySpinner = null
        // The previous setup EditText (if any) is about to leave the window:
        // best-effort wipe before dropping the reference, like clearTotpSetupState.
        totpSetupField?.let { wipe(it) }
        totpSetupField = null

        when (screen) {
            Screen.NO_FILE -> renderNoFile()
            Screen.FILE_SELECTED -> renderFileSelected()
            Screen.UNLOCKING -> renderUnlocking()
            Screen.LIST -> renderList()
            Screen.DETAIL -> renderDetail()
            Screen.CREATE_PASSWORD -> renderCreatePassword()
            Screen.CREATE_IN_PROGRESS -> renderCreateInProgress()
            Screen.ENTRY_EDIT -> renderEntryEdit()
            Screen.CATEGORY_MANAGE -> renderCategoryManage()
            Screen.TOTP_SETUP -> renderTotpSetup()
            Screen.RECOVERY_NEEDED -> renderRecoveryNeeded()
        }
    }

    private fun renderNoFile() {
        addHeader()
        addStatus()
        addPrimaryButton(getString(R.string.choose_vault), topMargin = 24) { openPicker() }
        addSecondaryButton(getString(R.string.create_new_vault), topMargin = 10) { startCreateVault() }

        addSectionTitle(getString(R.string.recent_vaults))

        val items = recents.load()
        if (items.isEmpty()) {
            addBody(getString(R.string.recent_vaults_empty), color = R.color.lv_text_tertiary, topMargin = 4)
            return
        }

        for (vault in items) {
            val card = newCard(clickable = true)
            card.setOnClickListener { selectRecent(vault) }

            card.addView(newText(vault.name.ifEmpty { getString(R.string.default_vault_name) }, size = 16f, bold = true))

            val actions = LinearLayout(this)
            actions.orientation = LinearLayout.HORIZONTAL
            actions.gravity = Gravity.END
            if (vault.grant == VaultGrant.READ_ONLY) {
                actions.addView(
                    newTextButton(getString(R.string.enable_editing)) { requestWriteAccess(vault) },
                )
            }
            actions.addView(
                newTextButton(getString(R.string.remove_from_history)) { confirmForgetVault(vault) },
            )
            card.addView(actions, wrapParams(top = 8, gravity = Gravity.END))

            addToContent(card, topMargin = 8)
        }
    }

    private fun renderFileSelected() {
        addHeader()

        val card = newCard()
        card.addView(newText(getString(R.string.vault_label), size = 13f, color = R.color.lv_text_tertiary))
        card.addView(newText(vaultName, size = 17f, bold = true), matchParams(top = 2))
        addBackupWarningIfNeeded(vaultName)
        card.addView(
            newText(getString(R.string.master_password), size = 13f, color = R.color.lv_text_tertiary),
            matchParams(top = 16),
        )

        val field = newPasswordField()
        passwordField = field
        card.addView(field, matchParams(top = 6))
        addToContent(card, topMargin = 20)

        addStatus()
        addPrimaryButton(getString(R.string.unlock), topMargin = 16) { startUnlock() }
        addSecondaryButton(getString(R.string.choose_another_vault), topMargin = 10) { openPicker() }
        addSecondaryButton(getString(R.string.create_new_vault), topMargin = 10) { startCreateVault() }
    }

    private fun renderUnlocking() {
        addHeader()

        val card = newCard()
        card.gravity = Gravity.CENTER_HORIZONTAL
        card.addView(ProgressBar(this), wrapParams(top = 8, gravity = Gravity.CENTER_HORIZONTAL))
        card.addView(
            newText(getString(R.string.unlocking), size = 16f, bold = true),
            wrapParams(top = 12, gravity = Gravity.CENTER_HORIZONTAL),
        )
        addToContent(card, topMargin = 24)
    }

    /**
     * 1T-B5b-6 recovery fix: shown instead of the ordinary unlock flow when
     * [runUnlockPreOpenGate] reconciled an unresolved save marker to
     * UNKNOWN_NEEDS_RECOVERY -- the vault is never opened from here (no
     * session exists), only an explicit, user-confirmed restore of the
     * verified pre-write snapshot (see [showRecoveryRestoreConfirm]) or
     * choosing a different vault.
     */
    private fun renderRecoveryNeeded() {
        addHeader()

        val card = newCard()
        card.addView(newText(getString(R.string.vault_label), size = 13f, color = R.color.lv_text_tertiary))
        card.addView(newText(vaultName, size = 17f, bold = true), matchParams(top = 2))
        card.addView(
            newText(getString(R.string.forget_vault_unresolved_title), size = 15f, bold = true),
            matchParams(top = 16),
        )
        card.addView(
            newText(getString(R.string.msg_recovery_needed), size = 14f, color = R.color.lv_text_secondary),
            matchParams(top = 6),
        )
        addToContent(card, topMargin = 20)

        addStatus()

        if (restoring) {
            val progressCard = newCard()
            progressCard.gravity = Gravity.CENTER_HORIZONTAL
            progressCard.addView(ProgressBar(this), wrapParams(top = 8, gravity = Gravity.CENTER_HORIZONTAL))
            addToContent(progressCard, topMargin = 16)
        } else {
            addPrimaryButton(getString(R.string.restore_previous_version), topMargin = 16) { showRecoveryRestoreConfirm() }
            addSecondaryButton(getString(R.string.choose_another_vault), topMargin = 10) { openPicker() }
        }
    }

    private fun showRecoveryRestoreConfirm() {
        val uri = vaultUri ?: return

        AlertDialog.Builder(this)
            .setTitle(R.string.confirm_restore_title)
            .setMessage(R.string.confirm_restore_message)
            .setPositiveButton(R.string.restore_previous_version) { _, _ -> runRestore(uri) }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /**
     * Drives [RecoverySnapshotRestorer] off the main thread, exactly
     * mirroring [runUnlock]'s own generation-guard pattern so a stale
     * result from a screen the user already left cannot touch state it no
     * longer owns.
     */
    private fun runRestore(uri: Uri) {
        restoring = true
        render()

        val pin = recoveryUnresolvedSha256
        val generation = ++unlockGeneration
        Thread {
            val outcome = RecoverySnapshotRestorer(documentIo, recovery).restore(uri.toString(), pin)
            runOnUiThread { finishRestore(generation, outcome) }
        }.start()
    }

    private fun finishRestore(generation: Int, outcome: RestoreOutcome) {
        if (generation != unlockGeneration || screen != Screen.RECOVERY_NEEDED || isFinishing || isDestroyed) return
        restoring = false

        when (outcome) {
            is RestoreOutcome.Success -> {
                recoveryUnresolvedSha256 = null
                screen = Screen.FILE_SELECTED
                statusRes = R.string.msg_restore_succeeded
            }
            is RestoreOutcome.RestoredButMarkerClearFailed -> {
                recoveryUnresolvedSha256 = null
                screen = Screen.FILE_SELECTED
                // Non-success wording: the primary genuinely holds the
                // restored bytes, but the marker's durable clear could not
                // be confirmed -- a fresh unlock's own reconciliation
                // resolves it normally.
                statusRes = R.string.msg_restore_needs_retry
            }
            is RestoreOutcome.RecheckRequired -> {
                if (outcome.freshOutcome == ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY && outcome.freshPrimarySha256 != null) {
                    // Still unresolved -- stay blocked, re-pin, require a
                    // brand-new explicit confirmation before any future
                    // destructive write.
                    recoveryUnresolvedSha256 = outcome.freshPrimarySha256
                    screen = Screen.RECOVERY_NEEDED
                    statusRes = R.string.msg_restore_recheck
                } else {
                    // Resolved elsewhere, or genuinely undeterminable right
                    // now -- never claim success; a fresh unlock decides
                    // current truth.
                    recoveryUnresolvedSha256 = null
                    screen = Screen.FILE_SELECTED
                    statusRes = R.string.msg_vault_changed_externally
                }
            }
            RestoreOutcome.SnapshotMissing, RestoreOutcome.SnapshotInvalid, RestoreOutcome.ProviderNotWritable, RestoreOutcome.WriteFailed -> {
                // Retryable: stay on RECOVERY_NEEDED, pin left untouched so
                // a retry still compares against the original unresolved
                // state, not a silently-reset null.
                screen = Screen.RECOVERY_NEEDED
                statusRes = R.string.msg_restore_failed
            }
        }
        render()
    }

    private fun renderCreatePassword() {
        addHeader()

        val card = newCard()
        card.addView(newText(getString(R.string.vault_label), size = 13f, color = R.color.lv_text_tertiary))
        card.addView(newText(createDocumentName, size = 17f, bold = true), matchParams(top = 2))

        card.addView(
            newText(getString(R.string.master_password), size = 13f, color = R.color.lv_text_tertiary),
            matchParams(top = 16),
        )
        val field = newField()
        field.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        field.imeOptions = EditorInfo.IME_ACTION_NEXT or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        passwordField = field
        card.addView(field, matchParams(top = 6))

        card.addView(
            newText(getString(R.string.confirm_master_password), size = 13f, color = R.color.lv_text_tertiary),
            matchParams(top = 16),
        )
        val confirmField = newField()
        confirmField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        confirmField.imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        confirmField.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                submitCreatePassword()
                true
            } else {
                false
            }
        }
        confirmPasswordField = confirmField
        card.addView(confirmField, matchParams(top = 6))

        addToContent(card, topMargin = 20)

        addStatus()
        addPrimaryButton(getString(R.string.create_vault_action), topMargin = 16) { submitCreatePassword() }
        addSecondaryButton(getString(android.R.string.cancel), topMargin = 10) { cancelCreatePassword() }
    }

    private fun renderCreateInProgress() {
        addHeader()

        val card = newCard()
        card.gravity = Gravity.CENTER_HORIZONTAL
        card.addView(ProgressBar(this), wrapParams(top = 8, gravity = Gravity.CENTER_HORIZONTAL))
        card.addView(
            newText(getString(R.string.creating_vault), size = 16f, bold = true),
            wrapParams(top = 12, gravity = Gravity.CENTER_HORIZONTAL),
        )
        addToContent(card, topMargin = 24)
    }

    /**
     * Shared create/edit form (1T-B5b-4, accepted task section A). Populated
     * from, in priority order: an [editPendingSnapshot] left by a just-failed
     * save attempt (preserves what the user typed), then the already-fetched
     * [detail] for edit mode, then blank for create mode. No category
     * spinner yet -- [editCategoryId] is preserved silently; B5b-5 adds the
     * picker UI for it. No TOTP field (B5c).
     */
    private fun renderEntryEdit() {
        val isCreate = editEntryId == null
        val existing = if (isCreate) null else detail
        val snapshot = editPendingSnapshot
        editPendingSnapshot = null

        addToContent(
            newText(
                getString(if (isCreate) R.string.new_entry_title else R.string.edit_entry_title),
                size = 22f,
                bold = true,
            ),
            topMargin = 8,
        )

        val card = newCard()

        card.addView(newText(getString(R.string.field_title), size = 13f, color = R.color.lv_text_tertiary))
        val titleField = newField()
        titleField.setText(snapshot?.title ?: existing?.title ?: "")
        editTitleField = titleField
        card.addView(titleField, matchParams(top = 6))

        card.addView(newText(getString(R.string.profile), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val profileField = newField()
        profileField.setText(snapshot?.profileName ?: existing?.profileName ?: "")
        editProfileField = profileField
        card.addView(profileField, matchParams(top = 6))

        card.addView(newText(getString(R.string.website), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val urlField = newField()
        urlField.setText(snapshot?.url ?: existing?.url ?: "")
        editUrlField = urlField
        card.addView(urlField, matchParams(top = 6))

        card.addView(newText(getString(R.string.username), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val usernameField = newField()
        usernameField.setText(snapshot?.username ?: existing?.username ?: "")
        editUsernameField = usernameField
        card.addView(usernameField, matchParams(top = 6))

        card.addView(newText(getString(R.string.password), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val pwField = newField()
        pwField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        // Never sourced from [snapshot] (Blocker 3 -- EntryEditSnapshot never
        // carries a password): only the initial edit-mode fetch prefills
        // this field. After any failed save, submitEntryEdit has already
        // wiped it, so a retry always requires the password to be retyped.
        pwField.setText(editInitialPassword ?: "")
        editPasswordField = pwField
        card.addView(pwField, matchParams(top = 6))
        // Consumed into the visible field; never retained a second place
        // beyond it (accepted task section F).
        editInitialPassword = null

        card.addView(newText(getString(R.string.field_notes), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val notesField = newField()
        notesField.setSingleLine(false)
        notesField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        notesField.setMinLines(3)
        notesField.setText(snapshot?.notes ?: existing?.notes ?: "")
        editNotesField = notesField
        card.addView(notesField, matchParams(top = 6))

        card.addView(newText(getString(R.string.field_tags), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val tagsField = newField()
        tagsField.hint = getString(R.string.field_tags_hint)
        tagsField.setText(snapshot?.tags ?: existing?.tags?.joinToString(", ") ?: "")
        editTagsField = tagsField
        card.addView(tagsField, matchParams(top = 6))

        // 1T-B5b-5: category picker. [editCategoryId] is the persistent
        // source of truth -- set on startCreateEntry (null)/startEditEntry
        // (the entry's current category), updated live by the listener
        // below, and never reset by a failed save (see finishEntrySave's
        // failure branches, which only set editPendingSnapshot) -- so a
        // failed save keeps the user's selection without any dedicated
        // EntryEditSnapshot field for it.
        //
        // If editCategoryId names a category that is no longer in
        // [categories] (e.g. deleted concurrently by another client/
        // session), a transient UI-only "Current category unavailable" row
        // is prepended whose value is the missing id itself -- never a fake
        // id, and never null. That row, not "Uncategorized", is the initial
        // selection. This matters because Spinner can fire its selection
        // callback once during initial layout even without user action: with
        // this row selected, that callback can only rewrite editCategoryId
        // to the SAME missing id (a no-op), never silently to null. The
        // save-time membership guard in submitEntryEdit keeps blocking Save
        // for as long as this row (or the still-missing id) remains
        // selected; only an explicit user choice of "Uncategorized" or a
        // real category changes editCategoryId to a value that guard
        // accepts.
        card.addView(newText(getString(R.string.field_category), size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 16))
        val currentCategoryId = editCategoryId
        val categoryMissing = currentCategoryId != null && categories.none { it.id == currentCategoryId }

        val categoryOptions: List<Pair<String?, String>> =
            (if (categoryMissing) listOf(currentCategoryId to getString(R.string.category_unavailable)) else emptyList()) +
                listOf(null to getString(R.string.category_uncategorized)) +
                categories.map { it.id to it.name }

        val spinner = Spinner(this)
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, categoryOptions.map { it.second })
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinner.adapter = adapter
        val selectedIndex = categoryOptions.indexOfFirst { it.first == currentCategoryId }
        spinner.setSelection(if (selectedIndex >= 0) selectedIndex else 0)
        spinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                editCategoryId = categoryOptions.getOrNull(position)?.first
            }

            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
        editCategorySpinner = spinner
        card.addView(spinner, matchParams(top = 6))

        if (categoryMissing) {
            card.addView(
                newText(getString(R.string.msg_entry_category_missing), size = 12f, color = R.color.lv_error),
                matchParams(top = 4),
            )
        }

        val favoriteCheckbox = CheckBox(this)
        favoriteCheckbox.text = getString(R.string.field_favorite)
        favoriteCheckbox.isChecked = snapshot?.favorite ?: existing?.favorite ?: false
        editFavoriteCheckbox = favoriteCheckbox
        card.addView(favoriteCheckbox, matchParams(top = 16))

        addToContent(card, topMargin = 16)

        addStatus()
        addPrimaryButton(getString(R.string.save), topMargin = 16) { submitEntryEdit() }
        addSecondaryButton(getString(android.R.string.cancel), topMargin = 10) { cancelEntryEdit() }
    }

    /**
     * 1T-B5c-2. Dedicated setup/replace screen for an entry's 2FA key. Kept
     * off ENTRY_EDIT on purpose: the raw setup input is secret material and
     * must live only in this one EditText ([totpSetupField]) under the
     * render/onStop/lock/wipe lifecycle. The field is concealed by default,
     * excluded from autofill/suggestions/IME learning, and has NO IME action
     * -- submitting is only via the Save button. The accepted formats are
     * described to the user but never inspected here.
     */
    private fun renderTotpSetup() {
        val entryId = totpSetupEntryId
        val current = detail
        if (entryId == null || current == null || current.id != entryId) {
            clearTotpSetupState()
            screen = Screen.LIST
            renderList()
            return
        }

        val bar = LinearLayout(this)
        bar.orientation = LinearLayout.HORIZONTAL
        bar.gravity = Gravity.CENTER_VERTICAL
        bar.addView(newTextButton(getString(R.string.back)) { cancelTotpSetup() })
        addToContent(bar, topMargin = 0)

        addToContent(
            newText(
                getString(if (totpSetupReplacing) R.string.totp_replace_title else R.string.totp_setup_title),
                size = 22f,
                bold = true,
            ),
            topMargin = 12,
        )
        addToContent(newText(current.title, size = 14f, color = R.color.lv_text_secondary), topMargin = 2)

        val card = newCard()
        card.addView(newText(getString(R.string.totp_setup_help), size = 14f, color = R.color.lv_text_secondary))
        if (totpSetupReplacing) {
            card.addView(
                newText(getString(R.string.totp_replace_warning), size = 14f, color = R.color.lv_text_secondary),
                matchParams(top = 8),
            )
        }

        card.addView(
            newText(getString(R.string.totp_key_label), size = 13f, color = R.color.lv_text_tertiary),
            matchParams(top = 16),
        )
        val field = newField()
        field.hint = getString(R.string.totp_key_hint)
        field.inputType =
            InputType.TYPE_CLASS_TEXT or
            InputType.TYPE_TEXT_VARIATION_PASSWORD or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        field.imeOptions = EditorInfo.IME_ACTION_NONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        totpSetupField = field
        card.addView(field, matchParams(top = 6))

        val showKey = CheckBox(this)
        showKey.text = getString(R.string.totp_show_key)
        showKey.setOnCheckedChangeListener { _, checked ->
            val selection = field.selectionEnd
            field.inputType =
                if (checked) {
                    InputType.TYPE_CLASS_TEXT or
                        InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
                        InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                } else {
                    InputType.TYPE_CLASS_TEXT or
                        InputType.TYPE_TEXT_VARIATION_PASSWORD or
                        InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
                }
            if (selection >= 0) field.setSelection(selection.coerceAtMost(field.text.length))
        }
        card.addView(showKey, matchParams(top = 8))

        addToContent(card, topMargin = 16)

        addStatus()
        addPrimaryButton(getString(R.string.save), topMargin = 16) { submitTotpSetup() }
        addSecondaryButton(getString(android.R.string.cancel), topMargin = 10) { cancelTotpSetup() }
    }

    /**
     * 1T-B5b-5. Lists categories in stored order with per-category entry
     * counts (already carried by [CategorySummary], no new bridge read),
     * plus Rename/Delete per row and an Add-category action. No search
     * (accepted task section A). Stays on this screen after every normal
     * create/rename/delete success or failure -- only explicit Back leaves it.
     */
    private fun renderCategoryManage() {
        val bar = LinearLayout(this)
        bar.orientation = LinearLayout.HORIZONTAL
        bar.gravity = Gravity.CENTER_VERTICAL
        bar.addView(newTextButton(getString(R.string.back)) { closeCategoryManage() })
        addToContent(bar, topMargin = 0)

        addToContent(newText(getString(R.string.categories_title), size = 22f, bold = true), topMargin = 12)

        addStatus()

        addSecondaryButton(getString(R.string.add_category), topMargin = 16) { showAddCategoryDialog() }

        if (categories.isEmpty()) {
            addBody(getString(R.string.no_categories), color = R.color.lv_text_tertiary, topMargin = 16)
            return
        }

        for (category in categories) {
            val card = newCard()
            card.addView(newText(category.name, size = 16f, bold = true))
            card.addView(
                newText(
                    resources.getQuantityString(R.plurals.entries_count, category.entryCount.toInt(), category.entryCount.toInt()),
                    size = 13f,
                    color = R.color.lv_text_tertiary,
                ),
                matchParams(top = 2),
            )

            val actions = LinearLayout(this)
            actions.orientation = LinearLayout.HORIZONTAL
            actions.addView(newSecondaryButton(getString(R.string.rename), compact = true) { showRenameCategoryDialog(category) })
            actions.addView(
                newSecondaryButton(getString(R.string.delete), compact = true) { confirmDeleteCategory(category) },
                wrapParams(left = 8),
            )
            card.addView(actions, wrapParams(top = 12, gravity = Gravity.START))

            addToContent(card, topMargin = 8)
        }
    }

    private fun renderList() {
        // Stable heading + Lock on one row; the (possibly long) vault file name
        // sits below on its own single, end-ellipsized line so it can never
        // wrap awkwardly next to the button.
        val header = LinearLayout(this)
        header.orientation = LinearLayout.HORIZONTAL
        header.gravity = Gravity.CENTER_VERTICAL

        val title = newText(getString(R.string.app_name), size = 22f, bold = true)
        header.addView(title, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        header.addView(
            newSecondaryButton(getString(R.string.add_entry), compact = true) { startCreateEntry() },
            wrapParams(left = 8),
        )
        header.addView(
            newSecondaryButton(getString(R.string.lock), compact = true) { lockVault() },
            wrapParams(left = 8),
        )
        addToContent(header, topMargin = 4)

        val fileName = newText(vaultName, size = 14f, color = R.color.lv_text_secondary)
        fileName.setSingleLine()
        fileName.ellipsize = TextUtils.TruncateAt.END
        addToContent(fileName, topMargin = 2)
        addBackupWarningIfNeeded(vaultName)

        val search = newSearchField()
        searchField = search
        addToContent(search, topMargin = 16)

        val chipScroll = HorizontalScrollView(this)
        chipScroll.isHorizontalScrollBarEnabled = false
        val chipRow = LinearLayout(this)
        chipRow.orientation = LinearLayout.HORIZONTAL
        chipsContainer = chipRow
        chipScroll.addView(chipRow)
        addToContent(chipScroll, topMargin = 12)
        renderChips()

        addToContent(
            newTextButton(getString(R.string.manage_categories)) { startCategoryManage() },
            topMargin = 4,
        )

        val count = newText("", size = 13f, color = R.color.lv_text_tertiary)
        countView = count
        addToContent(count, topMargin = 12)

        val container = LinearLayout(this)
        container.orientation = LinearLayout.VERTICAL
        rowsContainer = container
        addToContent(container, topMargin = 4)

        renderRows()
    }

    private fun renderRows() {
        val container = rowsContainer ?: return
        container.removeAllViews()

        val query = searchQuery.trim()
        val visible = entries.filter { matchesCategory(it) && (query.isEmpty() || matchesQuery(it, query)) }

        countView?.text = resources.getQuantityString(R.plurals.entries_count, visible.size, visible.size)

        if (entries.isEmpty()) {
            container.addView(newText(getString(R.string.no_entries), color = R.color.lv_text_tertiary), matchParams(top = 12))
            return
        }
        if (visible.isEmpty()) {
            val emptyRes =
                if (query.isEmpty() && categoryFilter != CategoryFilter.All) {
                    R.string.category_empty
                } else {
                    R.string.no_search_results
                }
            container.addView(newText(getString(emptyRes), color = R.color.lv_text_tertiary), matchParams(top = 12))
            return
        }

        for (entry in visible) {
            container.addView(newEntryRow(entry), matchParams(top = 8))
        }
    }

    /** Category chips: All, each category in stored order, then Uncategorized (only if any exist). */
    private fun renderChips() {
        val row = chipsContainer ?: return
        row.removeAllViews()

        row.addView(
            newChip(getString(R.string.category_all), categoryFilter == CategoryFilter.All) {
                selectCategory(CategoryFilter.All)
            },
        )

        for (category in categories) {
            val selected = (categoryFilter as? CategoryFilter.Category)?.id == category.id
            row.addView(
                newChip(category.name, selected) { selectCategory(CategoryFilter.Category(category.id)) },
                wrapParams(left = 8),
            )
        }

        if (categories.isNotEmpty() && entries.any { it.categoryId == null }) {
            row.addView(
                newChip(getString(R.string.category_uncategorized), categoryFilter == CategoryFilter.Uncategorized) {
                    selectCategory(CategoryFilter.Uncategorized)
                },
                wrapParams(left = 8),
            )
        }
    }

    private fun selectCategory(filter: CategoryFilter) {
        categoryFilter = filter
        renderChips()
        renderRows()
    }

    private fun renderDetail() {
        val current = detail
        if (current == null) {
            screen = Screen.LIST
            renderList()
            return
        }

        val bar = LinearLayout(this)
        bar.orientation = LinearLayout.HORIZONTAL
        bar.gravity = Gravity.CENTER_VERTICAL
        bar.addView(newTextButton(getString(R.string.back)) { closeDetail() })
        bar.addView(View(this), LinearLayout.LayoutParams(0, 1, 1f))
        bar.addView(newSecondaryButton(getString(R.string.edit), compact = true) { startEditEntry() })
        bar.addView(
            newSecondaryButton(getString(R.string.delete), compact = true) { confirmDeleteEntry() },
            wrapParams(left = 8),
        )
        bar.addView(
            newSecondaryButton(getString(R.string.lock), compact = true) { lockVault() },
            wrapParams(left = 8),
        )
        addToContent(bar, topMargin = 0)

        addToContent(newText(current.title, size = 24f, bold = true), topMargin = 12)

        val info = newCard()
        var first = true
        if (current.profileName.isNotBlank()) {
            addField(info, getString(R.string.profile), current.profileName, first)
            first = false
        }
        if (current.url.isNotBlank()) {
            addField(info, getString(R.string.website), current.url, first)
            first = false
        }
        addField(info, getString(R.string.username), current.username.ifBlank { getString(R.string.not_set) }, first)
        if (current.username.isNotEmpty()) {
            info.addView(
                newSecondaryButton(getString(R.string.copy_username), compact = true) { copyUsername() },
                wrapParams(top = 12, gravity = Gravity.START),
            )
        }
        addToContent(info, topMargin = 16)

        val secret = newCard()
        secret.addView(newText(getString(R.string.password), size = 13f, color = R.color.lv_text_tertiary))

        val value = newText(PASSWORD_MASK, size = 18f)
        value.typeface = Typeface.MONOSPACE
        value.setTextIsSelectable(false)
        value.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        passwordValueView = value
        secret.addView(value, matchParams(top = 4))

        val buttons = LinearLayout(this)
        buttons.orientation = LinearLayout.HORIZONTAL
        val toggle = newSecondaryButton(getString(R.string.show_password), compact = true) { togglePassword() }
        passwordToggleButton = toggle
        buttons.addView(toggle)
        buttons.addView(
            newSecondaryButton(getString(R.string.copy_password), compact = true) { copyPassword() },
            wrapParams(left = 8),
        )
        secret.addView(buttons, matchParams(top = 12))
        addToContent(secret, topMargin = 12)

        if (current.totpEnabled) {
            val totp = newCard()
            totp.addView(newText(getString(R.string.totp_title), size = 13f, color = R.color.lv_text_tertiary))

            val code = newText("", size = 28f, bold = true)
            code.typeface = Typeface.MONOSPACE
            code.setTextIsSelectable(false)
            code.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            totpCodeView = code
            totp.addView(code, matchParams(top = 4))

            val progress = ProgressBar(this, null, android.R.attr.progressBarStyleHorizontal)
            progress.progressTintList = ColorStateList.valueOf(getColor(R.color.lv_primary))
            totpProgress = progress
            totp.addView(progress, matchParams(top = 8))

            val remaining = newText("", size = 13f, color = R.color.lv_text_secondary)
            totpRemainingView = remaining
            totp.addView(remaining, matchParams(top = 4))

            totp.addView(
                newSecondaryButton(getString(R.string.totp_copy), compact = true) { copyTotp() },
                wrapParams(top = 12, gravity = Gravity.START),
            )

            // 1T-B5c-2: the key itself is never shown; only replace/remove.
            val keyActions = LinearLayout(this)
            keyActions.orientation = LinearLayout.HORIZONTAL
            keyActions.addView(newSecondaryButton(getString(R.string.totp_replace), compact = true) { startTotpSetup() })
            keyActions.addView(
                newSecondaryButton(getString(R.string.totp_remove), compact = true) { confirmRemoveTotp() },
                wrapParams(left = 8),
            )
            totp.addView(keyActions, wrapParams(top = 8, gravity = Gravity.START))
            addToContent(totp, topMargin = 12)

            startTotp(current.id)
        } else {
            val totp = newCard()
            totp.addView(newText(getString(R.string.totp_section_title), size = 13f, color = R.color.lv_text_tertiary))
            totp.addView(
                newText(getString(R.string.totp_not_configured), size = 14f, color = R.color.lv_text_secondary),
                matchParams(top = 4),
            )
            totp.addView(
                newSecondaryButton(getString(R.string.totp_setup_action), compact = true) { startTotpSetup() },
                wrapParams(top = 12, gravity = Gravity.START),
            )
            addToContent(totp, topMargin = 12)
        }

        addToContent(
            newText(getString(R.string.clipboard_hint), size = 12f, color = R.color.lv_text_tertiary),
            topMargin = 12,
        )
    }

    private fun addField(card: LinearLayout, label: String, value: String, first: Boolean) {
        card.addView(newText(label, size = 13f, color = R.color.lv_text_tertiary), matchParams(top = if (first) 0 else 14))
        card.addView(newText(value, size = 16f), matchParams(top = 2))
    }

    // ---------------------------------------------------------------- view factories

    private fun newEntryRow(entry: EntrySummary): View {
        val row = newCard(clickable = true)
        row.setOnClickListener { openDetail(entry.id) }

        row.addView(newText(entry.title, size = 16f, bold = true))

        if (entry.username.isNotBlank()) {
            row.addView(newText(entry.username, size = 14f, color = R.color.lv_text_secondary), matchParams(top = 2))
        }

        val site = listOf(entry.url, entry.profileName).filter { it.isNotBlank() }.joinToString(" · ")
        if (site.isNotEmpty()) {
            row.addView(newText(site, size = 13f, color = R.color.lv_text_tertiary), matchParams(top = 2))
        }

        return row
    }

    private fun newChip(label: String, selected: Boolean, onClick: () -> Unit): TextView {
        val chip = TextView(this)
        chip.text = label
        chip.textSize = 14f
        chip.gravity = Gravity.CENTER
        chip.setSingleLine()
        chip.ellipsize = TextUtils.TruncateAt.END
        chip.maxWidth = dp(220)
        chip.minHeight = dp(40)
        chip.setPadding(dp(16), dp(8), dp(16), dp(8))
        chip.isClickable = true
        chip.isSelected = selected
        chip.background = getDrawable(if (selected) R.drawable.bg_chip_selected else R.drawable.bg_chip)
        chip.setTextColor(getColor(if (selected) R.color.lv_on_primary else R.color.lv_text))
        if (selected) chip.setTypeface(chip.typeface, Typeface.BOLD)
        chip.setOnClickListener { onClick() }
        return chip
    }

    private fun newCard(clickable: Boolean = false): LinearLayout {
        val card = LinearLayout(this)
        card.orientation = LinearLayout.VERTICAL
        card.setPadding(dp(16), dp(14), dp(16), dp(14))
        card.background = getDrawable(if (clickable) R.drawable.bg_row else R.drawable.bg_card)
        card.isClickable = clickable
        return card
    }

    private fun newText(
        text: String,
        size: Float = 16f,
        bold: Boolean = false,
        color: Int = R.color.lv_text,
    ): TextView {
        val view = TextView(this)
        view.text = text
        view.textSize = size
        view.setTextColor(getColor(color))
        if (bold) view.setTypeface(view.typeface, Typeface.BOLD)
        return view
    }

    private fun newPrimaryButton(label: String, onClick: () -> Unit): Button {
        val button = newButton(label, R.drawable.bg_button_primary, R.color.lv_on_primary)
        button.setOnClickListener { onClick() }
        return button
    }

    private fun newSecondaryButton(label: String, compact: Boolean = false, onClick: () -> Unit): Button {
        val button = newButton(label, R.drawable.bg_button_secondary, R.color.lv_primary)
        if (compact) {
            button.minHeight = dp(40)
            button.minimumHeight = dp(40)
            button.setPadding(dp(14), 0, dp(14), 0)
        }
        button.setOnClickListener { onClick() }
        return button
    }

    private fun newTextButton(label: String, onClick: () -> Unit): Button {
        val button = newButton(label, R.drawable.bg_button_text, R.color.lv_primary)
        button.minHeight = dp(40)
        button.minimumHeight = dp(40)
        button.minWidth = 0
        button.minimumWidth = 0
        button.setPadding(dp(10), 0, dp(10), 0)
        button.setOnClickListener { onClick() }
        return button
    }

    private fun newButton(label: String, backgroundRes: Int, textColorRes: Int): Button {
        val button = Button(this)
        button.text = label
        button.isAllCaps = false
        button.textSize = 15f
        button.setTextColor(getColor(textColorRes))
        button.background = getDrawable(backgroundRes)
        button.stateListAnimator = null
        button.minHeight = dp(48)
        button.minimumHeight = dp(48)
        return button
    }

    private fun newPasswordField(): EditText {
        val field = newField()
        field.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        field.imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        field.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                startUnlock()
                true
            } else {
                false
            }
        }
        return field
    }

    private fun newSearchField(): EditText {
        val field = newField()
        field.hint = getString(R.string.search_hint)
        field.contentDescription = getString(R.string.search)
        field.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        field.imeOptions = EditorInfo.IME_ACTION_SEARCH or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        field.setText(searchQuery)
        field.setSelection(field.text.length)
        field.addTextChangedListener(
            object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}

                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}

                override fun afterTextChanged(s: Editable?) {
                    searchQuery = s?.toString() ?: ""
                    renderRows()
                }
            },
        )
        return field
    }

    private fun newField(): EditText {
        val field = EditText(this)
        field.setSingleLine()
        field.textSize = 16f
        field.setTextColor(getColor(R.color.lv_text))
        field.setHintTextColor(getColor(R.color.lv_text_tertiary))
        field.background = getDrawable(R.drawable.bg_field)
        field.setPadding(dp(14), dp(12), dp(14), dp(12))
        field.isSaveEnabled = false
        field.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        return field
    }

    // ---------------------------------------------------------------- layout helpers

    private fun addHeader() {
        addToContent(newText(getString(R.string.app_name), size = 30f, bold = true), topMargin = 8)
        addToContent(newText(getString(R.string.tagline), size = 14f, color = R.color.lv_text_secondary), topMargin = 2)
    }

    private fun addSectionTitle(text: String) {
        addToContent(newText(text, size = 14f, bold = true, color = R.color.lv_text_secondary), topMargin = 32)
    }

    private fun addBody(text: String, color: Int = R.color.lv_text, topMargin: Int = 0) {
        addToContent(newText(text, color = color), topMargin = topMargin)
    }

    private fun addStatus() {
        if (statusRes == 0) return

        val message = newText(getString(statusRes), size = 14f, color = R.color.lv_error)
        message.setPadding(dp(14), dp(12), dp(14), dp(12))
        message.background = getDrawable(R.drawable.bg_error)
        addToContent(message, topMargin = 16)
    }

    /**
     * 1T-B5a: warns before opening or saving to a document whose name
     * matches the automatic rolling backup convention (`<name>.backup`) --
     * the exact naming that caused the real, documented QA confusion
     * between a vault's primary and backup files (accepted review, Revision
     * 3, section 7).
     */
    private fun addBackupWarningIfNeeded(name: String, topMargin: Int = 10) {
        if (!isLikelyBackupFilename(name)) return

        val message = newText(getString(R.string.backup_file_warning), size = 13f, color = R.color.lv_error)
        message.setPadding(dp(14), dp(10), dp(14), dp(10))
        message.background = getDrawable(R.drawable.bg_error)
        addToContent(message, topMargin = topMargin)
    }

    private fun addPrimaryButton(label: String, topMargin: Int, onClick: () -> Unit) {
        addToContent(newPrimaryButton(label, onClick), topMargin = topMargin)
    }

    private fun addSecondaryButton(label: String, topMargin: Int, onClick: () -> Unit) {
        addToContent(newSecondaryButton(label, onClick = onClick), topMargin = topMargin)
    }

    private fun addToContent(view: View, topMargin: Int) {
        content.addView(view, matchParams(top = topMargin))
    }

    private fun matchParams(top: Int = 0): LinearLayout.LayoutParams {
        val params =
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
        params.topMargin = dp(top)
        return params
    }

    private fun wrapParams(top: Int = 0, left: Int = 0, gravity: Int = Gravity.NO_GRAVITY): LinearLayout.LayoutParams {
        val params =
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
        params.topMargin = dp(top)
        params.leftMargin = dp(left)
        params.gravity = gravity
        return params
    }
}
