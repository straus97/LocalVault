package com.localvault.android.proof

import android.app.Activity
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
import android.widget.Button
import android.widget.EditText
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import java.io.IOException
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.CategorySummary
import uniffi.localvault_android_bridge.EntryDetails
import uniffi.localvault_android_bridge.EntrySummary
import uniffi.localvault_android_bridge.VaultSession
import uniffi.localvault_android_bridge.openVault

/**
 * LocalVault Android read-only client (1T-B3): pick or re-open a recent vault,
 * unlock it through localvault-core (via the Rust bridge, off the main thread),
 * search the entry list, open an entry, show/copy its credentials, and lock.
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
 *    from the list, and on explicit Lock.
 *  - Only non-secret metadata (document Uri + display name) is persisted, for
 *    the recent-vault list, with a persistable READ-only Uri grant.
 *  - This slice is read-only: the vault file is never written.
 */
class MainActivity : Activity() {

    private enum class Screen { NO_FILE, FILE_SELECTED, UNLOCKING, LIST, DETAIL }

    private class VaultReadException : Exception()

    /** Transient UI filter; "uncategorized" is a real state of the model (no category id). */
    private sealed class CategoryFilter {
        object All : CategoryFilter()

        object Uncategorized : CategoryFilter()

        class Category(val id: String) : CategoryFilter()
    }

    private companion object {
        const val REQUEST_PICK_VAULT = 1

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

    private var screen = Screen.NO_FILE
    private var vaultUri: Uri? = null
    private var vaultName: String = ""
    private var statusRes: Int = 0

    private var session: VaultSession? = null
    private var entries: List<EntrySummary> = emptyList()
    private var categories: List<CategorySummary> = emptyList()
    private var categoryFilter: CategoryFilter = CategoryFilter.All
    private var searchQuery: String = ""
    private var listScrollY: Int = 0
    private var detail: EntryDetails? = null

    // Views that hold user-entered or revealed text; nulled on every render.
    private var passwordField: EditText? = null
    private var searchField: EditText? = null
    private var rowsContainer: LinearLayout? = null
    private var countView: TextView? = null
    private var passwordValueView: TextView? = null
    private var passwordToggleButton: Button? = null
    private var passwordShown = false
    private var chipsContainer: LinearLayout? = null

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

    // Bumped on every lock/stop/destroy so a late background result for an
    // abandoned unlock is discarded (and its session closed) instead of shown.
    private var unlockGeneration = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Screenshots and recents thumbnails are blocked in every build except
        // a debuggable one (so development screenshots stay possible). This is
        // derived from the app's real debuggable state, not a hard-coded flag.
        val debuggable = (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }

        recents = RecentVaultStore(this)
        clipboard = SecureClipboard.get(this)

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

        if (screen == Screen.LIST || screen == Screen.DETAIL || screen == Screen.UNLOCKING) {
            lockVault()
        } else {
            passwordField?.let { wipe(it) }
        }
    }

    override fun onDestroy() {
        stopTotp()
        unlockGeneration++
        val current = session
        session = null
        entries = emptyList()
        categories = emptyList()
        detail = null
        closeQuietly(current)

        super.onDestroy()
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

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

    // ---------------------------------------------------------------- back

    private fun handleBack() {
        when (screen) {
            Screen.DETAIL -> closeDetail()
            Screen.LIST, Screen.UNLOCKING -> lockVault()
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

    private fun rememberVault(vault: RecentVault) {
        for (evicted in recents.promote(vault)) releaseGrant(evicted.uri)
    }

    private fun forgetVault(uri: Uri) {
        recents.remove(uri)
        releaseGrant(uri)
    }

    private fun releaseGrant(uri: Uri) {
        try {
            contentResolver.releasePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } catch (ignored: Exception) {
        }
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

    /** Runs on a dedicated background thread: file read + Argon2id + list. */
    private fun runUnlock(uri: Uri, password: String, generation: Int) {
        var opened: VaultSession? = null
        var rows: List<EntrySummary> = emptyList()
        var cats: List<CategorySummary> = emptyList()
        var messageRes = 0
        var unreadable = false

        try {
            val envelopeBytes = readVaultBytes(uri)
            opened = openVault(envelopeBytes, password)
            rows = opened.listEntries()
            cats = opened.listCategories()
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
        runOnUiThread { finishUnlock(generation, uri, result, rows, cats, messageRes, unreadable) }
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
        rows: List<EntrySummary>,
        cats: List<CategorySummary>,
        messageRes: Int,
        unreadable: Boolean,
    ) {
        if (generation != unlockGeneration || screen != Screen.UNLOCKING || isFinishing || isDestroyed) {
            closeQuietly(opened)
            return
        }

        if (opened != null) {
            session = opened
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

    private fun lockVault() {
        unlockGeneration++

        val current = session
        session = null
        entries = emptyList()
        categories = emptyList()
        categoryFilter = CategoryFilter.All
        detail = null
        searchQuery = ""
        listScrollY = 0
        clearRevealedPassword()
        closeQuietly(current)

        statusRes = 0
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

        when (screen) {
            Screen.NO_FILE -> renderNoFile()
            Screen.FILE_SELECTED -> renderFileSelected()
            Screen.UNLOCKING -> renderUnlocking()
            Screen.LIST -> renderList()
            Screen.DETAIL -> renderDetail()
        }
    }

    private fun renderNoFile() {
        addHeader()
        addStatus()
        addPrimaryButton(getString(R.string.choose_vault), topMargin = 24) { openPicker() }

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
            card.addView(
                newTextButton(getString(R.string.remove_from_history)) {
                    forgetVault(vault.uri)
                    statusRes = 0
                    render()
                },
                wrapParams(top = 8, gravity = Gravity.END),
            )

            addToContent(card, topMargin = 8)
        }
    }

    private fun renderFileSelected() {
        addHeader()

        val card = newCard()
        card.addView(newText(getString(R.string.vault_label), size = 13f, color = R.color.lv_text_tertiary))
        card.addView(newText(vaultName, size = 17f, bold = true), matchParams(top = 2))
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

    private fun renderList() {
        // Stable heading + Lock on one row; the (possibly long) vault file name
        // sits below on its own single, end-ellipsized line so it can never
        // wrap awkwardly next to the button.
        val header = LinearLayout(this)
        header.orientation = LinearLayout.HORIZONTAL
        header.gravity = Gravity.CENTER_VERTICAL

        val title = newText(getString(R.string.app_name), size = 22f, bold = true)
        header.addView(title, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        header.addView(newSecondaryButton(getString(R.string.lock), compact = true) { lockVault() })
        addToContent(header, topMargin = 4)

        val fileName = newText(vaultName, size = 14f, color = R.color.lv_text_secondary)
        fileName.setSingleLine()
        fileName.ellipsize = TextUtils.TruncateAt.END
        addToContent(fileName, topMargin = 2)

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
        bar.addView(newSecondaryButton(getString(R.string.lock), compact = true) { lockVault() })
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
            addToContent(totp, topMargin = 12)

            startTotp(current.id)
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
