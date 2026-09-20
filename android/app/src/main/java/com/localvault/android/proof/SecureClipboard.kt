package com.localvault.android.proof

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import java.util.UUID

/**
 * Best-effort, ownership-verified clipboard cleanup for LocalVault copies.
 *
 * What is done:
 *  - The value is placed on the system clipboard. Password copies are marked
 *    sensitive with [ClipDescription.EXTRA_IS_SENSITIVE] (Android 13+ hides the
 *    content in its clipboard preview; older APIs ignore it).
 *  - Each copy is tagged with a fresh random, NON-SECRET ownership token in the
 *    clip description extras (verified to round-trip on API 36). The copied
 *    value is never retained for comparison; only the token and its expiry are
 *    remembered (in memory, and mirrored to a private preference so a restarted
 *    process can still finish the job).
 *  - The LocalVault lifetime is [CLEAR_DELAY_MS] (30 s), tracked with the
 *    monotonic clock in-process.
 *
 * The Android constraint that shapes everything below: from Android 10, an app
 * that is not the focused app (or the IME) cannot read the clipboard. Reads
 * then come back empty (`primaryClipDescription == null`,
 * `hasPrimaryClip() == false`), which is indistinguishable from an empty
 * clipboard. So, when the timer fires while LocalVault is in the background,
 * "I cannot see the clip" must NOT be treated as "it is not mine". Instead:
 *  - expired + readable + token matches  -> clear it;
 *  - readable + token differs / absent   -> someone else's content: forget our
 *    ownership and leave the clipboard untouched;
 *  - unreadable while not focused        -> do nothing and keep only the
 *    non-secret pending-expiry metadata; retry when the app regains focus
 *    ([setAppFocused] / [cleanupExpiredOwnedClipIfPossible]).
 *
 * What is NOT guaranteed:
 *  - There is no promise that the value is physically deleted 30 seconds after
 *    the user leaves the app. If Android denies access, deletion waits until
 *    LocalVault is focused again (or never, if the user never returns).
 *  - Windows' clipboard sequence-number guarantee has no Android equivalent;
 *    other readers (the keyboard, clipboard history features) may keep copies.
 *  - Android's own clipboard auto-clear/sensitive handling is complementary
 *    platform behaviour that LocalVault does not control.
 *  - No foreground service, alarm or background job is used for this.
 *
 * Locking the vault deliberately does not touch the clipboard (normal flow is
 * copy -> switch app -> paste). Nothing here logs the copied value.
 */
class SecureClipboard private constructor(context: Context) {

    private val appContext = context.applicationContext
    private val clipboard = appContext.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    private val prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val handler = Handler(Looper.getMainLooper())

    // Non-secret pending-cleanup state: which clip is ours, and when it expires.
    private var token: String? = null
    private var expiresAtElapsed = 0L

    private var appFocused = false
    private var pendingTimer: Runnable? = null

    init {
        // Recover pending state after a process restart (still non-secret).
        val savedToken = prefs.getString(KEY_TOKEN, null)
        if (savedToken != null) {
            val remainingWall = prefs.getLong(KEY_EXPIRES_WALL, 0L) - System.currentTimeMillis()
            // Never wait longer than the intended lifetime, even if the wall
            // clock was moved backwards meanwhile.
            val remaining = remainingWall.coerceAtMost(CLEAR_DELAY_MS)
            token = savedToken
            expiresAtElapsed = SystemClock.elapsedRealtime() + remaining
        }
    }

    /** Copies [value]; [sensitive] marks it for Android's sensitive-content handling. */
    fun copy(label: String, value: String, sensitive: Boolean) {
        cancelTimer()

        val newToken = UUID.randomUUID().toString()

        val clip = ClipData.newPlainText(label, value)
        val extras = PersistableBundle()
        extras.putString(OWNER_KEY, newToken)
        if (sensitive) extras.putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
        clip.description.extras = extras

        clipboard.setPrimaryClip(clip)

        // A newer LocalVault copy replaces ownership of any older one.
        token = newToken
        expiresAtElapsed = SystemClock.elapsedRealtime() + CLEAR_DELAY_MS
        prefs.edit()
            .putString(KEY_TOKEN, newToken)
            .putLong(KEY_EXPIRES_WALL, System.currentTimeMillis() + CLEAR_DELAY_MS)
            .apply()

        scheduleTimer(CLEAR_DELAY_MS)
    }

    /** Records whether the app currently has window focus (clipboard read access). */
    fun setAppFocused(focused: Boolean) {
        appFocused = focused
        if (focused) cleanupExpiredOwnedClipIfPossible()
    }

    /**
     * Catch-up / retry entry point (call when the app returns to the
     * foreground). Does nothing when no LocalVault clip is pending, clears an
     * expired clip only when its ownership token still matches, and never
     * touches other clipboard content.
     */
    fun cleanupExpiredOwnedClipIfPossible() {
        val owned = token ?: return

        val remaining = expiresAtElapsed - SystemClock.elapsedRealtime()
        if (remaining > 0) {
            // Not expired yet (e.g. the app came back early): make sure a timer
            // exists for the rest of the lifetime.
            scheduleTimer(remaining)
            return
        }

        val description =
            try {
                clipboard.primaryClipDescription
            } catch (ignored: Throwable) {
                null
            }

        if (description == null) {
            val provablyEmpty =
                appFocused &&
                    try {
                        !clipboard.hasPrimaryClip()
                    } catch (ignored: Throwable) {
                        false
                    }

            // Focused and empty: nothing left to clear. Otherwise access is
            // (probably) denied: keep the pending metadata and retry later.
            if (provablyEmpty) forget()
            return
        }

        val currentOwner =
            try {
                description.extras?.getString(OWNER_KEY)
            } catch (ignored: Throwable) {
                null
            }

        if (currentOwner == owned) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    clipboard.clearPrimaryClip()
                } else {
                    clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                }
                forget()
            } catch (ignored: Throwable) {
                // Could not clear; keep the pending state and try again later.
            }
        } else {
            // Readable but not ours (or its metadata is gone): never erase it.
            forget()
        }
    }

    private fun forget() {
        cancelTimer()
        token = null
        expiresAtElapsed = 0L
        prefs.edit().remove(KEY_TOKEN).remove(KEY_EXPIRES_WALL).apply()
    }

    private fun scheduleTimer(delayMs: Long) {
        cancelTimer()

        val timer = Runnable {
            pendingTimer = null
            cleanupExpiredOwnedClipIfPossible()
        }
        pendingTimer = timer
        handler.postDelayed(timer, delayMs)
    }

    private fun cancelTimer() {
        pendingTimer?.let { handler.removeCallbacks(it) }
        pendingTimer = null
    }

    companion object {
        private const val CLEAR_DELAY_MS = 30_000L
        private const val OWNER_KEY = "com.localvault.android.clip_owner"

        private const val PREFS_NAME = "clipboard_ownership"
        private const val KEY_TOKEN = "token"
        private const val KEY_EXPIRES_WALL = "expires_wall_ms"

        @Volatile
        private var instance: SecureClipboard? = null

        /** One process-wide instance, so there is exactly one pending timer. */
        fun get(context: Context): SecureClipboard =
            instance
                ?: synchronized(this) {
                    instance ?: SecureClipboard(context).also { instance = it }
                }
    }
}
