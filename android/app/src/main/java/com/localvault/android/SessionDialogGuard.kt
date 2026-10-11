package com.localvault.android

/**
 * Ownership + staleness guard for application-owned dialogs that display
 * decrypted vault metadata (entry/category names) or whose positive action
 * mutates the open vault session.
 *
 * Pure Kotlin (no Android types) so the lifecycle rules are unit-testable on
 * the plain JVM; the Activity supplies a `dismiss` lambda per dialog.
 *
 * Model: every dialog is opened under a [Ticket] captured from the current
 * epoch. [invalidateAndDismissAll] (called from lock and destroy, and when a
 * session is replaced) bumps the epoch and dismisses every tracked dialog.
 * Any click callback wrapped in [runIfCurrent] is then inert for tickets from
 * an earlier epoch, even if the platform delivers it late or the dialog could
 * not be dismissed. Dismissing a dialog never invokes its button listeners,
 * so dismissal itself cannot run a positive action.
 *
 * Main-thread only, like the Activity that owns it. Holds no vault data.
 */
internal class SessionDialogGuard {
    class Ticket internal constructor(internal val epoch: Long)

    /** Opaque handle returned by [attach]; pass it to [detach] when the dialog goes away. */
    class Attachment internal constructor(internal val epoch: Long, internal val dismiss: () -> Unit)

    private var epoch = 0L
    private val tracked = ArrayList<Attachment>()

    /** Number of dialogs currently tracked as open. */
    val openCount: Int get() = tracked.size

    /** Captures the current epoch; call before building the dialog. */
    fun begin(): Ticket = Ticket(epoch)

    fun isCurrent(ticket: Ticket): Boolean = ticket.epoch == epoch

    /**
     * Starts tracking a dialog about to be shown. Returns null (caller must
     * not show it) if [ticket] is already stale.
     */
    fun attach(ticket: Ticket, dismiss: () -> Unit): Attachment? {
        if (!isCurrent(ticket)) return null
        val attachment = Attachment(ticket.epoch, dismiss)
        tracked.add(attachment)
        return attachment
    }

    /** Stops tracking (the dialog was dismissed). Safe to call repeatedly or after invalidation. */
    fun detach(attachment: Attachment) {
        tracked.remove(attachment)
    }

    /** Runs [action] only if [ticket] is still current; returns whether it ran. */
    fun runIfCurrent(ticket: Ticket, action: () -> Unit): Boolean {
        if (!isCurrent(ticket)) return false
        action()
        return true
    }

    /**
     * Invalidates every outstanding ticket and dismisses every tracked dialog.
     * Dismiss failures (e.g. window already gone) are swallowed; the epoch bump
     * alone already neutralises the callbacks.
     */
    fun invalidateAndDismissAll() {
        epoch++
        val snapshot = ArrayList(tracked)
        tracked.clear()
        for (attachment in snapshot) {
            try {
                attachment.dismiss()
            } catch (ignored: Exception) {
            }
        }
    }
}
