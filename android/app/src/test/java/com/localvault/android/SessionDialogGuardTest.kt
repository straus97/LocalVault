package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the lifecycle rules MainActivity relies on for dialogs that show
 * decrypted vault metadata or act on the open session. The Activity wiring
 * itself (AlertDialog, onStop) cannot run on the plain JVM; see
 * [MainActivityDialogWiringTest] for the static checks on that wiring.
 */
class SessionDialogGuardTest {

    /** Stand-in for an AlertDialog: dismiss() never fires button callbacks, like the real one. */
    private class FakeDialog {
        var dismissed = 0
        var positiveRan = 0
    }

    private fun show(guard: SessionDialogGuard, dialog: FakeDialog): Pair<SessionDialogGuard.Ticket, SessionDialogGuard.Attachment> {
        val ticket = guard.begin()
        val attachment = guard.attach(ticket) { dialog.dismissed++ }
        assertNotNull(attachment)
        return ticket to attachment!!
    }

    @Test
    fun lock_dismisses_every_open_dialog() {
        val guard = SessionDialogGuard()
        val a = FakeDialog()
        val b = FakeDialog()
        show(guard, a)
        show(guard, b)
        assertEquals(2, guard.openCount)

        guard.invalidateAndDismissAll()

        assertEquals(1, a.dismissed)
        assertEquals(1, b.dismissed)
        assertEquals(0, guard.openCount)
    }

    @Test
    fun dismissal_does_not_execute_positive_callbacks() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        val (ticket, _) = show(guard, dialog)
        // A positive action is only ever reached through runIfCurrent.
        guard.invalidateAndDismissAll()

        assertEquals(0, dialog.positiveRan)
        assertEquals(1, dialog.dismissed)
        assertFalse(guard.isCurrent(ticket))
    }

    @Test
    fun stale_positive_callback_is_inert_after_lock() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        val (ticket, _) = show(guard, dialog)

        guard.invalidateAndDismissAll()

        val ran = guard.runIfCurrent(ticket) { dialog.positiveRan++ }
        assertFalse(ran)
        assertEquals(0, dialog.positiveRan)
    }

    @Test
    fun stale_callback_stays_inert_after_a_new_session_starts_and_unlocks() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        val (oldTicket, _) = show(guard, dialog)

        guard.invalidateAndDismissAll() // lock
        val newTicket = guard.begin() // re-unlocked session opens its own dialog
        assertTrue(guard.isCurrent(newTicket))

        assertFalse(guard.runIfCurrent(oldTicket) { dialog.positiveRan++ })
        assertEquals(0, dialog.positiveRan)
        assertTrue(guard.runIfCurrent(newTicket) { dialog.positiveRan++ })
        assertEquals(1, dialog.positiveRan)
    }

    @Test
    fun normal_confirmation_runs_when_unlocked() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        val (ticket, attachment) = show(guard, dialog)

        // Real flow: the click listener runs first, then the dialog dismisses itself.
        assertTrue(guard.runIfCurrent(ticket) { dialog.positiveRan++ })
        guard.detach(attachment)

        assertEquals(1, dialog.positiveRan)
        assertEquals(0, guard.openCount)
        assertEquals(0, dialog.dismissed)
        assertTrue(guard.isCurrent(ticket))
    }

    @Test
    fun cancel_path_detaches_without_invalidating() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        val (ticket, attachment) = show(guard, dialog)

        guard.detach(attachment)

        assertTrue(guard.isCurrent(ticket))
        assertEquals(0, guard.openCount)
    }

    @Test
    fun dialog_dismissed_by_user_is_not_dismissed_again_on_lock() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        val (_, attachment) = show(guard, dialog)

        guard.detach(attachment) // user cancelled
        guard.invalidateAndDismissAll()

        assertEquals(0, dialog.dismissed)
    }

    @Test
    fun attach_with_stale_ticket_refuses_and_tracks_nothing() {
        val guard = SessionDialogGuard()
        val ticket = guard.begin()
        guard.invalidateAndDismissAll()

        assertNull(guard.attach(ticket) { })
        assertEquals(0, guard.openCount)
    }

    @Test
    fun dismiss_failure_does_not_stop_other_dialogs_or_invalidation() {
        val guard = SessionDialogGuard()
        val good = FakeDialog()
        val badTicket = guard.begin()
        guard.attach(badTicket) { throw IllegalStateException("window gone") }
        val (goodTicket, _) = show(guard, good)

        guard.invalidateAndDismissAll()

        assertEquals(1, good.dismissed)
        assertFalse(guard.isCurrent(badTicket))
        assertFalse(guard.isCurrent(goodTicket))
        assertEquals(0, guard.openCount)
    }

    @Test
    fun dismiss_that_detaches_during_iteration_is_safe() {
        val guard = SessionDialogGuard()
        val holder = arrayOfNulls<SessionDialogGuard.Attachment>(1)
        val ticket = guard.begin()
        // Mirrors AlertDialog.dismiss() synchronously firing the OnDismissListener -> detach().
        holder[0] = guard.attach(ticket) { holder[0]?.let { guard.detach(it) } }

        guard.invalidateAndDismissAll()

        assertEquals(0, guard.openCount)
    }

    @Test
    fun repeated_invalidation_is_idempotent() {
        val guard = SessionDialogGuard()
        val dialog = FakeDialog()
        show(guard, dialog)

        guard.invalidateAndDismissAll()
        guard.invalidateAndDismissAll()

        assertEquals(1, dialog.dismissed)
    }
}
