package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Static checks on how MainActivity wires [SessionDialogGuard]. These read
 * the source text: AlertDialog/Activity lifecycle cannot run on the plain
 * JVM (no Robolectric/instrumentation by design), so this guards against
 * accidental regressions of the wiring, not against runtime behavior. The
 * runtime lifecycle must be confirmed on a device.
 */
class MainActivityDialogWiringTest {

    private val source: String by lazy {
        File("src/main/java/com/localvault/android/MainActivity.kt").readText()
    }

    private fun body(signature: String, endMarker: String): String {
        val start = source.indexOf(signature)
        assertTrue("missing $signature", start >= 0)
        val end = source.indexOf(endMarker, start)
        assertTrue("missing end marker after $signature", end > start)
        return source.substring(start, end)
    }

    @Test
    fun lock_destroy_and_session_replacement_invalidate_dialogs() {
        assertTrue(body("private fun lockVault(", "private fun closeQuietly").contains("dialogGuard.invalidateAndDismissAll()"))
        assertTrue(body("override fun onDestroy()", "override fun onActivityResult").contains("dialogGuard.invalidateAndDismissAll()"))
        // Both places that install a new session.
        assertEquals(2, Regex("""dialogGuard\.invalidateAndDismissAll\(\)\s*(?:closeQuietly\(session\)\s*)?session = (?:outcome\.session|opened)""")
            .findAll(source).count())
    }

    @Test
    fun on_stop_still_locks_immediately() {
        val onStop = body("override fun onStop()", "override fun onDestroy()")
        assertTrue(onStop.contains("Screen.LIST, Screen.DETAIL, Screen.UNLOCKING, Screen.CATEGORY_MANAGE, Screen.RECOVERY_NEEDED -> lockVault()"))
        assertEquals(3, Regex("""lockVault\(\)""").findAll(onStop).count())
    }

    @Test
    fun session_bound_dialogs_are_guarded_and_tracked() {
        val guardedFunctions =
            listOf(
                "private fun confirmDeleteEntry()",
                "private fun showAddCategoryDialog()",
                "private fun showRenameCategoryDialog(",
                "private fun confirmDeleteCategory(",
                "private fun confirmRemoveTotp()",
                "private fun showRecoveryRestoreConfirm()",
            )
        for (signature in guardedFunctions) {
            val text = body(signature, "\n    }\n")
            assertTrue("$signature begins a ticket", text.contains("dialogGuard.begin()"))
            assertTrue("$signature guards the positive action", text.contains("guardedClick(ticket)"))
            assertTrue("$signature shows via the guard", text.contains("showGuardedDialog(ticket, dialog)"))
            assertFalse("$signature must not show directly", text.contains(".show()"))
            assertFalse("$signature must not use a raw positive lambda", Regex("""setPositiveButton\(\s*[\w.]+\s*\)\s*\{""").containsMatchIn(text))
        }
    }

    @Test
    fun only_the_metadata_free_forget_dialog_remains_untracked() {
        val chunks = source.split("AlertDialog.Builder(this)").drop(1)
        assertEquals(7, chunks.size)
        for (chunk in chunks) {
            val untracked = !chunk.substringBefore("\n    }\n").contains(".create()")
            if (untracked) assertTrue(chunk.contains("forget_vault_unresolved_title"))
        }
    }

    @Test
    fun dismissal_happens_via_tracked_dismiss_not_button_callbacks() {
        val helper = body("private fun showGuardedDialog(", "\n    }\n")
        assertTrue(helper.contains("dialog.dismiss()"))
        assertTrue(helper.contains("setOnDismissListener { dialogGuard.detach(attachment) }"))
    }
}
