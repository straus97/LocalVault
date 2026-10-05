package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.BridgeException

/**
 * Pins the pure decision seams `finishEntrySave`, `finishEntryDelete` and
 * `finishCategoryMutation` rely on (B5 correctness follow-up, Issue 1): when a
 * stale entry mutation must still refresh the session-derived cache, which
 * screens it may redraw, and which coordinator may lock the session after
 * `ChangedExternally`. Activity wiring itself is reviewed directly.
 */
class EntryMutationStaleCompletionTest {

    // ---- A. stale redraw policy

    @Test
    fun list_is_redrawn() {
        assertTrue(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.LIST, null, "e1"))
    }

    @Test
    fun list_is_redrawn_for_create() {
        assertTrue(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.LIST, null, null))
    }

    @Test
    fun category_manage_is_redrawn() {
        assertTrue(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.CATEGORY_MANAGE, null, "e1"))
    }

    @Test
    fun detail_of_same_mutated_entry_is_redrawn() {
        assertTrue(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.DETAIL, "e1", "e1"))
    }

    @Test
    fun detail_of_different_entry_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.DETAIL, "e2", "e1"))
    }

    @Test
    fun detail_with_no_current_entry_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.DETAIL, null, "e1"))
    }

    @Test
    fun detail_is_not_redrawn_for_create_with_no_known_entry_id() {
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.DETAIL, "e1", null))
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.DETAIL, null, null))
    }

    @Test
    fun entry_edit_is_never_redrawn() {
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.ENTRY_EDIT, "e1", "e1"))
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.ENTRY_EDIT, null, null))
    }

    @Test
    fun totp_setup_is_never_redrawn() {
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.TOTP_SETUP, "e1", "e1"))
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.TOTP_SETUP, null, null))
    }

    @Test
    fun other_screens_are_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.OTHER, "e1", "e1"))
        assertFalse(shouldRedrawAfterStaleEntryMutation(TotpRedrawScreen.OTHER, null, null))
    }

    @Test
    fun only_list_category_manage_and_matching_detail_ever_redraw() {
        for (screen in TotpRedrawScreen.values()) {
            val expected =
                screen == TotpRedrawScreen.LIST ||
                    screen == TotpRedrawScreen.CATEGORY_MANAGE ||
                    screen == TotpRedrawScreen.DETAIL
            assertEquals("$screen", expected, shouldRedrawAfterStaleEntryMutation(screen, "e1", "e1"))
        }
    }

    // ---- B. cache refresh policy

    private val failureOutcomes: List<SaveOutcome> =
        listOf(
            SaveOutcome.ProviderNotWritable,
            SaveOutcome.ValidationFailed(BridgeException.SessionLocked()),
            SaveOutcome.RecoverySnapshotFailed,
            SaveOutcome.WriteFailed,
            SaveOutcome.UnexpectedError(RuntimeException("boom")),
            SaveOutcome.ChangedExternally,
        )

    @Test
    fun success_with_live_coordinator_refreshes_cache() {
        assertTrue(entryMutationRefreshesCache(SaveOutcome.Success, coordinatorLive = true))
    }

    @Test
    fun success_with_replaced_coordinator_does_not_refresh_cache() {
        assertFalse(entryMutationRefreshesCache(SaveOutcome.Success, coordinatorLive = false))
    }

    @Test
    fun no_failure_outcome_refreshes_cache() {
        for (outcome in failureOutcomes) {
            assertFalse("$outcome live", entryMutationRefreshesCache(outcome, coordinatorLive = true))
            assertFalse("$outcome replaced", entryMutationRefreshesCache(outcome, coordinatorLive = false))
        }
    }

    // ---- C. ChangedExternally ownership policy
    //
    // UI generation is deliberately not a parameter: a Back/navigation makes
    // it stale while the live session is still owned, and the lock must
    // still happen.

    @Test
    fun alive_activity_with_live_coordinator_locks() {
        assertTrue(changedExternallyLocksSession(activityAlive = true, coordinatorLive = true))
    }

    @Test
    fun alive_activity_with_replaced_coordinator_does_not_lock() {
        assertFalse(changedExternallyLocksSession(activityAlive = true, coordinatorLive = false))
    }

    @Test
    fun dead_activity_with_live_coordinator_does_not_lock() {
        assertFalse(changedExternallyLocksSession(activityAlive = false, coordinatorLive = true))
    }

    @Test
    fun dead_activity_with_replaced_coordinator_does_not_lock() {
        assertFalse(changedExternallyLocksSession(activityAlive = false, coordinatorLive = false))
    }
}
