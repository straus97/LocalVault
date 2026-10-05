package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.BridgeException

/**
 * Pins the pure B5c-2 decision seams `finishTotpMutation` relies on: the
 * stale-completion redraw policy and the SaveOutcome -> action mapping.
 */
class TotpMutationUiTest {

    // ---- stale-completion redraw policy

    @Test
    fun matching_detail_is_redrawn() {
        assertTrue(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.DETAIL, "e1", "e1"))
    }

    @Test
    fun different_detail_entry_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.DETAIL, "e2", "e1"))
    }

    @Test
    fun detail_with_no_current_entry_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.DETAIL, null, "e1"))
    }

    @Test
    fun every_other_screen_is_not_redrawn_even_with_matching_entry_id() {
        for (screen in TotpRedrawScreen.values()) {
            if (screen == TotpRedrawScreen.DETAIL) continue
            assertFalse("$screen", shouldRedrawAfterStaleTotpMutation(screen, "e1", "e1"))
        }
    }

    @Test
    fun list_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.LIST, null, "e1"))
    }

    @Test
    fun entry_edit_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.ENTRY_EDIT, "e1", "e1"))
    }

    @Test
    fun totp_setup_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.TOTP_SETUP, "e1", "e1"))
    }

    @Test
    fun category_manage_is_not_redrawn() {
        assertFalse(shouldRedrawAfterStaleTotpMutation(TotpRedrawScreen.CATEGORY_MANAGE, null, "e1"))
    }

    // ---- outcome mapping

    @Test
    fun success_maps_to_success_for_both_kinds() {
        assertEquals(TotpOutcomeAction.SUCCESS, totpOutcomeAction(TotpMutationKind.SET, SaveOutcome.Success))
        assertEquals(TotpOutcomeAction.SUCCESS, totpOutcomeAction(TotpMutationKind.REMOVE, SaveOutcome.Success))
    }

    @Test
    fun invalid_totp_configuration_on_set_is_invalid_key() {
        val outcome = SaveOutcome.ValidationFailed(BridgeException.InvalidTotpConfiguration())
        assertEquals(TotpOutcomeAction.SHOW_INVALID_KEY, totpOutcomeAction(TotpMutationKind.SET, outcome))
    }

    @Test
    fun invalid_totp_configuration_on_remove_is_generic() {
        val outcome = SaveOutcome.ValidationFailed(BridgeException.InvalidTotpConfiguration())
        assertEquals(TotpOutcomeAction.SHOW_GENERIC_FAILURE, totpOutcomeAction(TotpMutationKind.REMOVE, outcome))
    }

    @Test
    fun pending_unsaved_changes_is_generic_not_invalid_key() {
        val outcome = SaveOutcome.ValidationFailed(BridgeException.PendingUnsavedChanges())
        assertEquals(TotpOutcomeAction.SHOW_GENERIC_FAILURE, totpOutcomeAction(TotpMutationKind.SET, outcome))
        assertEquals(TotpOutcomeAction.SHOW_GENERIC_FAILURE, totpOutcomeAction(TotpMutationKind.REMOVE, outcome))
    }

    @Test
    fun totp_not_configured_on_remove_is_generic() {
        val outcome = SaveOutcome.ValidationFailed(BridgeException.TotpNotConfigured())
        assertEquals(TotpOutcomeAction.SHOW_GENERIC_FAILURE, totpOutcomeAction(TotpMutationKind.REMOVE, outcome))
    }

    @Test
    fun session_locked_validation_failure_locks() {
        val outcome = SaveOutcome.ValidationFailed(BridgeException.SessionLocked())
        assertEquals(TotpOutcomeAction.LOCK_SESSION_LOCKED, totpOutcomeAction(TotpMutationKind.SET, outcome))
        assertEquals(TotpOutcomeAction.LOCK_SESSION_LOCKED, totpOutcomeAction(TotpMutationKind.REMOVE, outcome))
    }

    @Test
    fun provider_not_writable_maps_to_write_access_unavailable() {
        assertEquals(
            TotpOutcomeAction.SHOW_WRITE_ACCESS_UNAVAILABLE,
            totpOutcomeAction(TotpMutationKind.SET, SaveOutcome.ProviderNotWritable),
        )
        assertEquals(
            TotpOutcomeAction.SHOW_WRITE_ACCESS_UNAVAILABLE,
            totpOutcomeAction(TotpMutationKind.REMOVE, SaveOutcome.ProviderNotWritable),
        )
    }

    @Test
    fun changed_externally_maps_to_external_change_lock() {
        assertEquals(
            TotpOutcomeAction.LOCK_CHANGED_EXTERNALLY,
            totpOutcomeAction(TotpMutationKind.SET, SaveOutcome.ChangedExternally),
        )
        assertEquals(
            TotpOutcomeAction.LOCK_CHANGED_EXTERNALLY,
            totpOutcomeAction(TotpMutationKind.REMOVE, SaveOutcome.ChangedExternally),
        )
    }

    @Test
    fun other_failures_are_generic() {
        val others =
            listOf(
                SaveOutcome.RecoverySnapshotFailed,
                SaveOutcome.WriteFailed,
                SaveOutcome.UnexpectedError(RuntimeException()),
            )
        for (outcome in others) {
            assertEquals(TotpOutcomeAction.SHOW_GENERIC_FAILURE, totpOutcomeAction(TotpMutationKind.SET, outcome))
            assertEquals(TotpOutcomeAction.SHOW_GENERIC_FAILURE, totpOutcomeAction(TotpMutationKind.REMOVE, outcome))
        }
    }
}
