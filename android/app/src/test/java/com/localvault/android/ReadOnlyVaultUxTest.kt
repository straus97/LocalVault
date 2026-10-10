package com.localvault.android

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.BridgeException

/**
 * Pins the pure seams behind the read-only vault UX, the failed-delete
 * feedback and the SAF grant-hint / "Enable editing" document checks. The
 * hints are UX metadata only; none of these helpers is an authorization
 * source (VaultSaveCoordinator re-checks on every save).
 */
class ReadOnlyVaultUxTest {

    // ---- read-only state (fail closed)

    @Test
    fun vault_is_writable_only_when_both_the_grant_and_the_provider_allow_it() {
        assertFalse(isVaultReadOnly(hasPersistedWriteGrant = true, providerSupportsWrite = true))
        assertTrue(isVaultReadOnly(hasPersistedWriteGrant = true, providerSupportsWrite = false))
        assertTrue(isVaultReadOnly(hasPersistedWriteGrant = false, providerSupportsWrite = true))
        assertTrue(isVaultReadOnly(hasPersistedWriteGrant = false, providerSupportsWrite = false))
    }

    // ---- recovery guidance resources (EN/RU)

    private fun resource(dir: String): String {
        val candidates = listOf("src/main/res/$dir/strings.xml", "android/app/src/main/res/$dir/strings.xml")
        val file = candidates.map(::File).firstOrNull { it.isFile }
            ?: error("strings.xml for $dir not found from ${File(".").absolutePath}")
        return file.readText(Charsets.UTF_8)
    }

    private fun keys(xml: String): Set<String> =
        Regex("""<(?:string|plurals)\s+name="([^"]+)"""").findAll(xml).map { it.groupValues[1] }.toSet()

    private fun value(xml: String, key: String): String =
        Regex("""<string\s+name="$key">(.*?)</string>""", RegexOption.DOT_MATCHES_ALL)
            .find(xml)?.groupValues?.get(1) ?: error("missing string $key")

    @Test
    fun english_and_russian_string_keys_stay_synchronized() {
        assertEquals(keys(resource("values")), keys(resource("values-ru")))
    }

    @Test
    fun read_only_guidance_names_the_real_enable_editing_action_in_both_languages() {
        for (dir in listOf("values", "values-ru")) {
            val xml = resource(dir)
            val label = value(xml, "enable_editing")
            // The message tells the user which button to press on the start
            // screen, so its wording must match that button's label.
            assertTrue("$dir read-only message must name \"$label\"", value(xml, "msg_write_access_unavailable").contains(label))
        }
    }

    @Test
    fun new_feedback_strings_exist_in_both_languages() {
        for (dir in listOf("values", "values-ru")) {
            val xml = resource(dir)
            for (key in listOf("msg_enable_editing_wrong_document", "msg_enable_editing_request_lost", "msg_write_not_supported", "msg_write_access_not_granted")) {
                assertTrue("$dir/$key", value(xml, key).isNotBlank())
            }
        }
    }

    // ---- failed delete feedback

    @Test
    fun every_failed_delete_outcome_yields_a_visible_notice() {
        assertEquals(
            EntryDeleteNotice.WRITE_ACCESS_UNAVAILABLE,
            entryDeleteFailureNotice(SaveOutcome.ProviderNotWritable),
        )
        val generic =
            listOf(
                SaveOutcome.RecoverySnapshotFailed,
                SaveOutcome.WriteFailed,
                SaveOutcome.ValidationFailed(BridgeException.EntryNotFound()),
                SaveOutcome.UnexpectedError(java.io.IOException()),
            )
        for (outcome in generic) {
            assertEquals("$outcome", EntryDeleteNotice.ACTION_FAILED, entryDeleteFailureNotice(outcome))
        }
    }

    @Test
    fun success_and_changed_externally_produce_no_failure_notice() {
        // Success has its own "deleted" toast; ChangedExternally locks with
        // its own message. Neither may also show a failure notice.
        assertEquals(EntryDeleteNotice.NONE, entryDeleteFailureNotice(SaveOutcome.Success))
        assertEquals(EntryDeleteNotice.NONE, entryDeleteFailureNotice(SaveOutcome.ChangedExternally))
    }

    // ---- grant hint consistency

    @Test
    fun reopening_a_vault_with_a_valid_persisted_write_grant_keeps_read_write() {
        assertEquals(VaultGrant.READ_WRITE, reopenGrantHint(hasPersistedWriteGrant = true))
    }

    @Test
    fun reopening_a_vault_without_a_write_grant_is_read_only() {
        assertEquals(VaultGrant.READ_ONLY, reopenGrantHint(hasPersistedWriteGrant = false))
    }

    @Test
    fun provider_not_writable_downgrades_the_hint_only_for_the_live_coordinator() {
        assertTrue(shouldDowngradeGrantHint(SaveOutcome.ProviderNotWritable, coordinatorLive = true))
        // A stale result from a replaced/locked coordinator must not change
        // metadata for whatever vault is active now.
        assertFalse(shouldDowngradeGrantHint(SaveOutcome.ProviderNotWritable, coordinatorLive = false))
    }

    @Test
    fun other_outcomes_never_downgrade_the_hint() {
        val others =
            listOf(
                SaveOutcome.Success,
                SaveOutcome.ChangedExternally,
                SaveOutcome.RecoverySnapshotFailed,
                SaveOutcome.WriteFailed,
                SaveOutcome.ValidationFailed(BridgeException.EntryNotFound()),
                SaveOutcome.UnexpectedError(java.io.IOException()),
            )
        for (outcome in others) {
            assertFalse("$outcome", shouldDowngradeGrantHint(outcome, coordinatorLive = true))
        }
    }

    @Test
    fun hint_is_derived_from_live_availability() {
        assertEquals(VaultGrant.READ_WRITE, grantHintFor(true))
        assertEquals(VaultGrant.READ_ONLY, grantHintFor(false))
    }

    // ---- Enable editing: grant outcome

    @Test
    fun enable_editing_succeeds_only_with_confirmed_grants_and_provider_support() {
        assertEquals(EnableEditingOutcome.ENABLED, enableEditingOutcome(VaultGrant.READ_WRITE, providerSupportsWrite = true))
    }

    @Test
    fun enable_editing_with_an_insufficient_grant_is_not_granted_regardless_of_provider() {
        assertEquals(EnableEditingOutcome.NOT_GRANTED, enableEditingOutcome(VaultGrant.READ_ONLY, providerSupportsWrite = true))
        assertEquals(EnableEditingOutcome.NOT_GRANTED, enableEditingOutcome(VaultGrant.READ_ONLY, providerSupportsWrite = false))
    }

    @Test
    fun enable_editing_with_grants_but_no_provider_write_support_stays_read_only() {
        assertEquals(
            EnableEditingOutcome.PROVIDER_NOT_WRITABLE,
            enableEditingOutcome(VaultGrant.READ_WRITE, providerSupportsWrite = false),
        )
    }

    // ---- Enable editing: same-document check

    private val documentA = "content://com.android.providers.downloads.documents/document/msf%3A42"
    private val sameFileOtherProvider = "content://com.android.externalstorage.documents/document/primary%3ADownload%2Fvault.lvault"

    @Test
    fun the_same_document_uri_is_accepted() {
        assertTrue(isRequestedDocument(documentA, documentA))
    }

    @Test
    fun a_different_uri_is_rejected_even_if_it_may_name_the_same_physical_file() {
        // Two URIs are never guessed to be the same file.
        assertFalse(isRequestedDocument(documentA, sameFileOtherProvider))
        assertFalse(isRequestedDocument(documentA, "$documentA-other"))
    }

    // ---- pending target surviving Activity recreation

    @Test
    fun pending_target_survives_a_save_and_restore_and_still_matches_the_same_document() {
        val before = PendingEnableEditingTarget()
        before.begin(documentA)

        // Activity destroyed: only the snapshot string crosses into the new instance.
        val after = PendingEnableEditingTarget()
        after.restore(before.snapshot())

        assertEquals(EnableEditingTargetCheck.MATCH, checkEnableEditingTarget(after.consume(), documentA))
    }

    @Test
    fun restored_target_still_rejects_a_different_document() {
        val after = PendingEnableEditingTarget()
        after.restore(documentA)

        assertEquals(EnableEditingTargetCheck.MISMATCH, checkEnableEditingTarget(after.consume(), sameFileOtherProvider))
    }

    @Test
    fun target_is_consumed_exactly_once_so_cancellation_and_later_results_cannot_reuse_it() {
        val pending = PendingEnableEditingTarget()
        pending.begin(documentA)

        assertEquals(documentA, pending.consume())
        assertEquals(null, pending.consume())
        assertEquals(null, pending.snapshot())
    }

    @Test
    fun nothing_is_saved_when_no_request_is_pending() {
        // A fresh or already-handled Activity writes nothing into saved state.
        assertEquals(null, PendingEnableEditingTarget().snapshot())
    }

    @Test
    fun a_genuinely_missing_target_is_reported_as_lost_not_as_a_wrong_document() {
        assertEquals(EnableEditingTargetCheck.LOST, checkEnableEditingTarget(null, documentA))
        // Restoring "nothing" (no saved state) is the lost case too.
        val fresh = PendingEnableEditingTarget().also { it.restore(null) }
        assertEquals(EnableEditingTargetCheck.LOST, checkEnableEditingTarget(fresh.consume(), documentA))
    }

    @Test
    fun a_new_request_replaces_any_older_pending_one() {
        val pending = PendingEnableEditingTarget()
        pending.begin(sameFileOtherProvider)
        pending.begin(documentA)

        assertEquals(documentA, pending.consume())
    }

    @Test
    fun an_unverifiable_request_is_rejected() {
        // e.g. the target was lost across process death while the picker was open.
        assertFalse(isRequestedDocument(null, documentA))
        assertFalse(isRequestedDocument(documentA, null))
        assertFalse(isRequestedDocument(null, null))
    }
}
