package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `SaveReconciler`'s own integration tests (driving `reconcile()` from an
 * independent primary read) were removed when it was superseded by
 * [runUnlockPreOpenGate] -- see [UnlockPreOpenGateTest] for the equivalent
 * (and now single-read) coverage. `reconcile()` itself is unchanged and
 * still used internally by that gate, so its pure-decision tests remain
 * here.
 */
class SaveReconciliationTest {

    private val vaultUri = "content://provider/document/vault"

    private val savedContent = "saved-primary-content".toByteArray()
    private val baselineContent = "pre-write-baseline-content".toByteArray()

    private val marker = RecoveryMarker(
        vaultUri = vaultUri,
        baselineSha256 = Sha256.hex(baselineContent),
        expectedNewSha256 = Sha256.hex(savedContent),
        timestampMs = 1_000L,
    )

    @Test
    fun current_hash_matching_expected_new_means_saved() {
        assertEquals(ReconciliationOutcome.SAVED, reconcile(marker, marker.expectedNewSha256))
    }

    @Test
    fun current_hash_matching_baseline_means_not_saved() {
        assertEquals(ReconciliationOutcome.NOT_SAVED, reconcile(marker, marker.baselineSha256))
    }

    @Test
    fun current_hash_matching_neither_needs_recovery() {
        assertEquals(ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY, reconcile(marker, "some-other-hash"))
    }
}
