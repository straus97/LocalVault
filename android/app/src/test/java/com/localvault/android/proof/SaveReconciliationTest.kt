package com.localvault.android.proof

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.IOException

class SaveReconciliationTest {

    private val vaultUri = "content://provider/document/vault"

    // Real SHA-256 values of real content -- reconcile() itself is a pure
    // string comparison, but SaveReconciler drives it from
    // Sha256.hex(io.readAll(...)), so the integration tests below need
    // marker hashes that genuinely correspond to bytes the fake IO returns.
    private val savedContent = "saved-primary-content".toByteArray()
    private val baselineContent = "pre-write-baseline-content".toByteArray()
    private val unrelatedContent = "neither-baseline-nor-expected-content".toByteArray()

    private val marker = RecoveryMarker(
        vaultUri = vaultUri,
        baselineSha256 = Sha256.hex(baselineContent),
        expectedNewSha256 = Sha256.hex(savedContent),
        timestampMs = 1_000L,
    )

    // -- the pure decision function --------------------------------------

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

    // -- SaveReconciler ------------------------------------------------

    private fun storeWithMarker(): FakeRecoverySnapshotStore {
        val recovery = FakeRecoverySnapshotStore()
        recovery.writeAndVerify(vaultUri, ByteArray(0), marker.baselineSha256, marker.expectedNewSha256, 1L)
        return recovery
    }

    @Test
    fun no_marker_means_nothing_to_reconcile() {
        val outcome = SaveReconciler(FakeSafDocumentIo(), FakeRecoverySnapshotStore()).reconcileOnUnlock(vaultUri)

        assertNull(outcome)
    }

    @Test
    fun primary_matching_expected_new_content_is_reported_saved_and_clears_the_marker() {
        val recovery = storeWithMarker()
        val io = FakeSafDocumentIo(mapOf(vaultUri to savedContent))

        val outcome = SaveReconciler(io, recovery).reconcileOnUnlock(vaultUri)

        assertEquals(ReconciliationOutcome.SAVED, outcome)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun primary_matching_baseline_content_is_reported_not_saved_and_clears_the_marker() {
        val recovery = storeWithMarker()
        val io = FakeSafDocumentIo(mapOf(vaultUri to baselineContent))

        val outcome = SaveReconciler(io, recovery).reconcileOnUnlock(vaultUri)

        assertEquals(ReconciliationOutcome.NOT_SAVED, outcome)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun primary_matching_neither_content_needs_recovery_and_keeps_the_marker() {
        val recovery = storeWithMarker()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))

        val outcome = SaveReconciler(io, recovery).reconcileOnUnlock(vaultUri)

        assertEquals(ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY, outcome)
        assertEquals(marker.baselineSha256, recovery.readMarker(vaultUri)?.baselineSha256)
    }

    @Test
    fun a_read_failure_needs_recovery_and_keeps_the_marker() {
        val recovery = storeWithMarker()
        val io = FakeSafDocumentIo()
        io.readException = IOException("provider unavailable")

        val outcome = SaveReconciler(io, recovery).reconcileOnUnlock(vaultUri)

        assertEquals(ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY, outcome)
        assertEquals(marker.baselineSha256, recovery.readMarker(vaultUri)?.baselineSha256)
    }
}
