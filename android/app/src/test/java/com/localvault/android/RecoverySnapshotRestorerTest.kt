package com.localvault.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class RecoverySnapshotRestorerTest {

    private val vaultUri = "content://provider/document/vault"

    private val baselineContent = "pre-write-baseline-content".toByteArray()
    private val expectedNewContent = "expected-new-content".toByteArray()
    private val unrelatedContent = "neither-baseline-nor-expected-content".toByteArray()

    private val marker = RecoveryMarker(
        vaultUri = vaultUri,
        baselineSha256 = Sha256.hex(baselineContent),
        expectedNewSha256 = Sha256.hex(expectedNewContent),
        timestampMs = 1_000L,
    )

    /** A store with a marker and a snapshot whose bytes genuinely match
     * `marker.baselineSha256` -- the only combination a real [RecoverySnapshotStore]
     * can ever durably produce via `writeAndVerify`. */
    private fun storeWithValidSnapshot(): FakeRecoverySnapshotStore {
        val recovery = FakeRecoverySnapshotStore()
        recovery.writeAndVerify(vaultUri, baselineContent, marker.baselineSha256, marker.expectedNewSha256, 1L)
        return recovery
    }

    @Test
    fun verified_restore_writes_the_snapshot_and_clears_the_marker() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.Success, outcome)
        assertEquals(1, io.writes.size)
        assertArrayEquals(baselineContent, io.contentOf(vaultUri))
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun no_marker_requires_recheck_and_performs_no_write() {
        val recovery = FakeRecoverySnapshotStore()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, Sha256.hex(unrelatedContent))

        assertEquals(RestoreOutcome.RecheckRequired(null, null), outcome)
        assertEquals(0, io.writes.size)
    }

    // Snapshot absence/unreadability is covered by snapshot_read_failure_performs_no_write
    // below (readSnapshotBytes throwing is the general case; a real
    // RecoverySnapshotStore's writeAndVerify contract guarantees a marker
    // is never durably recorded without a corresponding snapshot, so a
    // marker-with-literally-no-snapshot-bytes state cannot otherwise arise).
    // Snapshot bytes genuinely matching marker.baselineSha256 (the integrity
    // check this test file's other tests all rely on) is exercised by
    // verified_restore_writes_the_snapshot_and_clears_the_marker above,
    // since storeWithValidSnapshot() only ever produces such a pair.

    @Test
    fun snapshot_not_matching_the_marker_baseline_is_rejected_without_writing() {
        val recovery = FakeRecoverySnapshotStore()
        // Write a marker/snapshot pair directly where the snapshot bytes do
        // NOT correspond to marker.baselineSha256 -- simulates a private
        // snapshot that has become damaged/truncated since it was created.
        recovery.writeAndVerify(vaultUri, expectedNewContent, marker.baselineSha256, marker.expectedNewSha256, 1L)
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.SnapshotInvalid, outcome)
        assertEquals(0, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertArrayEquals(expectedNewContent, recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun not_writable_performs_no_write_and_leaves_marker_and_snapshot() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeSupported = false
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.ProviderNotWritable, outcome)
        assertEquals(0, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun write_grant_check_throwing_is_treated_as_not_writable() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeGrantException = SecurityException("persisted grant lookup failed")
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.ProviderNotWritable, outcome)
        assertEquals(0, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun supports_write_check_throwing_is_treated_as_not_writable() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeSupportedException = IOException("provider query failed")
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.ProviderNotWritable, outcome)
        assertEquals(0, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun write_throwing_leaves_marker_and_snapshot_untouched() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeException = IOException("provider rejected wt")
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.WriteFailed, outcome)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun readback_mismatch_leaves_marker_and_snapshot_untouched_and_never_clears() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeTransform = { "corrupted-on-the-way-back".toByteArray() }
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.WriteFailed, outcome)
        assertEquals(1, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun stale_primary_resolved_elsewhere_clears_marker_and_performs_no_write() {
        val recovery = storeWithValidSnapshot()
        // Current primary now matches the marker's expected-new hash --
        // something else already completed/resolved this save.
        val io = FakeSafDocumentIo(mapOf(vaultUri to expectedNewContent))
        val stalePin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, stalePin)

        assertEquals(RestoreOutcome.RecheckRequired(ReconciliationOutcome.SAVED, Sha256.hex(expectedNewContent)), outcome)
        assertEquals(0, io.writes.size)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun stale_primary_still_unknown_leaves_marker_and_snapshot_and_performs_no_write() {
        val recovery = storeWithValidSnapshot()
        val differentUnknownContent = "yet-another-unrelated-content".toByteArray()
        val io = FakeSafDocumentIo(mapOf(vaultUri to differentUnknownContent))
        val stalePin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, stalePin)

        assertEquals(
            RestoreOutcome.RecheckRequired(ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY, Sha256.hex(differentUnknownContent)),
            outcome,
        )
        assertEquals(0, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun null_pin_never_authorizes_a_write_even_when_still_unresolved() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, null)

        assertEquals(RestoreOutcome.RecheckRequired(ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY, Sha256.hex(unrelatedContent)), outcome)
        assertEquals(0, io.writes.size)
        assertNotNull(recovery.readMarker(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun preserved_pin_across_a_retryable_failure_still_permits_a_legitimate_retry() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeSupported = false
        val pin = Sha256.hex(unrelatedContent)
        val restorer = RecoverySnapshotRestorer(io, recovery)

        val first = restorer.restore(vaultUri, pin)
        assertEquals(RestoreOutcome.ProviderNotWritable, first)
        assertEquals(0, io.writes.size)

        io.writeSupported = true
        val second = restorer.restore(vaultUri, pin)

        assertEquals(RestoreOutcome.Success, second)
        assertEquals(1, io.writes.size)
    }

    @Test
    fun preserved_pin_refuses_to_overwrite_a_primary_that_moved_between_attempts() {
        val recovery = storeWithValidSnapshot()
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        io.writeSupported = false
        val pin = Sha256.hex(unrelatedContent)
        val restorer = RecoverySnapshotRestorer(io, recovery)

        val first = restorer.restore(vaultUri, pin)
        assertEquals(RestoreOutcome.ProviderNotWritable, first)
        assertEquals(0, io.writes.size)

        io.writeSupported = true
        val differentUnknownContent = "yet-another-unrelated-content".toByteArray()
        io.setContent(vaultUri, differentUnknownContent)

        val second = restorer.restore(vaultUri, pin)

        assertTrue(second is RestoreOutcome.RecheckRequired)
        assertEquals(0, io.writes.size)
    }

    @Test
    fun marker_read_failure_requires_recheck_and_performs_no_write() {
        val recovery = storeWithValidSnapshot()
        recovery.readMarkerException = IOException("recovery store unavailable")
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, Sha256.hex(unrelatedContent))

        assertEquals(RestoreOutcome.RecheckRequired(null, null), outcome)
        assertEquals(0, io.writes.size)
    }

    @Test
    fun snapshot_read_failure_performs_no_write() {
        val recovery = storeWithValidSnapshot()
        recovery.readSnapshotBytesException = IOException("recovery store unavailable")
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, Sha256.hex(unrelatedContent))

        assertEquals(RestoreOutcome.SnapshotMissing, outcome)
        assertEquals(0, io.writes.size)
    }

    @Test
    fun clear_marker_failure_in_stale_resolution_branch_does_not_crash_or_claim_success() {
        val recovery = storeWithValidSnapshot()
        recovery.clearMarkerException = IOException("recovery store unavailable")
        val io = FakeSafDocumentIo(mapOf(vaultUri to expectedNewContent))
        val stalePin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, stalePin)

        assertEquals(RestoreOutcome.RecheckRequired(ReconciliationOutcome.SAVED, Sha256.hex(expectedNewContent)), outcome)
        assertEquals(0, io.writes.size)
    }

    @Test
    fun verified_write_but_silent_marker_clear_failure_reports_restored_but_marker_clear_failed() {
        val recovery = storeWithValidSnapshot()
        recovery.failClearMarkerSilently = true
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.RestoredButMarkerClearFailed, outcome)
        assertArrayEquals(baselineContent, io.contentOf(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun verified_write_but_marker_clear_exception_reports_restored_but_marker_clear_failed() {
        val recovery = storeWithValidSnapshot()
        recovery.clearMarkerException = IOException("recovery store unavailable")
        val io = FakeSafDocumentIo(mapOf(vaultUri to unrelatedContent))
        val pin = Sha256.hex(unrelatedContent)

        val outcome = RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)

        assertEquals(RestoreOutcome.RestoredButMarkerClearFailed, outcome)
        assertArrayEquals(baselineContent, io.contentOf(vaultUri))
        assertNotNull(recovery.readSnapshotBytes(vaultUri))
    }
}
