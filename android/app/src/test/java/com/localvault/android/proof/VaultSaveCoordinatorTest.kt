package com.localvault.android.proof

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.EntryInput
import java.io.IOException

/**
 * Exercises [VaultSaveCoordinator]'s accepted two-stale-check save sequence
 * (1T-B5 storage/mutation architecture review, Revision 3, section 4) end
 * to end against fakes -- no `ContentResolver`, no native bridge library,
 * no Android runtime involved, so this runs as a plain JVM unit test.
 */
class VaultSaveCoordinatorTest {

    private val vaultUri = "content://provider/document/vault"
    private val originalBytes = "original-envelope-bytes".toByteArray()
    private val stagedBytes = "staged-envelope-bytes".toByteArray()

    private fun sampleInput() = EntryInput(
        title = "Updated Title",
        profileName = "",
        url = "",
        username = "user",
        password = "pass",
        notes = "",
        categoryId = null,
        tags = emptyList(),
        favorite = false,
    )

    private fun coordinator(
        io: FakeSafDocumentIo,
        recovery: FakeRecoverySnapshotStore,
        session: FakeVaultSession,
    ) = VaultSaveCoordinator(session, io, recovery, originalBytes)

    @Test
    fun happy_path_commits_writes_wt_and_clears_the_marker() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.Success, outcome)
        assertEquals(1, session.commitCount)
        assertEquals(0, session.discardCount)
        assertNull(recovery.readMarker(vaultUri))
        assertEquals(1, io.writes.size)
        assertTrue(io.writes[0].contentEquals(stagedBytes))
        // The primary now reflects the staged bytes.
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))
    }

    @Test
    fun does_not_attempt_a_write_without_a_live_persisted_write_grant() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeGrant = false
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.ProviderNotWritable, outcome)
        assertEquals(0, session.stageCount)
        assertEquals(0, io.writes.size)
    }

    @Test
    fun does_not_attempt_a_write_when_the_provider_no_longer_reports_write_support() {
        // Confirms live capability is re-checked every attempt -- never
        // assumed from whatever granted the write permission originally.
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeSupported = false
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.ProviderNotWritable, outcome)
        assertEquals(0, session.stageCount)
    }

    @Test
    fun first_stale_check_mismatch_aborts_before_staging_anything() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to "externally-changed-bytes".toByteArray()))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        // The coordinator was constructed with originalBytes as its
        // baseline, but the document now holds different content.
        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        assertEquals(0, session.stageCount)
        assertEquals(0, io.writes.size)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun recovery_snapshot_failure_fails_closed_before_touching_the_primary() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        recovery.failWrites = true
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.RecoverySnapshotFailed, outcome)
        assertEquals(1, session.discardCount)
        assertEquals(0, session.commitCount)
        assertEquals(0, io.writes.size)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun second_stale_check_catches_a_change_injected_after_staging_and_never_opens_the_primary() {
        // The external write happens exactly between the first check and
        // the second -- realistically, while this attempt was staging and
        // writing its recovery snapshot -- modelled here by mutating the
        // fake document as a side effect of the stage call itself.
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(
            stagedBytes = stagedBytes,
            onStage = { io.setContent(vaultUri, "raced-external-write".toByteArray()) },
        )

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        // The primary must never be opened for writing once this is caught.
        assertEquals(0, io.writes.size)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals("raced-external-write".toByteArray()))
        // LocalVault never touched the primary this attempt: the stage is
        // discarded and the marker is explicitly cleared, not left
        // unresolved -- distinct from a genuine write failure.
        assertEquals(1, session.discardCount)
        assertNull(recovery.readMarker(vaultUri))
        // The now-stale snapshot from step 4 is not deleted (still
        // available for a *different*, prior unresolved case), but it must
        // not be surfaced as recovering *this* external change -- that is
        // an outcome-type distinction (ChangedExternally, not WriteFailed)
        // the caller relies on to avoid offering it.
    }

    @Test
    fun validation_failure_from_staging_does_not_touch_the_primary() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stageException = BridgeException.EntryNotFound())

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "missing-entry", sampleInput(), 1_000L)

        assertTrue(outcome is SaveOutcome.ValidationFailed)
        assertTrue((outcome as SaveOutcome.ValidationFailed).error is BridgeException.EntryNotFound)
        assertEquals(0, io.writes.size)
        assertEquals(0, recovery.writeAndVerifyCallCount)
    }

    @Test
    fun primary_write_failure_leaves_the_marker_unresolved_for_next_unlock_reconciliation() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeException = IOException("provider write failed")
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.WriteFailed, outcome)
        // Deliberately still present: the outcome here is genuinely
        // unknown until the next unlock reconciles it against disk truth.
        assertEquals(0, session.commitCount)
        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
    }

    @Test
    fun readback_mismatch_is_treated_as_write_failure_with_marker_left_unresolved() {
        // A provider that silently does not honor "wt" truncation (or a
        // truncated/partial write) is caught by exact byte comparison, not
        // merely a successful stream close.
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeTransform = { written -> written + "-corrupted-by-provider".toByteArray() }
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.WriteFailed, outcome)
        assertEquals(0, session.commitCount)
        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
    }

    @Test
    fun after_marker_hook_fires_exactly_once_after_the_marker_exists_and_before_the_second_read() {
        // This is the exact hook 1T-B5a's debug-only real-device QA harness
        // (MainActivity.awaitQaResume) uses to deterministically inject
        // both Revision 3 fault scenarios at the one moment they both
        // require: after the durable recovery snapshot/marker already
        // exist, before stale check #2 re-reads the primary.
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        var hookCalls = 0
        var markerExistedAtHookTime = false
        var readCountAtHookTime = -1

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(
            vaultUri,
            "entry-1",
            sampleInput(),
            1_000L,
            onAfterMarkerWritten = {
                hookCalls++
                markerExistedAtHookTime = recovery.hasUnresolvedMarker(vaultUri)
                readCountAtHookTime = io.readCount
            },
        )

        assertEquals(SaveOutcome.Success, outcome)
        assertEquals(1, hookCalls)
        assertTrue(markerExistedAtHookTime)
        // Exactly one read (the first stale check) must have happened
        // before the hook fires; the second (step 7) and the post-write
        // readback verification (step 9) both happen after it, for three
        // reads total by the end of a successful save.
        assertEquals(1, readCountAtHookTime)
        assertEquals(3, io.readCount)
    }

    @Test
    fun after_marker_hook_is_never_called_when_the_recovery_snapshot_fails() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        recovery.failWrites = true
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        var hookCalls = 0

        coordinator(io, recovery, session).saveUpdateEntry(
            vaultUri,
            "entry-1",
            sampleInput(),
            1_000L,
            onAfterMarkerWritten = { hookCalls++ },
        )

        assertEquals(0, hookCalls)
    }

    // -- onAfterPrimaryWrite ------------------------------------------

    @Test
    fun after_primary_write_hook_fires_exactly_once_after_the_real_write_and_before_readback() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        var hookCalls = 0
        var writesAtHookTime = -1
        var primaryContentAtHookTime: ByteArray? = null
        var readCountAtHookTime = -1
        var markerExistedAtHookTime = false

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(
            vaultUri,
            "entry-1",
            sampleInput(),
            1_000L,
            onAfterMarkerWritten = null,
            onAfterPrimaryWrite = {
                hookCalls++
                writesAtHookTime = io.writes.size
                primaryContentAtHookTime = io.contentOf(vaultUri)
                // The second stale check (step 7) and the "wt" write
                // (step 8) both count as reads/writes that must already
                // have happened; the post-write readback verification
                // (step 9) has NOT happened yet at this point.
                readCountAtHookTime = io.readCount
                markerExistedAtHookTime = recovery.hasUnresolvedMarker(vaultUri)
            },
        )

        assertEquals(SaveOutcome.Success, outcome)
        assertEquals(1, hookCalls)
        // The real ContentResolver-path write has already landed...
        assertEquals(1, writesAtHookTime)
        assertTrue(primaryContentAtHookTime!!.contentEquals(stagedBytes))
        // ...but the readback verification read (step 9) has not happened
        // yet: only the two stale-check reads (steps 1-2 and 7) have.
        assertEquals(2, readCountAtHookTime)
        // The marker is still present -- neither cleared nor resolved --
        // exactly the state a killed process must leave behind for
        // next-unlock reconciliation to find and resolve as SAVED.
        assertTrue(markerExistedAtHookTime)
        // By the time the whole call returns normally (no interruption),
        // the marker has since been cleared by the ordinary success path.
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun after_primary_write_hook_is_never_called_when_the_second_stale_check_aborts() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(
            stagedBytes = stagedBytes,
            onStage = { io.setContent(vaultUri, "raced-external-write".toByteArray()) },
        )
        var afterPrimaryWriteCalls = 0

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(
            vaultUri,
            "entry-1",
            sampleInput(),
            1_000L,
            onAfterMarkerWritten = null,
            onAfterPrimaryWrite = { afterPrimaryWriteCalls++ },
        )

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        assertEquals(0, afterPrimaryWriteCalls)
        assertEquals(0, io.writes.size)
    }

    @Test
    fun after_primary_write_hook_is_never_called_when_the_primary_write_itself_fails() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeException = IOException("provider write failed")
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        var afterPrimaryWriteCalls = 0

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(
            vaultUri,
            "entry-1",
            sampleInput(),
            1_000L,
            onAfterMarkerWritten = null,
            onAfterPrimaryWrite = { afterPrimaryWriteCalls++ },
        )

        assertEquals(SaveOutcome.WriteFailed, outcome)
        assertEquals(0, afterPrimaryWriteCalls)
    }

    @Test
    fun normal_behavior_is_unchanged_when_both_hooks_are_null() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

        assertEquals(SaveOutcome.Success, outcome)
        assertEquals(1, session.commitCount)
        assertNull(recovery.readMarker(vaultUri))
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))
    }

    @Test
    fun a_successful_save_advances_the_in_memory_baseline_for_the_next_attempt() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        val save = coordinator(io, recovery, session)

        assertEquals(SaveOutcome.Success, save.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L))
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))

        // If the coordinator still believed the baseline was the original
        // bytes, this second attempt would incorrectly report
        // ChangedExternally even though nothing external happened -- only
        // this coordinator's own prior save changed the primary.
        val secondOutcome = save.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 2_000L)

        assertEquals(SaveOutcome.Success, secondOutcome)
        assertEquals(2, session.commitCount)
    }
}
