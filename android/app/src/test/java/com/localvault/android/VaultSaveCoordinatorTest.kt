package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.CategoryInput
import uniffi.localvault_android_bridge.EntryInput
import uniffi.localvault_android_bridge.InternalException
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

    // -- 1T-B5b: generalized wrappers (saveCreateEntry, saveDeleteEntry,
    // saveCreateCategory, saveUpdateCategory, saveDeleteCategory), all
    // delegating to the same private runStagedSave core saveUpdateEntry
    // already proved above. ------------------------------------------

    private fun createEntryInput(title: String) = EntryInput(
        title = title,
        profileName = "",
        url = "",
        username = "user",
        password = "pass",
        notes = "",
        categoryId = null,
        tags = emptyList(),
        favorite = false,
    )

    private fun categoryInput(name: String) = CategoryInput(name = name)

    @Test
    fun each_wrapper_stages_only_its_own_bridge_call_and_commits_exactly_once() {
        // One shared-core proof for all six public methods: each must
        // reach runStagedSave, invoke exactly its own stage_* call (never
        // a different one), and commit exactly once on success -- proving
        // the mechanical extraction routes correctly without repeating the
        // full transactional sequence's assertions six times over.
        val cases: List<Pair<String, (VaultSaveCoordinator) -> SaveOutcome>> = listOf(
            "stageUpdateEntry" to { c: VaultSaveCoordinator ->
                c.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)
            },
            "stageCreateEntry" to { c: VaultSaveCoordinator ->
                c.saveCreateEntry(vaultUri, createEntryInput("New"), 1_000L)
            },
            "stageDeleteEntry" to { c: VaultSaveCoordinator ->
                c.saveDeleteEntry(vaultUri, "entry-1", 1_000L)
            },
            "stageCreateCategory" to { c: VaultSaveCoordinator ->
                c.saveCreateCategory(vaultUri, categoryInput("New"), 1_000L)
            },
            "stageUpdateCategory" to { c: VaultSaveCoordinator ->
                c.saveUpdateCategory(vaultUri, "category-1", categoryInput("Renamed"), 1_000L)
            },
            "stageDeleteCategory" to { c: VaultSaveCoordinator ->
                c.saveDeleteCategory(vaultUri, "category-1", 1_000L)
            },
        )

        for ((expectedMethod, invoke) in cases) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = invoke(coordinator(io, recovery, session))

            assertEquals("$expectedMethod outcome", SaveOutcome.Success, outcome)
            assertEquals(
                "$expectedMethod should be the only stage call made",
                listOf(expectedMethod),
                session.stagedMethodCalls,
            )
            assertEquals("$expectedMethod commit count", 1, session.commitCount)
            assertEquals("$expectedMethod discard count", 0, session.discardCount)
            assertEquals("$expectedMethod write count", 1, io.writes.size)
        }
    }

    @Test
    fun saveCreateEntry_success_advances_the_baseline_for_the_next_attempt() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        val save = coordinator(io, recovery, session)

        assertEquals(
            SaveOutcome.Success,
            save.saveCreateEntry(vaultUri, createEntryInput("First"), 1_000L),
        )
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))

        // If the coordinator still believed the baseline was the original
        // bytes, this second attempt would incorrectly report
        // ChangedExternally even though nothing external happened -- only
        // this coordinator's own prior save changed the primary.
        val secondOutcome = save.saveCreateEntry(vaultUri, createEntryInput("Second"), 2_000L)

        assertEquals(SaveOutcome.Success, secondOutcome)
        assertEquals(2, session.commitCount)
    }

    @Test
    fun saveCreateEntry_first_stale_check_mismatch_does_not_stage_or_write() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to "externally-changed-bytes".toByteArray()))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session)
            .saveCreateEntry(vaultUri, createEntryInput("New"), 1_000L)

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        assertEquals(0, session.stageCount)
        assertEquals(0, io.writes.size)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun saveDeleteEntry_write_failure_leaves_the_marker_unresolved_for_next_unlock_reconciliation() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeException = IOException("provider write failed")
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session)
            .saveDeleteEntry(vaultUri, "entry-1", 1_000L)

        assertEquals(SaveOutcome.WriteFailed, outcome)
        // Deliberately still present: the outcome here is genuinely
        // unknown until the next unlock reconciles it against disk truth.
        assertEquals(0, session.commitCount)
        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
    }

    @Test
    fun saveDeleteCategory_categoryInUse_surfaces_as_validationFailed_and_never_commits() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stageException = BridgeException.CategoryInUse())

        val outcome = coordinator(io, recovery, session)
            .saveDeleteCategory(vaultUri, "category-1", 1_000L)

        assertTrue(outcome is SaveOutcome.ValidationFailed)
        assertTrue((outcome as SaveOutcome.ValidationFailed).error is BridgeException.CategoryInUse)
        // A rejected stage never opens/writes the primary and never commits.
        assertEquals(0, io.writes.size)
        assertEquals(0, session.commitCount)
        assertEquals(0, recovery.writeAndVerifyCallCount)
    }

    @Test
    fun saveCreateCategory_second_stale_check_still_catches_a_race_after_generalization() {
        // Mirrors second_stale_check_catches_a_change_injected_after_staging_and_never_opens_the_primary
        // above, but through a non-update wrapper -- proves the extraction
        // preserved the shared marker/stale-check ordering for every
        // mutation type, not only stageUpdateEntry.
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(
            stagedBytes = stagedBytes,
            onStage = { io.setContent(vaultUri, "raced-external-write".toByteArray()) },
        )

        val outcome = coordinator(io, recovery, session)
            .saveCreateCategory(vaultUri, categoryInput("New"), 1_000L)

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        // The primary must never be opened for writing once this is caught.
        assertEquals(0, io.writes.size)
        assertEquals(1, session.discardCount)
        assertNull(recovery.readMarker(vaultUri))
    }

    // -- 1T-B5c-1: saveSetEntryTotp / saveRemoveEntryTotp, both thin
    // wrappers over the same private runStagedSave core. These tests prove
    // routing, verbatim pass-through and inheritance of the shared
    // behavior -- not a second copy of the transactional sequence. -------

    // Deliberately awkward: leading/trailing whitespace (incl. a tab and a
    // newline), lower case, inner spaces and '=' padding. A throw-away test
    // value, not a real key.
    private val awkwardSetupInput = "  gezd gnbv\tgy3t qojq gezd gnbv gy3t qojq====\n"

    private val setEntryTotp: (VaultSaveCoordinator) -> SaveOutcome = { c ->
        c.saveSetEntryTotp(vaultUri, "entry-1", awkwardSetupInput, 1_000L)
    }

    private val removeEntryTotp: (VaultSaveCoordinator) -> SaveOutcome = { c ->
        c.saveRemoveEntryTotp(vaultUri, "entry-1", 1_000L)
    }

    private val totpWrappers: List<Pair<String, (VaultSaveCoordinator) -> SaveOutcome>> = listOf(
        "stageSetEntryTotp" to setEntryTotp,
        "stageRemoveEntryTotp" to removeEntryTotp,
    )

    // A. / B. successful paths through the shared pipeline.

    @Test
    fun saveSetEntryTotp_success_uses_the_shared_pipeline_and_advances_the_baseline() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        val save = coordinator(io, recovery, session)

        val outcome = save.saveSetEntryTotp(vaultUri, "entry-1", awkwardSetupInput, 1_000L)

        assertEquals(SaveOutcome.Success, outcome)
        assertEquals(listOf("stageSetEntryTotp"), session.stagedMethodCalls)
        assertEquals(1, session.stageCount)
        assertEquals(1, session.commitCount)
        assertEquals(0, session.discardCount)
        // Existing shared behavior: exactly one write of the staged bytes,
        // marker cleared, primary now equals the staged bytes.
        assertEquals(1, io.writes.size)
        assertTrue(io.writes[0].contentEquals(stagedBytes))
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))
        assertNull(recovery.readMarker(vaultUri))
        // The durable snapshot holds the pre-write ciphertext, nothing else.
        assertTrue(recovery.readSnapshotBytes(vaultUri)!!.contentEquals(originalBytes))

        // Baseline advanced: a second attempt is not mistaken for an
        // external change.
        val secondOutcome = save.saveSetEntryTotp(vaultUri, "entry-1", awkwardSetupInput, 2_000L)

        assertEquals(SaveOutcome.Success, secondOutcome)
        assertEquals(2, session.commitCount)
    }

    @Test
    fun saveRemoveEntryTotp_success_uses_the_shared_pipeline_and_advances_the_baseline() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        val save = coordinator(io, recovery, session)

        val outcome = save.saveRemoveEntryTotp(vaultUri, "entry-1", 1_000L)

        assertEquals(SaveOutcome.Success, outcome)
        assertEquals(listOf("stageRemoveEntryTotp"), session.stagedMethodCalls)
        assertEquals(1, session.commitCount)
        assertEquals(0, session.discardCount)
        assertEquals(1, io.writes.size)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))
        assertNull(recovery.readMarker(vaultUri))

        val secondOutcome = save.saveRemoveEntryTotp(vaultUri, "entry-1", 2_000L)

        assertEquals(SaveOutcome.Success, secondOutcome)
        assertEquals(2, session.commitCount)
    }

    // C. dispatch isolation.

    @Test
    fun totp_wrappers_each_reach_only_their_own_stage_call() {
        for ((expectedMethod, invoke) in totpWrappers) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = invoke(coordinator(io, recovery, session))

            assertEquals("$expectedMethod outcome", SaveOutcome.Success, outcome)
            // Set never reaches remove, and remove never reaches set (nor
            // any of the six pre-existing stage calls).
            assertEquals(
                "$expectedMethod should be the only stage call made",
                listOf(expectedMethod),
                session.stagedMethodCalls,
            )
        }
    }

    @Test
    fun saveRemoveEntryTotp_never_passes_any_setup_input_to_the_session() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        coordinator(io, FakeRecoverySnapshotStore(), session).saveRemoveEntryTotp(vaultUri, "entry-1", 1_000L)

        assertNull(session.lastSetupInput)
    }

    // D. verbatim pass-through.

    @Test
    fun saveSetEntryTotp_passes_setupInput_to_the_session_exactly_as_given() {
        val inputs = listOf(
            awkwardSetupInput,
            "otpauth://totp/Example:alice?secret=gezdgnbvgy3tqojq&issuer=Example Inc&digits=6",
            "OTPAUTH://TOTP/Example?SECRET=GEZDGNBVGY3TQOJQ====",
            "   ",
            "",
        )

        for (input in inputs) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            coordinator(io, FakeRecoverySnapshotStore(), session)
                .saveSetEntryTotp(vaultUri, "entry-1", input, 1_000L)

            // Not trimmed, not case-folded, padding and inner whitespace
            // intact, not parsed: the very same characters reach the bridge
            // (empty/blank input too -- rejecting it is core's job).
            assertEquals(input, session.lastSetupInput)
            assertEquals(input.length, session.lastSetupInput!!.length)
        }
    }

    // E. bridge rejection of the setup input.

    @Test
    fun saveSetEntryTotp_invalidTotpConfiguration_surfaces_as_validationFailed_and_never_writes() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stageException = BridgeException.InvalidTotpConfiguration())

        val outcome = coordinator(io, recovery, session)
            .saveSetEntryTotp(vaultUri, "entry-1", awkwardSetupInput, 1_000L)

        assertTrue(outcome is SaveOutcome.ValidationFailed)
        assertTrue((outcome as SaveOutcome.ValidationFailed).error is BridgeException.InvalidTotpConfiguration)
        // A rejected stage never opens/writes the primary, never creates a
        // marker/snapshot transaction, and never commits.
        assertEquals(0, io.writes.size)
        assertEquals(0, recovery.writeAndVerifyCallCount)
        assertNull(recovery.readMarker(vaultUri))
        assertEquals(0, session.commitCount)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(originalBytes))
        // The raw input is not carried into the outcome's text.
        assertTrue(!outcome.toString().contains("gezd"))
    }

    @Test
    fun saveRemoveEntryTotp_totpNotConfigured_surfaces_as_validationFailed_and_never_writes() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stageException = BridgeException.TotpNotConfigured())

        val outcome = coordinator(io, recovery, session).saveRemoveEntryTotp(vaultUri, "entry-1", 1_000L)

        assertTrue(outcome is SaveOutcome.ValidationFailed)
        assertTrue((outcome as SaveOutcome.ValidationFailed).error is BridgeException.TotpNotConfigured)
        assertEquals(0, io.writes.size)
        assertEquals(0, recovery.writeAndVerifyCallCount)
        assertEquals(0, session.commitCount)
    }

    // F. ProviderNotWritable inherited from the shared pre-stage check.

    @Test
    fun totp_wrappers_do_not_stage_or_write_without_a_live_write_grant() {
        for ((name, invoke) in totpWrappers) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            io.writeGrant = false
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = invoke(coordinator(io, recovery, session))

            assertEquals("$name outcome", SaveOutcome.ProviderNotWritable, outcome)
            assertEquals("$name stage count", 0, session.stageCount)
            assertTrue("$name stage calls", session.stagedMethodCalls.isEmpty())
            assertEquals("$name write count", 0, io.writes.size)
            assertEquals("$name read count", 0, io.readCount)
            assertEquals("$name snapshot count", 0, recovery.writeAndVerifyCallCount)
        }
    }

    @Test
    fun totp_wrappers_do_not_stage_or_write_when_the_provider_reports_no_write_support() {
        for ((name, invoke) in totpWrappers) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            io.writeSupported = false
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = invoke(coordinator(io, recovery, session))

            assertEquals("$name outcome", SaveOutcome.ProviderNotWritable, outcome)
            assertEquals("$name stage count", 0, session.stageCount)
            assertEquals("$name write count", 0, io.writes.size)
        }
    }

    // G. ChangedExternally via both shared stale checks.

    @Test
    fun totp_wrappers_first_stale_check_mismatch_aborts_before_staging_anything() {
        for ((name, invoke) in totpWrappers) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to "externally-changed-bytes".toByteArray()))
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = invoke(coordinator(io, recovery, session))

            assertEquals("$name outcome", SaveOutcome.ChangedExternally, outcome)
            assertEquals("$name stage count", 0, session.stageCount)
            assertNull("$name raw input never reached the session", session.lastSetupInput)
            assertEquals("$name write count", 0, io.writes.size)
            assertNull("$name marker", recovery.readMarker(vaultUri))
        }
    }

    @Test
    fun saveSetEntryTotp_second_stale_check_via_the_existing_after_marker_hook_catches_a_race() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        var markerExistedWhenRaceInjected = false

        val outcome = coordinator(io, recovery, session).saveSetEntryTotp(
            vaultUri,
            "entry-1",
            awkwardSetupInput,
            1_000L,
            onAfterMarkerWritten = {
                markerExistedWhenRaceInjected = recovery.hasUnresolvedMarker(vaultUri)
                io.setContent(vaultUri, "raced-external-write".toByteArray())
            },
        )

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        assertTrue(markerExistedWhenRaceInjected)
        // Staged, then aborted by stale check #2: primary never written, the
        // stage discarded, the marker explicitly cleared, nothing committed.
        assertEquals(1, session.stageCount)
        assertEquals(0, io.writes.size)
        assertEquals(1, session.discardCount)
        assertEquals(0, session.commitCount)
        assertNull(recovery.readMarker(vaultUri))
        assertTrue(io.contentOf(vaultUri)!!.contentEquals("raced-external-write".toByteArray()))
    }

    @Test
    fun saveRemoveEntryTotp_second_stale_check_catches_a_change_injected_while_staging() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(
            stagedBytes = stagedBytes,
            onStage = { io.setContent(vaultUri, "raced-external-write".toByteArray()) },
        )

        val outcome = coordinator(io, recovery, session).saveRemoveEntryTotp(vaultUri, "entry-1", 1_000L)

        assertEquals(SaveOutcome.ChangedExternally, outcome)
        assertEquals(0, io.writes.size)
        assertEquals(1, session.discardCount)
        assertEquals(0, session.commitCount)
        assertNull(recovery.readMarker(vaultUri))
    }

    // H. write / readback failure paths inherited unchanged.

    @Test
    fun saveSetEntryTotp_write_failure_leaves_the_marker_unresolved_and_never_commits() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeException = IOException("provider write failed")
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session)
            .saveSetEntryTotp(vaultUri, "entry-1", awkwardSetupInput, 1_000L)

        assertEquals(SaveOutcome.WriteFailed, outcome)
        assertEquals(0, session.commitCount)
        // Same as every other mutation: left for next-unlock reconciliation.
        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
    }

    @Test
    fun saveRemoveEntryTotp_readback_mismatch_is_a_write_failure_with_the_marker_left_unresolved() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeTransform = { written -> written + "-corrupted-by-provider".toByteArray() }
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session).saveRemoveEntryTotp(vaultUri, "entry-1", 1_000L)

        assertEquals(SaveOutcome.WriteFailed, outcome)
        assertEquals(0, session.commitCount)
        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
    }

    @Test
    fun totp_wrappers_recovery_snapshot_failure_fails_closed_before_touching_the_primary() {
        for ((name, invoke) in totpWrappers) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            val recovery = FakeRecoverySnapshotStore()
            recovery.failWrites = true
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = invoke(coordinator(io, recovery, session))

            assertEquals("$name outcome", SaveOutcome.RecoverySnapshotFailed, outcome)
            assertEquals("$name discard count", 1, session.discardCount)
            assertEquals("$name commit count", 0, session.commitCount)
            assertEquals("$name write count", 0, io.writes.size)
        }
    }

    // -- Issue 2 (B5 correctness follow-up): the Rust staged candidate must
    // not stay pending after SaveOutcome.WriteFailed. Recovery state (marker,
    // snapshot, baseline) is deliberately left untouched. ------------------

    /** Each of the three existing WriteFailed paths, as a way to configure
     * the fakes so the save ends in [SaveOutcome.WriteFailed]. */
    private val writeFailureModes: List<Pair<String, (FakeSafDocumentIo) -> Unit>> = listOf(
        "primary write throws" to { io: FakeSafDocumentIo ->
            io.writeException = IOException("provider write failed")
        },
        "readback read throws" to { io: FakeSafDocumentIo ->
            // Reads: #1 stale check 1, #2 stale check 2, #3 readback.
            io.onBeforeRead = { if (io.readCount >= 3) throw IOException("readback failed") }
        },
        "readback bytes mismatch" to { io: FakeSafDocumentIo ->
            io.writeTransform = { written -> written + "-corrupted-by-provider".toByteArray() }
        },
    )

    @Test
    fun write_failed_paths_discard_the_stage_once_and_leave_recovery_state_untouched() {
        for ((name, configure) in writeFailureModes) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            configure(io)
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)

            val outcome = coordinator(io, recovery, session)
                .saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

            assertEquals("$name outcome", SaveOutcome.WriteFailed, outcome)
            assertEquals("$name discard count", 1, session.discardCount)
            assertEquals("$name commit count", 0, session.commitCount)
            assertTrue("$name marker kept", recovery.hasUnresolvedMarker(vaultUri))
            assertEquals("$name marker baseline", Sha256.hex(originalBytes), recovery.readMarker(vaultUri)!!.baselineSha256)
            assertEquals("$name marker expected", Sha256.hex(stagedBytes), recovery.readMarker(vaultUri)!!.expectedNewSha256)
            assertTrue("$name snapshot is the pre-write primary", recovery.readSnapshotBytes(vaultUri)!!.contentEquals(originalBytes))
            assertEquals("$name snapshot written once", 1, recovery.writeAndVerifyCallCount)
        }
    }

    @Test
    fun retry_after_write_failed_with_untouched_primary_succeeds_when_only_one_pending_stage_is_allowed() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeException = IOException("provider write failed")
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        session.enforceSinglePendingStage = true
        val save = coordinator(io, recovery, session)

        assertEquals(SaveOutcome.WriteFailed, save.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L))
        assertTrue(!session.hasPendingStage)

        // The failed write never touched the primary; the provider recovers.
        io.writeException = null
        val retry = save.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 2_000L)

        assertEquals(SaveOutcome.Success, retry)
        assertEquals(1, session.commitCount)
        assertNull(recovery.readMarker(vaultUri))
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))
    }

    @Test
    fun retry_after_a_failed_write_that_changed_the_primary_is_changed_externally_and_keeps_recovery_state() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.writeTransform = { written -> written + "-corrupted-by-provider".toByteArray() }
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        session.enforceSinglePendingStage = true
        val save = coordinator(io, recovery, session)

        assertEquals(SaveOutcome.WriteFailed, save.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L))
        val markerAfterFailure = recovery.readMarker(vaultUri)!!

        val retry = save.saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 2_000L)

        assertEquals(SaveOutcome.ChangedExternally, retry)
        // Stopped at stale check #1: nothing staged, written or committed,
        // and the recovery marker/snapshot from the failed attempt remain.
        assertEquals(1, session.stageCount)
        assertEquals(0, session.commitCount)
        assertEquals(1, io.writes.size)
        assertEquals(1, recovery.writeAndVerifyCallCount)
        assertEquals(markerAfterFailure, recovery.readMarker(vaultUri))
        assertTrue(recovery.readSnapshotBytes(vaultUri)!!.contentEquals(originalBytes))
    }

    @Test
    fun write_succeeded_but_readback_threw_still_reconciles_as_saved_on_next_unlock() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        io.onBeforeRead = { if (io.readCount >= 3) throw IOException("readback failed") }
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session)
            .saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)
        assertEquals(SaveOutcome.WriteFailed, outcome)
        assertEquals(1, session.discardCount)

        io.onBeforeRead = null
        val gate = runUnlockPreOpenGate(
            readMarker = { recovery.readMarker(vaultUri) },
            readCurrentBytes = { io.readAll(vaultUri) },
            clearMarker = { recovery.clearMarker(vaultUri) },
            openPrimary = { bytes -> bytes },
        )

        val opened = gate as UnlockGateResult.Opened<ByteArray>
        assertEquals(ReconciliationOutcome.SAVED, opened.reconciliationOutcome)
        assertTrue(opened.envelopeBytes.contentEquals(stagedBytes))
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun partial_or_corrupt_write_still_reconciles_as_recovery_needed_on_next_unlock() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val corrupted = { written: ByteArray -> written.copyOf(written.size / 2) }
        io.writeTransform = corrupted
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)

        val outcome = coordinator(io, recovery, session)
            .saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)
        assertEquals(SaveOutcome.WriteFailed, outcome)
        assertEquals(1, session.discardCount)

        val gate = runUnlockPreOpenGate(
            readMarker = { recovery.readMarker(vaultUri) },
            readCurrentBytes = { io.readAll(vaultUri) },
            clearMarker = { recovery.clearMarker(vaultUri) },
            openPrimary = { bytes -> bytes },
        )

        assertTrue(gate is UnlockGateResult.RecoveryNeeded<*>)
        assertEquals(
            Sha256.hex(corrupted(stagedBytes)),
            (gate as UnlockGateResult.RecoveryNeeded<*>).unresolvedPrimarySha256,
        )
        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
        assertTrue(recovery.readSnapshotBytes(vaultUri)!!.contentEquals(originalBytes))
    }

    @Test
    fun already_closed_session_during_discard_still_returns_write_failed_and_keeps_recovery_state() {
        for ((name, configure) in writeFailureModes) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            configure(io)
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)
            session.discardException = IllegalStateException("VaultSession object has already been destroyed")

            val outcome = coordinator(io, recovery, session)
                .saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)

            assertEquals("$name outcome", SaveOutcome.WriteFailed, outcome)
            assertEquals("$name discard attempted once", 1, session.discardCount)
            assertEquals("$name commit count", 0, session.commitCount)
            assertTrue("$name marker kept", recovery.hasUnresolvedMarker(vaultUri))
        }
    }

    @Test
    fun unrelated_internal_exception_from_discard_is_not_swallowed() {
        for ((name, configure) in writeFailureModes) {
            val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
            configure(io)
            val recovery = FakeRecoverySnapshotStore()
            val session = FakeVaultSession(stagedBytes = stagedBytes)
            val failure = InternalException("unexpected bridge failure")
            session.discardException = failure

            val thrown =
                try {
                    coordinator(io, recovery, session)
                        .saveUpdateEntry(vaultUri, "entry-1", sampleInput(), 1_000L)
                    null
                } catch (error: InternalException) {
                    error
                }

            assertSame("$name must propagate the discard failure", failure, thrown)
            assertEquals("$name commit count", 0, session.commitCount)
            // Recovery state is still intact for next-unlock reconciliation.
            assertTrue("$name marker kept", recovery.hasUnresolvedMarker(vaultUri))
        }
    }
}
