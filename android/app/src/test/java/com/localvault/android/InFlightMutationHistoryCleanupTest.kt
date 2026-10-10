package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.EntryInput
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * History cleanup (`recovery.forget`) versus an in-flight save. `MainActivity`
 * keeps its [MutationOwnership] token across lock, and the recent-vault list
 * is reachable again after a lock (Back from FILE_SELECTED), so "Remove from
 * history" and the automatic 5-item eviction can run while the save's thread
 * is still going. `forgetVault`/`confirmForgetVault` therefore refuse, and
 * `rememberVault` keeps everything it evicts, whenever
 * [MutationOwnership.reopenBlocked] is true.
 *
 * A real [VaultSaveCoordinator] runs on a real thread, parked inside it, and
 * the real recovery-store fake and [evictionOutcomeFor] are used. The
 * `MainActivity` branches themselves cannot run on the JVM, so `forgetVault`'s
 * guard is modelled below by [forgetUnlessSaveInFlight] and its wiring needs
 * device (or instrumented) verification.
 */
class InFlightMutationHistoryCleanupTest {

    private val vaultUri = "content://provider/document/vault"
    private val originalBytes = "original-envelope-bytes".toByteArray()
    private val stagedBytes = "staged-envelope-bytes".toByteArray()

    private fun input() = EntryInput(
        title = "t",
        profileName = "",
        url = "",
        username = "u",
        password = "p",
        notes = "",
        categoryId = null,
        tags = emptyList(),
        favorite = false,
    )

    private class Gate {
        private val reached = CountDownLatch(1)
        private val release = CountDownLatch(1)

        /** Called on the save thread. */
        fun park() {
            reached.countDown()
            assertTrue("test never released the save", release.await(5, TimeUnit.SECONDS))
        }

        fun awaitParked() = assertTrue("save never parked", reached.await(5, TimeUnit.SECONDS))

        fun release() = release.countDown()
    }

    private class RunningSave(private val thread: Thread) {
        @Volatile
        var outcome: SaveOutcome? = null

        fun join() {
            thread.join(5_000)
            assertFalse("save thread did not finish", thread.isAlive)
        }
    }

    private enum class ParkAt { STAGE, AFTER_MARKER }

    private fun startSave(
        io: FakeSafDocumentIo,
        recovery: FakeRecoverySnapshotStore,
        gate: Gate,
        parkAt: ParkAt,
    ): RunningSave {
        val session = FakeVaultSession(
            stagedBytes = stagedBytes,
            onStage = if (parkAt == ParkAt.STAGE) ({ gate.park() }) else null,
        )
        val coordinator = VaultSaveCoordinator(session, io, recovery, originalBytes)
        lateinit var running: RunningSave
        val thread = Thread {
            running.outcome =
                coordinator.saveUpdateEntry(
                    vaultUri,
                    "entry-1",
                    input(),
                    1_000L,
                    onAfterMarkerWritten = if (parkAt == ParkAt.AFTER_MARKER) ({ gate.park() }) else null,
                )
        }
        running = RunningSave(thread)
        thread.start()
        return running
    }

    /** Models `MainActivity.forgetVault`'s guard: refuse before any state change. */
    private fun forgetUnlessSaveInFlight(
        ownership: MutationOwnership,
        recovery: FakeRecoverySnapshotStore,
    ): Boolean {
        if (ownership.reopenBlocked) return false
        recovery.forget(vaultUri)
        return true
    }

    @Test
    fun history_removal_cannot_delete_recovery_data_during_a_save_and_works_after_it() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        // Readback fails: the save ends WriteFailed with its marker kept.
        var failed = false
        io.onBeforeRead = {
            if (!failed && io.writes.isNotEmpty()) {
                failed = true
                throw IOException("readback failed")
            }
        }
        val ownership = MutationOwnership()
        val token = ownership.begin()!!
        val gate = Gate()
        val save = startSave(io, recovery, gate, ParkAt.AFTER_MARKER)
        gate.awaitParked()

        // The user has locked and opened the recent list: removal is refused
        // and the snapshot + marker the save depends on are untouched.
        assertFalse(forgetUnlessSaveInFlight(ownership, recovery))
        assertNotNull(recovery.readMarker(vaultUri))
        assertTrue(recovery.readSnapshotBytes(vaultUri)!!.contentEquals(originalBytes))

        gate.release()
        save.join()
        assertEquals(SaveOutcome.WriteFailed, save.outcome)

        // A stale token's completion cannot release ownership...
        ownership.endIfOwned(token + 100)
        assertFalse(forgetUnlessSaveInFlight(ownership, recovery))
        assertNotNull(recovery.readMarker(vaultUri))

        // ...only the real completion can. Normal reconciliation still works
        // on the surviving marker, and removal is then allowed.
        ownership.endIfOwned(token)
        val gateResult = runUnlockPreOpenGate(
            readMarker = { recovery.readMarker(vaultUri) },
            readCurrentBytes = { io.readAll(vaultUri) },
            clearMarker = { recovery.clearMarker(vaultUri) },
            openPrimary = { bytes -> bytes },
        )
        assertEquals(
            ReconciliationOutcome.SAVED,
            (gateResult as UnlockGateResult.Opened<*>).reconciliationOutcome,
        )
        assertTrue(forgetUnlessSaveInFlight(ownership, recovery))
        assertNull(recovery.readMarker(vaultUri))
        assertNull(recovery.readSnapshotBytes(vaultUri))
    }

    @Test
    fun eviction_during_a_save_keeps_everything_even_before_the_marker_exists() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val ownership = MutationOwnership()
        val token = ownership.begin()!!
        val gate = Gate()
        // Parked in the stage call: no snapshot/marker has been written yet,
        // which is exactly when the plain marker check sees nothing to protect.
        val save = startSave(io, recovery, gate, ParkAt.STAGE)
        gate.awaitParked()

        assertFalse(recovery.hasUnresolvedMarker(vaultUri))
        assertEquals(
            "marker check alone would release and forget",
            EvictionOutcome.RELEASE_AND_FORGET,
            evictionOutcomeFor(recovery.hasUnresolvedMarker(vaultUri)),
        )
        val duringSave = evictionOutcomeFor(recovery.hasUnresolvedMarker(vaultUri), ownership.reopenBlocked)
        assertEquals(EvictionOutcome.KEEP, duringSave)

        gate.release()
        save.join()
        assertEquals(SaveOutcome.Success, save.outcome)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))

        // Once the save has completed, ordinary eviction cleanup applies again.
        ownership.endIfOwned(token)
        assertEquals(
            EvictionOutcome.RELEASE_AND_FORGET,
            evictionOutcomeFor(recovery.hasUnresolvedMarker(vaultUri), ownership.reopenBlocked),
        )
    }

    @Test
    fun eviction_during_a_save_with_a_written_marker_keeps_the_recovery_state() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val ownership = MutationOwnership()
        val token = ownership.begin()!!
        val gate = Gate()
        val save = startSave(io, recovery, gate, ParkAt.AFTER_MARKER)
        gate.awaitParked()

        assertTrue(recovery.hasUnresolvedMarker(vaultUri))
        val outcome = evictionOutcomeFor(recovery.hasUnresolvedMarker(vaultUri), ownership.reopenBlocked)
        assertEquals(EvictionOutcome.KEEP, outcome)
        // KEEP means rememberVault never reaches recovery.forget.
        assertNotNull(recovery.readMarker(vaultUri))

        gate.release()
        save.join()
        // The save's own protocol still cleans up after itself.
        assertEquals(SaveOutcome.Success, save.outcome)
        assertNull(recovery.readMarker(vaultUri))
        ownership.endIfOwned(token)
        assertEquals(
            EvictionOutcome.RELEASE_AND_FORGET,
            evictionOutcomeFor(recovery.hasUnresolvedMarker(vaultUri), ownership.reopenBlocked),
        )
    }
}
