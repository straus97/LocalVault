package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.EntryInput
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * The lock-during-save race (audit finding P2-4): `MainActivity` keeps its
 * [MutationOwnership] token across lock/onStop because the save's bare
 * `Thread` cannot be cancelled, so [MutationOwnership.reopenBlocked] is what
 * must keep `startUnlock`/`runRestore` away from the vault until that thread
 * completes. These tests run a real [VaultSaveCoordinator] on a real thread,
 * parked at its QA hooks, against the real [runUnlockPreOpenGate] and
 * [RecoverySnapshotRestorer].
 *
 * `MainActivity` itself cannot run on the JVM, so the two call sites that
 * consult the guard are not exercised here; they are one-line
 * `if (mutationOwnership.reopenBlocked) { toast; return }` checks that need
 * device (or instrumented) verification.
 */
class InFlightMutationReopenGuardTest {

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

    /** A save running on its own thread, parked inside one of the coordinator's hooks. */
    private class ParkedSave(
        private val reached: CountDownLatch,
        private val release: CountDownLatch,
        private val thread: Thread,
    ) {
        @Volatile
        var outcome: SaveOutcome? = null

        fun awaitParked() = assertTrue("save never reached its hook", reached.await(5, TimeUnit.SECONDS))

        fun finish() {
            release.countDown()
            thread.join(5_000)
            assertFalse("save thread did not finish", thread.isAlive)
        }
    }

    private fun startSave(
        io: FakeSafDocumentIo,
        recovery: FakeRecoverySnapshotStore,
        session: FakeVaultSession,
        parkAfterMarker: Boolean,
    ): ParkedSave {
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        val park = {
            reached.countDown()
            assertTrue("test never released the save", release.await(5, TimeUnit.SECONDS))
        }
        val coordinator = VaultSaveCoordinator(session, io, recovery, originalBytes)
        lateinit var parked: ParkedSave
        val thread = Thread {
            parked.outcome =
                coordinator.saveUpdateEntry(
                    vaultUri,
                    "entry-1",
                    input(),
                    1_000L,
                    onAfterMarkerWritten = if (parkAfterMarker) park else null,
                    onAfterPrimaryWrite = if (parkAfterMarker) null else park,
                )
        }
        parked = ParkedSave(reached, release, thread)
        thread.start()
        return parked
    }

    /** Fails exactly one read, the first after the primary write: the save's readback. */
    private fun failFirstReadAfterWrite(io: FakeSafDocumentIo) {
        var failed = false
        io.onBeforeRead = {
            if (!failed && io.writes.isNotEmpty()) {
                failed = true
                throw IOException("readback failed")
            }
        }
    }

    private fun unlockGate(io: FakeSafDocumentIo, recovery: FakeRecoverySnapshotStore) =
        runUnlockPreOpenGate(
            readMarker = { recovery.readMarker(vaultUri) },
            readCurrentBytes = { io.readAll(vaultUri) },
            clearMarker = { recovery.clearMarker(vaultUri) },
            openPrimary = { bytes -> bytes },
        )

    @Test
    fun root_cause_an_unguarded_gate_clears_the_marker_the_inflight_save_still_depends_on() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        // The session was already locked/closed by onStop.
        val session = FakeVaultSession(stagedBytes = stagedBytes).apply {
            discardException = IllegalStateException("already destroyed")
        }
        // Readback fails, so the save ends WriteFailed with the marker kept
        // -- the one state in which that marker is the only protection.
        failFirstReadAfterWrite(io)
        val save = startSave(io, recovery, session, parkAfterMarker = true)
        save.awaitParked()

        // Primary still equals the baseline, so the gate reads NOT_SAVED...
        val gate = unlockGate(io, recovery)
        assertTrue(gate is UnlockGateResult.Opened<*>)
        assertEquals(ReconciliationOutcome.NOT_SAVED, (gate as UnlockGateResult.Opened<*>).reconciliationOutcome)
        // ...and clears the marker.
        assertNull(recovery.readMarker(vaultUri))

        save.finish()

        // The in-flight save then wrote the primary anyway, with no marker.
        assertEquals(SaveOutcome.WriteFailed, save.outcome)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(stagedBytes))
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun inflight_mutation_blocks_reconciliation_and_it_resumes_normally_once_the_save_finishes() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes).apply {
            discardException = IllegalStateException("already destroyed")
        }
        failFirstReadAfterWrite(io)
        val ownership = MutationOwnership()
        val token = ownership.begin()!!
        val save = startSave(io, recovery, session, parkAfterMarker = true)
        save.awaitParked()

        // Locked/backgrounded while the save thread is still running: the
        // token deliberately survives, so a reopen attempt is refused and
        // never reaches the gate.
        assertTrue(ownership.reopenBlocked)
        val readsWhileBlocked = io.readCount
        val gateResult = if (ownership.reopenBlocked) null else unlockGate(io, recovery)
        assertNull(gateResult)
        assertEquals(readsWhileBlocked, io.readCount)
        assertNotNull(recovery.readMarker(vaultUri))

        save.finish()
        assertEquals(SaveOutcome.WriteFailed, save.outcome)
        // The completion callback is what releases the guard.
        assertTrue(ownership.reopenBlocked)
        ownership.endIfOwned(token)
        assertFalse(ownership.reopenBlocked)

        // Normal next-unlock reconciliation: the marker survived the whole
        // race, and disk truth (primary == expected-new) resolves it SAVED.
        val gate = if (ownership.reopenBlocked) null else unlockGate(io, recovery)
        assertTrue(gate is UnlockGateResult.Opened<*>)
        assertEquals(ReconciliationOutcome.SAVED, (gate as UnlockGateResult.Opened<*>).reconciliationOutcome)
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun inflight_mutation_blocks_restore_and_it_resumes_once_the_save_finishes() {
        val io = FakeSafDocumentIo(mapOf(vaultUri to originalBytes))
        val recovery = FakeRecoverySnapshotStore()
        val session = FakeVaultSession(stagedBytes = stagedBytes)
        // A partial write: the primary ends up matching neither baseline nor
        // expected-new, i.e. exactly the state a restore would be offered for.
        val corrupted = stagedBytes + "-partial".toByteArray()
        io.writeTransform = { corrupted }
        val ownership = MutationOwnership()
        val token = ownership.begin()!!
        val save = startSave(io, recovery, session, parkAfterMarker = false)
        save.awaitParked()
        val pin = Sha256.hex(corrupted)

        assertTrue(ownership.reopenBlocked)
        val writesWhileBlocked = io.writes.size
        val restoreResult =
            if (ownership.reopenBlocked) null else RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)
        assertNull(restoreResult)
        assertEquals(writesWhileBlocked, io.writes.size)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(corrupted))
        assertNotNull(recovery.readMarker(vaultUri))

        save.finish()
        assertEquals(SaveOutcome.WriteFailed, save.outcome)
        ownership.endIfOwned(token)
        assertFalse(ownership.reopenBlocked)
        io.writeTransform = null

        val restored =
            if (ownership.reopenBlocked) null else RecoverySnapshotRestorer(io, recovery).restore(vaultUri, pin)
        assertEquals(RestoreOutcome.Success, restored)
        assertTrue(io.contentOf(vaultUri)!!.contentEquals(originalBytes))
        assertNull(recovery.readMarker(vaultUri))
    }

    @Test
    fun ownership_slot_is_single_and_only_the_current_token_releases_it() {
        val ownership = MutationOwnership()
        assertFalse(ownership.reopenBlocked)

        val first = ownership.begin()!!
        assertTrue(ownership.reopenBlocked)
        assertNull("a second mutation must not start", ownership.begin())

        // A completion presenting any other token must not release the slot.
        ownership.endIfOwned(first + 1)
        assertTrue(ownership.reopenBlocked)

        ownership.endIfOwned(first)
        assertFalse(ownership.reopenBlocked)

        val second = ownership.begin()!!
        assertNotEquals("tokens are never reused", first, second)
        // The older, already-released token cannot release the newer owner.
        ownership.endIfOwned(first)
        assertTrue(ownership.reopenBlocked)
    }
}
