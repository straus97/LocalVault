package com.localvault.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import uniffi.localvault_android_bridge.EntryInput
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

/**
 * Exercises the real [FileRecoverySnapshotStore] (not
 * [FakeRecoverySnapshotStore]) against a real directory. Its read/clear logic
 * -- absent vs. unreadable vs. malformed, and verifying that a delete took
 * effect -- is production code running unmodified; only two things are
 * substituted, both because the Android framework classes are stubbed in
 * plain JVM tests: `android.util.AtomicFile` by [TestAtomicBlob] (same
 * documented semantics, real files) and the `org.json` marker codec by
 * [TestMarkerCodec]. Not covered here, and still device-only: the real
 * `AtomicFile` implementation across API levels and the real `org.json`
 * decode of a damaged file.
 *
 * Fixtures live under the module's `build/` directory (never `%TEMP%`) and
 * contain only synthetic bytes.
 */
class FileRecoverySnapshotStoreTest {

    @get:Rule
    val folder = TemporaryFolder(File("build/recovery-store-test").apply { mkdirs() }.absoluteFile)

    private val uri = "content://provider/document/synthetic-vault"
    private val baselineBytes = "synthetic-baseline-ciphertext".toByteArray()
    private val newBytes = "synthetic-new-ciphertext".toByteArray()

    private lateinit var directory: File
    private lateinit var store: FileRecoverySnapshotStore

    private var deleteIneffective = false
    private var restoreFromBackupFails = false
    private var readFailure: Throwable? = null

    @Before
    fun setUp() {
        directory = folder.newFolder("vault_recovery")
        store = newStore()
    }

    private fun newStore() =
        FileRecoverySnapshotStore(
            directory,
            { file ->
                TestAtomicBlob(file).also {
                    if (file.name.endsWith(".sidecar.json")) {
                        it.deleteIsIneffective = deleteIneffective
                        it.restoreFromBackupFails = restoreFromBackupFails
                        it.readFailure = readFailure
                    }
                }
            },
            TestMarkerCodec,
        )

    private fun markerFile() = File(directory, "${Sha256.hex(uri.toByteArray())}.sidecar.json")

    private fun backupFile() = File(markerFile().path + ".bak")

    private fun writeMarker() =
        assertTrue(store.writeAndVerify(uri, baselineBytes, Sha256.hex(baselineBytes), Sha256.hex(newBytes), 1_000L))

    // --- readMarker -------------------------------------------------------

    @Test
    fun truly_absent_marker_reads_as_null_and_is_not_unresolved() {
        assertNull(store.readMarker(uri))
        assertFalse(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun valid_marker_is_decoded_and_snapshot_round_trips() {
        writeMarker()

        val marker = store.readMarker(uri)

        assertEquals(RecoveryMarker(uri, Sha256.hex(baselineBytes), Sha256.hex(newBytes), 1_000L), marker)
        assertArrayEquals(baselineBytes, store.readSnapshotBytes(uri))
        assertTrue(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun malformed_marker_is_a_failure_not_null() {
        markerFile().writeText("this is not a marker")

        assertThrows(RecoveryMarkerUnreadableException::class.java) { store.readMarker(uri) }
        assertTrue("uncertain state must read as unresolved", store.hasUnresolvedMarker(uri))
    }

    @Test
    fun empty_marker_file_is_a_failure_not_null() {
        markerFile().writeBytes(ByteArray(0))

        assertThrows(RecoveryMarkerUnreadableException::class.java) { store.readMarker(uri) }
    }

    @Test
    fun marker_that_exists_but_cannot_be_opened_is_a_failure_not_null() {
        // A directory where the marker file should be: it exists, and
        // FileInputStream throws FileNotFoundException for it exactly as it
        // does for a permission-denied file.
        assertTrue(markerFile().mkdirs())

        assertThrows(FileNotFoundException::class.java) { store.readMarker(uri) }
        assertTrue(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun storage_and_security_failures_while_reading_propagate() {
        writeMarker()

        readFailure = IOException("simulated storage failure")
        assertThrows(IOException::class.java) { newStore().readMarker(uri) }

        readFailure = SecurityException("simulated permission failure")
        val store = newStore()
        assertThrows(SecurityException::class.java) { store.readMarker(uri) }
        assertTrue(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun a_recoverable_atomicfile_backup_is_returned_not_reported_missing() {
        writeMarker()
        // Interrupted rewrite: the base file is gone, the backup holds the
        // last complete marker. AtomicFile restores it on read.
        assertTrue(markerFile().renameTo(backupFile()))

        val marker = store.readMarker(uri)

        assertEquals(RecoveryMarker(uri, Sha256.hex(baselineBytes), Sha256.hex(newBytes), 1_000L), marker)
    }

    @Test
    fun a_backup_that_cannot_be_restored_is_a_failure_not_null() {
        writeMarker()
        assertTrue(markerFile().renameTo(backupFile()))
        restoreFromBackupFails = true

        assertThrows(FileNotFoundException::class.java) { newStore().readMarker(uri) }
        assertTrue(backupFile().exists())
    }

    // --- clearMarker ------------------------------------------------------

    @Test
    fun successful_clear_leaves_no_marker_and_keeps_the_snapshot() {
        writeMarker()

        store.clearMarker(uri)

        assertNull(store.readMarker(uri))
        assertFalse(markerFile().exists())
        assertFalse(backupFile().exists())
        assertArrayEquals(baselineBytes, store.readSnapshotBytes(uri))
    }

    @Test
    fun clearing_an_absent_marker_is_safe_and_repeatable() {
        store.clearMarker(uri)
        writeMarker()
        store.clearMarker(uri)
        store.clearMarker(uri)

        assertNull(store.readMarker(uri))
    }

    @Test
    fun clear_also_removes_a_leftover_backup_so_it_cannot_resurrect_the_marker() {
        writeMarker()
        markerFile().copyTo(backupFile())

        store.clearMarker(uri)

        assertFalse(backupFile().exists())
        assertNull(store.readMarker(uri))
    }

    @Test
    fun a_delete_that_silently_does_nothing_is_reported_as_a_failure() {
        writeMarker()
        deleteIneffective = true

        assertThrows(IOException::class.java) { newStore().clearMarker(uri) }

        // The marker really is still live and still decodes.
        deleteIneffective = false
        assertNotNull(newStore().readMarker(uri))
    }

    @Test
    fun a_marker_that_cannot_really_be_deleted_is_reported_as_a_failure() {
        // A non-empty directory at the marker path: File.delete() returns
        // false on every platform, with no exception -- AtomicFile.delete()
        // would swallow that.
        assertTrue(markerFile().mkdirs())
        File(markerFile(), "child").writeText("x")

        assertThrows(IOException::class.java) { store.clearMarker(uri) }
        assertTrue(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun a_backup_that_survives_the_delete_is_reported_as_a_failure() {
        writeMarker()
        // Only the leftover backup remains, and it cannot be removed.
        assertTrue(markerFile().renameTo(backupFile()))
        deleteIneffective = true

        assertThrows(IOException::class.java) { newStore().clearMarker(uri) }
    }

    private fun newFile() = File(markerFile().path + ".new")

    @Test
    fun clear_removes_a_leftover_uncommitted_new_file() {
        writeMarker()
        newFile().writeText("incomplete")

        store.clearMarker(uri)

        assertFalse(newFile().exists())
        assertFalse(markerFile().exists())
        assertNull(store.readMarker(uri))
    }

    @Test
    fun clear_of_an_absent_marker_with_only_a_leftover_new_file_removes_it() {
        newFile().writeText("incomplete")

        store.clearMarker(uri)

        assertFalse(newFile().exists())
    }

    @Test
    fun an_ineffective_delete_that_leaves_only_a_new_file_is_reported_as_a_failure() {
        // Base and .bak are already gone; only the .new artifact survives.
        newFile().writeText("incomplete")
        deleteIneffective = true

        assertThrows(IOException::class.java) { newStore().clearMarker(uri) }
        assertTrue(newFile().exists())
    }

    @Test
    fun a_new_file_that_cannot_really_be_deleted_is_reported_as_a_failure() {
        assertTrue(newFile().mkdirs())
        File(newFile(), "child").writeText("x")

        assertThrows(IOException::class.java) { store.clearMarker(uri) }
    }

    @Test
    fun an_uncommitted_new_file_alone_is_not_a_marker() {
        newFile().writeText("incomplete")

        assertNull(store.readMarker(uri))
        assertFalse(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun an_uncommitted_new_file_does_not_disturb_a_committed_marker() {
        writeMarker()
        newFile().writeText("incomplete")

        assertEquals(RecoveryMarker(uri, Sha256.hex(baselineBytes), Sha256.hex(newBytes), 1_000L), store.readMarker(uri))
    }

    @Test
    fun forget_removes_snapshot_and_marker() {
        writeMarker()

        store.forget(uri)

        assertNull(store.readMarker(uri))
        assertNull(store.readSnapshotBytes(uri))
    }

    // --- consumers, driven by the production store -------------------------

    @Test
    fun pre_open_gate_refuses_to_open_on_a_malformed_marker() {
        markerFile().writeText("garbage")
        var opens = 0

        val result =
            runUnlockPreOpenGate(
                readMarker = { store.readMarker(uri) },
                readCurrentBytes = { newBytes },
                clearMarker = { store.clearMarker(uri) },
                openPrimary = { opens++; it },
            )

        assertTrue(result is UnlockGateResult.RecoveryNeeded<*>)
        assertEquals(0, opens)
        assertTrue("the damaged marker must be left in place", markerFile().exists())
    }

    @Test
    fun pre_open_gate_refuses_to_open_when_an_existing_marker_cannot_be_cleared() {
        writeMarker()
        deleteIneffective = true
        val failingStore = newStore()
        var opens = 0

        val result =
            runUnlockPreOpenGate(
                readMarker = { failingStore.readMarker(uri) },
                readCurrentBytes = { newBytes },
                clearMarker = { failingStore.clearMarker(uri) },
                openPrimary = { opens++; it },
            )

        assertTrue(result is UnlockGateResult.RecoveryNeeded<*>)
        assertEquals(0, opens)
    }

    @Test
    fun pre_open_gate_resolves_and_clears_normally_when_the_store_is_healthy() {
        writeMarker()

        val result =
            runUnlockPreOpenGate(
                readMarker = { store.readMarker(uri) },
                readCurrentBytes = { newBytes },
                clearMarker = { store.clearMarker(uri) },
                openPrimary = { it },
            )

        val opened = result as UnlockGateResult.Opened<ByteArray>
        assertEquals(ReconciliationOutcome.SAVED, opened.reconciliationOutcome)
        assertNull(store.readMarker(uri))
    }

    private fun sampleInput() =
        EntryInput(
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

    @Test
    fun successful_save_with_the_production_store_clears_the_marker() {
        val io = FakeSafDocumentIo(mapOf(uri to baselineBytes))
        val session = FakeVaultSession(stagedBytes = newBytes)

        val outcome = VaultSaveCoordinator(session, io, store, baselineBytes).saveUpdateEntry(uri, "e", sampleInput(), 1L)

        assertEquals(SaveOutcome.Success, outcome)
        assertNull(store.readMarker(uri))
    }

    @Test
    fun coordinator_does_not_report_success_when_the_marker_cannot_be_cleared() {
        val io = FakeSafDocumentIo(mapOf(uri to baselineBytes))
        val session = FakeVaultSession(stagedBytes = newBytes)
        deleteIneffective = true
        val failingStore = newStore()
        val coordinator = VaultSaveCoordinator(session, io, failingStore, baselineBytes)

        assertThrows(IOException::class.java) { coordinator.saveUpdateEntry(uri, "e", sampleInput(), 1L) }

        // The primary write itself was verified and committed, and the marker
        // is honestly still pending.
        assertArrayEquals(newBytes, io.contentOf(uri))
        assertEquals(1, session.commitCount)
        assertTrue(failingStore.hasUnresolvedMarker(uri))

        // The stale baseline refuses a retry rather than re-applying it.
        assertEquals(SaveOutcome.ChangedExternally, coordinator.saveUpdateEntry(uri, "e", sampleInput(), 2L))
        assertEquals(1, io.writes.size)

        // Next unlock reconciles it from disk truth once storage works again.
        deleteIneffective = false
        val healthy = newStore()
        val result =
            runUnlockPreOpenGate(
                readMarker = { healthy.readMarker(uri) },
                readCurrentBytes = { io.readAll(uri) },
                clearMarker = { healthy.clearMarker(uri) },
                openPrimary = { it },
            )
        assertEquals(ReconciliationOutcome.SAVED, (result as UnlockGateResult.Opened<ByteArray>).reconciliationOutcome)
        assertNull(healthy.readMarker(uri))
    }
}
