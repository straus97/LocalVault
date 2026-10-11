package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

/**
 * What the callers of [RecoverySnapshotStore.forget] do with its result: the
 * recent-vault entry and the SAF grant may only go once the recovery files are
 * verifiably gone. Drives the production [forgetThen] and [evictionOutcomeFor]
 * against the real [FileRecoverySnapshotStore] on a real directory (or
 * [FakeRecoverySnapshotStore] for the thrown-error propagation), with a
 * recording history and grant in place of `RecentVaultStore` and
 * `ContentResolver`.
 *
 * Limitation: `MainActivity.forgetVault` and `rememberVault` themselves
 * cannot run in plain JVM tests (Activity, SharedPreferences, ContentResolver,
 * Toast). [forgetVault] and [evictAndForget] below mirror their few lines of
 * wiring around the real production pieces; that wiring, the failure toast and
 * the stale-vault unlock fall-through need device (or instrumented) checks.
 */
class ForgetRecoveryCleanupTest {

    @get:Rule
    val folder = TemporaryFolder(File("build/recovery-store-test").apply { mkdirs() }.absoluteFile)

    private val uri = "content://provider/document/synthetic-vault"
    private val ciphertext = "synthetic-baseline-ciphertext".toByteArray()

    private lateinit var directory: File
    private var snapshotDeleteIneffective = false
    private var markerDeleteIneffective = false

    private val history = mutableListOf<String>()
    private val grants = mutableSetOf<String>()
    private var toasts = 0

    @Before
    fun setUp() {
        directory = folder.newFolder("vault_recovery")
        history += uri
        grants += uri
    }

    private fun newStore() =
        FileRecoverySnapshotStore(
            directory,
            { file ->
                TestAtomicBlob(file).also {
                    if (file.name.endsWith(".sidecar.json")) it.deleteIsIneffective = markerDeleteIneffective
                    if (file.name.endsWith(".snapshot")) it.deleteIsIneffective = snapshotDeleteIneffective
                }
            },
            TestMarkerCodec,
        )

    private fun RecoverySnapshotStore.save() = assertTrue(writeAndVerify(uri, ciphertext, "base", "new", 1L))

    private fun fileCount() = directory.listFiles()!!.size

    /** Mirrors `MainActivity.forgetVault`. */
    private fun forgetVault(
        store: RecoverySnapshotStore,
        ownership: MutationOwnership = MutationOwnership(),
    ): Boolean {
        if (ownership.reopenBlocked) return false
        val forgotten =
            store.forgetThen(uri) {
                history.remove(uri)
                grants.remove(uri)
            }
        if (!forgotten) toasts++
        return forgotten
    }

    /** Mirrors `MainActivity.rememberVault`'s handling of one evicted entry. */
    private fun evictAndForget(store: RecoverySnapshotStore, saveInFlight: Boolean = false) {
        history.remove(uri) // RecentVaultStore.promote has already dropped it.
        if (evictionOutcomeFor(store.hasUnresolvedMarker(uri), saveInFlight) == EvictionOutcome.RELEASE_AND_FORGET) {
            store.forgetThen(uri) { grants.remove(uri) }
        }
    }

    // --- user-triggered forget --------------------------------------------

    @Test
    fun successful_forget_removes_files_history_and_grant() {
        val store = newStore()
        store.save()

        assertTrue(forgetVault(store))

        assertEquals(0, fileCount())
        assertTrue(history.isEmpty())
        assertTrue(grants.isEmpty())
        assertEquals(0, toasts)
    }

    @Test
    fun forget_with_nothing_stored_still_succeeds_and_removes_history_and_grant() {
        val store = newStore()

        assertTrue(forgetVault(store))
        assertTrue(forgetVault(store))

        assertTrue(history.isEmpty())
        assertTrue(grants.isEmpty())
    }

    @Test
    fun failed_marker_deletion_keeps_history_grant_marker_and_snapshot() {
        newStore().save()
        markerDeleteIneffective = true
        val store = newStore()

        assertFalse(forgetVault(store))

        assertEquals(listOf(uri), history)
        assertEquals(setOf(uri), grants)
        assertEquals(1, toasts)
        assertNotNull(store.readMarker(uri))
        assertNotNull(store.readSnapshotBytes(uri))
    }

    @Test
    fun failed_snapshot_deletion_keeps_history_and_grant_and_a_retry_completes() {
        newStore().save()
        snapshotDeleteIneffective = true

        assertFalse(forgetVault(newStore()))
        assertEquals(listOf(uri), history)
        assertEquals(setOf(uri), grants)
        assertNotNull(newStore().readSnapshotBytes(uri))
        // Not a hidden unresolved marker: the marker itself did go.
        assertFalse(newStore().hasUnresolvedMarker(uri))

        snapshotDeleteIneffective = false
        assertTrue(forgetVault(newStore()))
        assertEquals(0, fileCount())
        assertTrue(history.isEmpty())
        assertTrue(grants.isEmpty())
    }

    @Test
    fun a_thrown_failure_is_reported_as_not_forgotten_without_running_the_follow_up() {
        val store = FakeRecoverySnapshotStore()
        store.writeAndVerify(uri, ciphertext, "base", "new", 1L)
        store.forgetException = IOException("simulated")

        assertFalse(forgetVault(store))

        assertEquals(listOf(uri), history)
        assertEquals(setOf(uri), grants)
        assertNotNull(store.readMarker(uri))
    }

    @Test
    fun unexpected_non_io_errors_are_not_swallowed() {
        val store = FakeRecoverySnapshotStore()
        store.forgetException = IllegalStateException("bug")

        try {
            forgetVault(store)
            org.junit.Assert.fail("expected the exception to propagate")
        } catch (expected: IllegalStateException) {
        }

        assertEquals(listOf(uri), history)
        assertEquals(setOf(uri), grants)
    }

    @Test
    fun forget_refused_during_a_save_deletes_nothing() {
        val store = newStore()
        store.save()
        val ownership = MutationOwnership()
        ownership.begin()!!

        assertFalse(forgetVault(store, ownership))

        assertEquals(listOf(uri), history)
        assertEquals(setOf(uri), grants)
        assertNotNull(store.readMarker(uri))
        assertNotNull(store.readSnapshotBytes(uri))
    }

    @Test
    fun forget_does_not_touch_another_vaults_recovery_data() {
        val store = newStore()
        store.save()
        val other = "content://provider/document/other-vault"
        assertTrue(store.writeAndVerify(other, ciphertext, "b2", "n2", 2L))

        assertTrue(forgetVault(store))

        assertEquals("b2", store.readMarker(other)?.baselineSha256)
        assertNotNull(store.readSnapshotBytes(other))
    }

    // --- automatic eviction -----------------------------------------------

    @Test
    fun eviction_of_a_resolved_vault_forgets_files_and_releases_the_grant() {
        val store = newStore()
        store.save()
        store.clearMarker(uri)

        evictAndForget(store)

        assertEquals(0, fileCount())
        assertTrue(grants.isEmpty())
    }

    @Test
    fun eviction_keeps_the_grant_when_the_snapshot_cannot_be_deleted() {
        val store = newStore()
        store.save()
        store.clearMarker(uri)
        snapshotDeleteIneffective = true

        evictAndForget(newStore())

        assertEquals(setOf(uri), grants)
        assertNotNull(newStore().readSnapshotBytes(uri))
    }

    @Test
    fun eviction_with_an_unresolved_marker_keeps_everything() {
        val store = newStore()
        store.save()

        evictAndForget(store)

        assertEquals(setOf(uri), grants)
        assertNotNull(store.readMarker(uri))
        assertNotNull(store.readSnapshotBytes(uri))
    }

    @Test
    fun eviction_during_a_save_keeps_everything() {
        val store = newStore()
        store.save()
        store.clearMarker(uri)

        evictAndForget(store, saveInFlight = true)

        assertEquals(setOf(uri), grants)
        assertNotNull(store.readSnapshotBytes(uri))
    }

    // --- existing save / restore behavior with the production store --------

    @Test
    fun successful_save_then_forget_leaves_a_clean_directory() {
        val store = newStore()
        val io = FakeSafDocumentIo(mapOf(uri to ciphertext))
        val session = FakeVaultSession(stagedBytes = "staged".toByteArray())
        val outcome =
            VaultSaveCoordinator(session, io, store, ciphertext).saveUpdateEntry(
                uri,
                "e",
                uniffi.localvault_android_bridge.EntryInput(
                    title = "t",
                    profileName = "",
                    url = "",
                    username = "u",
                    password = "p",
                    notes = "",
                    categoryId = null,
                    tags = emptyList(),
                    favorite = false,
                ),
                1L,
            )
        assertEquals(SaveOutcome.Success, outcome)
        assertNull(store.readMarker(uri))
        assertNotNull(store.readSnapshotBytes(uri))

        assertTrue(forgetVault(store))

        assertEquals(0, fileCount())
        assertNull(store.readSnapshotBytes(uri))
    }
}
