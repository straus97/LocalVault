package com.localvault.android.proof

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Exercises the [RecoverySnapshotStore] contract that [VaultSaveCoordinator]
 * and [SaveReconciler] rely on, via [FakeRecoverySnapshotStore]. The real
 * `android.util.AtomicFile`-backed [FileRecoverySnapshotStore] cannot be
 * exercised in a plain JVM unit test (AGP stubs `AtomicFile`'s methods to
 * throw without Robolectric, which is deliberately not added here per the
 * accepted review's guidance against overengineering this seam) -- its
 * actual durability is a real-device QA item. This test instead pins the
 * *contract* both implementations must uphold.
 */
class RecoverySnapshotStoreContractTest {

    private val uri = "content://provider/document/vault"

    @Test
    fun write_and_verify_round_trips_snapshot_bytes_and_marker() {
        val store = FakeRecoverySnapshotStore()

        val ok = store.writeAndVerify(uri, "pre-write-ciphertext".toByteArray(), "baseline", "expectedNew", 1_000L)

        assertTrue(ok)
        assertArrayEquals("pre-write-ciphertext".toByteArray(), store.readSnapshotBytes(uri))

        val marker = store.readMarker(uri)
        assertEquals(uri, marker?.vaultUri)
        assertEquals("baseline", marker?.baselineSha256)
        assertEquals("expectedNew", marker?.expectedNewSha256)
        assertEquals(1_000L, marker?.timestampMs)
    }

    @Test
    fun no_marker_or_snapshot_exists_for_an_unknown_vault() {
        val store = FakeRecoverySnapshotStore()

        assertNull(store.readMarker(uri))
        assertNull(store.readSnapshotBytes(uri))
        assertFalse(store.hasUnresolvedMarker(uri))
    }

    @Test
    fun clear_marker_removes_only_the_marker_not_the_snapshot() {
        val store = FakeRecoverySnapshotStore()
        store.writeAndVerify(uri, "bytes".toByteArray(), "b", "e", 1L)

        store.clearMarker(uri)

        assertNull(store.readMarker(uri))
        assertFalse(store.hasUnresolvedMarker(uri))
        // The snapshot is retained -- replaced only by the next successful
        // save's own writeAndVerify, not deleted merely because the marker
        // resolved (accepted review, Revision 3, section 7).
        assertArrayEquals("bytes".toByteArray(), store.readSnapshotBytes(uri))
    }

    @Test
    fun forget_deletes_both_snapshot_and_marker() {
        val store = FakeRecoverySnapshotStore()
        store.writeAndVerify(uri, "bytes".toByteArray(), "b", "e", 1L)

        store.forget(uri)

        assertNull(store.readMarker(uri))
        assertNull(store.readSnapshotBytes(uri))
    }

    @Test
    fun a_failed_write_leaves_no_snapshot_or_marker_behind() {
        val store = FakeRecoverySnapshotStore()
        store.failWrites = true

        val ok = store.writeAndVerify(uri, "bytes".toByteArray(), "b", "e", 1L)

        assertFalse(ok)
        assertNull(store.readMarker(uri))
        assertNull(store.readSnapshotBytes(uri))
    }

    @Test
    fun a_second_write_replaces_rather_than_accumulates() {
        val store = FakeRecoverySnapshotStore()
        store.writeAndVerify(uri, "first".toByteArray(), "b1", "e1", 1L)
        store.writeAndVerify(uri, "second".toByteArray(), "b2", "e2", 2L)

        assertArrayEquals("second".toByteArray(), store.readSnapshotBytes(uri))
        assertEquals("b2", store.readMarker(uri)?.baselineSha256)
    }
}
