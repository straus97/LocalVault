package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Pins the pure eviction-decision policy fixed by the 1T-B5a post-QA review:
 * an automatically-evicted recent-vault entry (the 5-item cap pushing out
 * its oldest entry) must not be treated like explicit "forget" when a save
 * for it is genuinely unresolved.
 */
class EvictionOutcomeTest {

    @Test
    fun no_unresolved_marker_releases_and_forgets() {
        assertEquals(EvictionOutcome.RELEASE_AND_FORGET, evictionOutcomeFor(hasUnresolvedMarker = false))
    }

    @Test
    fun unresolved_marker_is_kept_untouched() {
        assertEquals(EvictionOutcome.KEEP, evictionOutcomeFor(hasUnresolvedMarker = true))
    }

    @Test
    fun eviction_with_no_unresolved_marker_forgets_recovery_state_for_that_vault() {
        val uri = "content://provider/document/evicted"
        val store = FakeRecoverySnapshotStore()
        store.writeAndVerify(uri, "bytes".toByteArray(), "b", "e", 1L)
        store.clearMarker(uri) // resolved: snapshot survives, marker is gone -- the common case.

        if (evictionOutcomeFor(store.hasUnresolvedMarker(uri)) == EvictionOutcome.RELEASE_AND_FORGET) {
            store.forget(uri)
        }

        assertNull(store.readMarker(uri))
        assertNull(store.readSnapshotBytes(uri))
    }

    @Test
    fun eviction_with_unresolved_marker_keeps_recovery_state_for_that_vault() {
        val uri = "content://provider/document/evicted"
        val store = FakeRecoverySnapshotStore()
        store.writeAndVerify(uri, "bytes".toByteArray(), "baseline", "expectedNew", 1L)

        if (evictionOutcomeFor(store.hasUnresolvedMarker(uri)) == EvictionOutcome.RELEASE_AND_FORGET) {
            store.forget(uri)
        }

        assertEquals("baseline", store.readMarker(uri)?.baselineSha256)
        assertEquals("bytes".toByteArray().toList(), store.readSnapshotBytes(uri)?.toList())
    }

    @Test
    fun eviction_with_neither_marker_nor_snapshot_is_a_safe_no_op() {
        val uri = "content://provider/document/never-saved"
        val store = FakeRecoverySnapshotStore()

        assertFalse(store.hasUnresolvedMarker(uri))
        assertEquals(EvictionOutcome.RELEASE_AND_FORGET, evictionOutcomeFor(store.hasUnresolvedMarker(uri)))

        store.forget(uri) // must not throw despite nothing existing for this uri.

        assertNull(store.readMarker(uri))
        assertNull(store.readSnapshotBytes(uri))
    }
}
