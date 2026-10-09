package com.localvault.android.bench

import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The benchmark is only comparable before/after a later change (virtualization,
 * grouping) if the synthetic dataset stays byte-identical, so its content is
 * pinned here by checksum.
 */
class SyntheticEntriesTest {

    private fun checksum(count: Int, seed: Long = SyntheticEntries.DEFAULT_SEED): String {
        val digest = MessageDigest.getInstance("SHA-256")
        for (e in SyntheticEntries.generate(count, seed)) {
            digest.update("${e.id}|${e.title}|${e.profileName}|${e.url}|${e.username}|${e.categoryId}\n".toByteArray())
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    @Test
    fun same_seed_gives_identical_data() {
        assertEquals(checksum(1_000), checksum(1_000))
    }

    @Test
    fun different_seed_gives_different_data() {
        assertNotEquals(checksum(1_000), checksum(1_000, seed = 7L))
    }

    @Test
    fun dataset_checksum_is_pinned() {
        // If this fails the dataset changed: old and new benchmark numbers are no longer comparable.
        assertEquals("a12eeb1ae9e222f65a7a98b62d050ae84dda3d0f88e26512266ac96919cf416a", checksum(1_000))
    }

    @Test
    fun site_keys_follow_the_url_and_group_entries() {
        val entries = SyntheticEntries.generate(5_000)
        for (e in entries) {
            if (e.url.isEmpty()) {
                assertEquals(null, e.siteKey)
            } else {
                // host of "https://<host>/..." with one leading "www." removed
                val host = e.url.removePrefix("https://").substringBefore('/').removePrefix("www.")
                assertEquals(host, e.siteKey)
            }
        }
        val keys = entries.mapNotNull { it.siteKey }
        assertTrue(keys.isNotEmpty())
        assertTrue("some sites carry several profiles", keys.size > keys.toSet().size)
    }

    @Test
    fun sizes_are_exact() {
        assertEquals(0, SyntheticEntries.generate(0).size)
        assertEquals(1_000, SyntheticEntries.generate(1_000).size)
        assertEquals(50_000, SyntheticEntries.generate(50_000).size)
    }

    @Test
    fun data_is_clearly_synthetic_and_varied() {
        val entries = SyntheticEntries.generate(5_000)
        assertTrue(entries.all { it.url.isEmpty() || it.url.contains(".example") })
        assertTrue(entries.all { it.username.isEmpty() || it.username.endsWith(".example") || it.username.startsWith("user") })
        assertTrue(entries.any { it.url.isEmpty() })
        assertTrue(entries.any { it.username.isEmpty() })
        assertTrue(entries.any { it.profileName.isNotEmpty() })
        assertTrue(entries.any { it.categoryId == null })
        assertEquals(SyntheticEntries.CATEGORY_COUNT, entries.mapNotNull { it.categoryId }.toSet().size)
        assertEquals(entries.size, entries.map { it.id }.toSet().size)
    }
}
