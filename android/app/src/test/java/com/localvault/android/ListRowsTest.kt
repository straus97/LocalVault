package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.EntrySummary

/**
 * Pins the pure logic behind the virtualized LIST screen: the flat row model
 * (exactly one row per visible entry, in stored order, no grouping), the
 * empty-state decision, the per-row display content used when a recycled row
 * is rebound, and scroll-position clamping.
 */
class ListRowsTest {

    private fun entry(
        id: String,
        title: String = "t-$id",
        username: String = "",
        url: String = "",
        profileName: String = "",
        categoryId: String? = null,
    ) = EntrySummary(
        id = id,
        title = title,
        profileName = profileName,
        url = url,
        username = username,
        categoryId = categoryId,
    )

    private fun ids(rows: List<ListRow>): List<String> = rows.map { (it as ListRow.EntryRow).entryId }

    // ---- row model ----

    @Test
    fun zeroEntriesGiveZeroRows() {
        assertTrue(ListRows.forVisibleEntries(emptyList()).isEmpty())
    }

    @Test
    fun oneEntryGivesOneRowCarryingThatEntry() {
        val e = entry("only")
        val rows = ListRows.forVisibleEntries(listOf(e))
        assertEquals(1, rows.size)
        val row = rows[0] as ListRow.EntryRow
        assertEquals("only", row.entryId)
        assertSame(e, row.entry)
    }

    @Test
    fun manyEntriesKeepStoredOrderAndEachRowCarriesItsOwnId() {
        val entries = (0 until 500).map { entry("id-${499 - it}") } // deliberately not sorted
        val rows = ListRows.forVisibleEntries(entries)
        assertEquals(entries.map { it.id }, ids(rows))
    }

    @Test
    fun duplicateTitlesStayDistinctRowsWithTheirOwnIds() {
        val rows = ListRows.forVisibleEntries(listOf(entry("a", title = "Same"), entry("b", title = "Same")))
        assertEquals(listOf("a", "b"), ids(rows))
    }

    @Test
    fun noGroupingEverySameSiteEntryIsItsOwnRow() {
        val entries =
            listOf(
                entry("1", url = "https://github.com", profileName = "work"),
                entry("2", url = "https://github.com", profileName = "personal"),
                entry("3", url = "https://github.com"),
            )
        val rows = ListRows.forVisibleEntries(entries)
        assertEquals(3, rows.size)
        assertTrue(rows.all { it is ListRow.EntryRow })
        assertTrue(rows.all { it.viewType == ListRow.VIEW_TYPE_ENTRY })
    }

    @Test
    fun viewTypesAreWithinTheDeclaredCount() {
        val rows = ListRows.forVisibleEntries(listOf(entry("a")))
        assertTrue(rows.all { it.viewType in 0 until ListRow.VIEW_TYPE_COUNT })
    }

    @Test
    fun buildFiltersBeforeCreatingRows() {
        val entries =
            listOf(
                entry("1", title = "Mail", categoryId = "c1"),
                entry("2", title = "Bank", categoryId = "c1"),
                entry("3", title = "Mailbox", categoryId = "c2"),
                entry("4", title = "Mail", categoryId = null),
            )
        assertEquals(listOf("1", "3", "4"), ids(ListRows.build(entries, CategoryFilter.All, "mail")))
        assertEquals(listOf("1"), ids(ListRows.build(entries, CategoryFilter.Category("c1"), "mail")))
        assertEquals(listOf("4"), ids(ListRows.build(entries, CategoryFilter.Uncategorized, "mail")))
        assertEquals(listOf("1", "2", "3", "4"), ids(ListRows.build(entries, CategoryFilter.All, "")))
        assertTrue(ListRows.build(entries, CategoryFilter.All, "zzz").isEmpty())
    }

    @Test
    fun buildEqualsFilterThenModel() {
        val entries = (0 until 40).map { entry("e$it", title = if (it % 3 == 0) "match $it" else "other $it") }
        val expected = ids(ListRows.forVisibleEntries(EntryListFilter.visible(entries, CategoryFilter.All, "match")))
        assertEquals(expected, ids(ListRows.build(entries, CategoryFilter.All, "match")))
    }

    // ---- empty state (the former renderRows branches) ----

    @Test
    fun emptyStateNoEntriesWinsOverEverything() {
        assertEquals(ListEmptyState.NO_ENTRIES, ListEmptyState.resolve(0, 0, "", CategoryFilter.All))
        assertEquals(ListEmptyState.NO_ENTRIES, ListEmptyState.resolve(0, 0, "x", CategoryFilter.Uncategorized))
    }

    @Test
    fun emptyStateNoneWhenRowsExist() {
        assertEquals(ListEmptyState.NONE, ListEmptyState.resolve(5, 2, "x", CategoryFilter.Category("c")))
    }

    @Test
    fun emptyStateCategoryOnlyFilterWithNoRows() {
        assertEquals(ListEmptyState.CATEGORY_EMPTY, ListEmptyState.resolve(5, 0, "", CategoryFilter.Category("c")))
        assertEquals(ListEmptyState.CATEGORY_EMPTY, ListEmptyState.resolve(5, 0, "", CategoryFilter.Uncategorized))
    }

    @Test
    fun emptyStateNoResultsWhenQueryPresentOrCategoryAll() {
        assertEquals(ListEmptyState.NO_RESULTS, ListEmptyState.resolve(5, 0, "x", CategoryFilter.All))
        assertEquals(ListEmptyState.NO_RESULTS, ListEmptyState.resolve(5, 0, "x", CategoryFilter.Category("c")))
    }

    // ---- row content (what a recycled row is rebound with) ----

    @Test
    fun contentWithAllOptionalPartsComposesSubtitleWithMiddleDot() {
        val c = EntryRowContent.from(entry("a", title = "T", username = "bob", url = "https://x.example", profileName = "Work"))
        assertEquals("T", c.title)
        assertEquals("bob", c.username)
        assertEquals("https://x.example · Work", c.subtitle)
    }

    @Test
    fun contentOmitsAbsentOrBlankOptionalParts() {
        val bare = EntryRowContent.from(entry("a", title = "T"))
        assertEquals("T", bare.title)
        assertNull(bare.username)
        assertNull(bare.subtitle)

        val blank = EntryRowContent.from(entry("a", title = "T", username = "  ", url = " ", profileName = ""))
        assertNull(blank.username)
        assertNull(blank.subtitle)
    }

    @Test
    fun contentSubtitleUsesOnlyThePresentOfUrlAndProfile() {
        assertEquals("https://x.example", EntryRowContent.from(entry("a", url = "https://x.example")).subtitle)
        assertEquals("Work", EntryRowContent.from(entry("a", profileName = "Work")).subtitle)
    }

    @Test
    fun contentIsDerivedPerEntryWithNoCarryOverBetweenRebinds() {
        // The adapter rebinds one row view across entries; each rebind must be a
        // pure function of the new entry (a full row followed by a bare row has
        // no username/subtitle left over).
        val full = EntryRowContent.from(entry("a", title = "A", username = "u", url = "https://a", profileName = "p"))
        val bare = EntryRowContent.from(entry("b", title = "B"))
        assertEquals("u", full.username)
        assertNull(bare.username)
        assertNull(bare.subtitle)
        assertEquals("B", bare.title)
    }

    // ---- scroll position ----

    @Test
    fun scrollPositionInRangeIsKeptAsIs() {
        val p = ListScrollPosition(12, -37)
        assertEquals(p, p.coercedTo(100))
        assertEquals(p, p.coercedTo(13))
    }

    @Test
    fun scrollPositionBeyondTheEndFallsBackToLastPositionWithNoOffset() {
        assertEquals(ListScrollPosition(9, 0), ListScrollPosition(40, -120).coercedTo(10))
    }

    @Test
    fun scrollPositionNegativeOrEmptyListFallsBackToTop() {
        assertEquals(ListScrollPosition.TOP, ListScrollPosition(-1, 5).coercedTo(10))
        assertEquals(ListScrollPosition.TOP, ListScrollPosition(3, 5).coercedTo(0))
    }

    @Test
    fun topIsPositionZeroOffsetZero() {
        assertEquals(ListScrollPosition(0, 0), ListScrollPosition.TOP)
    }
}
