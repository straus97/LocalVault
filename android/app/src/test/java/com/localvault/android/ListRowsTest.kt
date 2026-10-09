package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.EntrySummary

/**
 * Pins the pure logic behind the virtualized, site-grouped LIST screen: the
 * row model (site group / profile child / standalone entry), grouping order,
 * filter-before-group, the entry-vs-row count distinction, expansion state,
 * the empty-state decision, per-row display content used when a recycled row
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
        siteKey: String? = null,
    ) = EntrySummary(
        id = id,
        title = title,
        profileName = profileName,
        url = url,
        username = username,
        categoryId = categoryId,
        siteKey = siteKey,
    )

    private val none: Set<String> = emptySet()

    /** Compact, order-sensitive description: `S:key(n)` / `S+:key(n)` group, `C:id` child, `E:id` standalone. */
    private fun shape(rows: List<ListRow>): List<String> =
        rows.map {
            when (it) {
                is ListRow.SiteGroupRow -> (if (it.expanded) "S+:" else "S:") + it.siteKey + "(" + it.profileCount + ")"
                is ListRow.ProfileChildRow -> "C:" + it.entryId
                is ListRow.EntryRow -> "E:" + it.entryId
            }
        }

    // ---- row model ----

    @Test
    fun zeroEntriesGiveZeroRowsAndZeroCounts() {
        val g = ListRows.group(emptyList(), none)
        assertTrue(g.rows.isEmpty())
        assertEquals(0, g.visibleEntryCount)
        assertEquals(0, g.siteGroupCount)
        assertEquals(0, g.expandedSiteGroupCount)
    }

    @Test
    fun oneParseableSiteIsOneCollapsedSiteGroup() {
        val g = ListRows.group(listOf(entry("a", siteKey = "x.example")), none)
        assertEquals(listOf("S:x.example(1)"), shape(g.rows))
        assertEquals(1, g.visibleEntryCount)
        assertEquals(1, g.siteGroupCount)
    }

    @Test
    fun severalEntriesOfOneSiteAreOneSiteGroup() {
        val entries = listOf("1", "2", "3").map { entry(it, siteKey = "github.com") }
        val g = ListRows.group(entries, none)
        assertEquals(listOf("S:github.com(3)"), shape(g.rows))
        assertEquals(3, g.visibleEntryCount)
        assertEquals(1, g.siteGroupCount)
    }

    @Test
    fun expandedSiteShowsItsChildrenImmediatelyBelowTheGroup() {
        val entries = listOf("1", "2", "3").map { entry(it, siteKey = "github.com") }
        val g = ListRows.group(entries, setOf("github.com"))
        assertEquals(listOf("S+:github.com(3)", "C:1", "C:2", "C:3"), shape(g.rows))
        assertEquals(1, g.expandedSiteGroupCount)
        assertEquals(3, g.visibleEntryCount)
    }

    @Test
    fun childOrderFollowsTheVisibleEntryOrderEvenWhenNotSorted() {
        val entries = listOf("z", "m", "a").map { entry(it, siteKey = "s.example") }
        val g = ListRows.group(entries, setOf("s.example"))
        assertEquals(listOf("S+:s.example(3)", "C:z", "C:m", "C:a"), shape(g.rows))
    }

    @Test
    fun differentSitesAreSeparateGroupsInFirstAppearanceOrder() {
        val entries =
            listOf(
                entry("1", siteKey = "zeta.example"),
                entry("2", siteKey = "alpha.example"),
                entry("3", siteKey = "zeta.example"),
                entry("4", siteKey = "mid.example"),
                entry("5", siteKey = "alpha.example"),
            )
        val g = ListRows.group(entries, none)
        // Not alphabetical: zeta, alpha, mid by first appearance.
        assertEquals(listOf("S:zeta.example(2)", "S:alpha.example(2)", "S:mid.example(1)"), shape(g.rows))
        assertEquals(5, g.visibleEntryCount)
        assertEquals(3, g.siteGroupCount)
    }

    @Test
    fun siblingsAreGatheredUnderTheFirstAppearanceNotTheirOwnPosition() {
        val entries =
            listOf(
                entry("1", siteKey = "a.example"),
                entry("2", siteKey = "b.example"),
                entry("3", siteKey = "a.example"),
            )
        val g = ListRows.group(entries, setOf("a.example", "b.example"))
        assertEquals(listOf("S+:a.example(2)", "C:1", "C:3", "S+:b.example(1)", "C:2"), shape(g.rows))
    }

    @Test
    fun ungroupableEntriesStayStandaloneEntryRows() {
        val a = entry("a", siteKey = null)
        val b = entry("b", siteKey = "")
        val c = entry("c", siteKey = "   ")
        val g = ListRows.group(listOf(a, b, c), none)
        assertEquals(listOf("E:a", "E:b", "E:c"), shape(g.rows))
        assertSame(a, (g.rows[0] as ListRow.EntryRow).entry)
        assertEquals(0, g.siteGroupCount)
        assertEquals(3, g.visibleEntryCount)
    }

    @Test
    fun mixedGroupedAndUngroupedKeepNaturalOrder() {
        val entries =
            listOf(
                entry("1", siteKey = null),
                entry("2", siteKey = "a.example"),
                entry("3", siteKey = null),
                entry("4", siteKey = "a.example"),
                entry("5", siteKey = "b.example"),
                entry("6", siteKey = null),
            )
        val collapsed = ListRows.group(entries, none)
        assertEquals(listOf("E:1", "S:a.example(2)", "E:3", "S:b.example(1)", "E:6"), shape(collapsed.rows))

        val expanded = ListRows.group(entries, setOf("a.example"))
        assertEquals(
            listOf("E:1", "S+:a.example(2)", "C:2", "C:4", "E:3", "S:b.example(1)", "E:6"),
            shape(expanded.rows),
        )
        assertEquals(6, expanded.visibleEntryCount)
    }

    @Test
    fun aSiteWithOneVisibleEntryIsStillASiteGroupNotAStandaloneRow() {
        val g = ListRows.group(listOf(entry("only", siteKey = "solo.example")), none)
        assertTrue(g.rows.single() is ListRow.SiteGroupRow)
    }

    // ---- filter before group ----

    @Test
    fun buildFiltersBeforeGrouping() {
        val entries =
            listOf(
                entry("1", title = "Mail", categoryId = "c1", siteKey = "a.example"),
                entry("2", title = "Bank", categoryId = "c1", siteKey = "a.example"),
                entry("3", title = "Mailbox", categoryId = "c2", siteKey = "b.example"),
                entry("4", title = "Mail", categoryId = null, siteKey = null),
            )
        val all = setOf("a.example", "b.example")

        assertEquals(
            listOf("S+:a.example(1)", "C:1", "S+:b.example(1)", "C:3", "E:4"),
            shape(ListRows.build(entries, CategoryFilter.All, "mail", all).rows),
        )
        assertEquals(
            listOf("S+:a.example(1)", "C:1"),
            shape(ListRows.build(entries, CategoryFilter.Category("c1"), "mail", all).rows),
        )
        assertEquals(
            listOf("E:4"),
            shape(ListRows.build(entries, CategoryFilter.Uncategorized, "mail", all).rows),
        )
        assertTrue(ListRows.build(entries, CategoryFilter.All, "zzz", all).rows.isEmpty())
    }

    @Test
    fun categoryFilteringIsPerEntryNotPerSite() {
        val entries =
            listOf(
                entry("1", categoryId = "work", siteKey = "s.example"),
                entry("2", categoryId = "home", siteKey = "s.example"),
                entry("3", categoryId = "work", siteKey = "s.example"),
            )
        val work = ListRows.build(entries, CategoryFilter.Category("work"), "", setOf("s.example"))
        assertEquals(listOf("S+:s.example(2)", "C:1", "C:3"), shape(work.rows))
        val home = ListRows.build(entries, CategoryFilter.Category("home"), "", setOf("s.example"))
        assertEquals(listOf("S+:s.example(1)", "C:2"), shape(home.rows))
    }

    @Test
    fun searchMatchingOneChildDoesNotLeakUnmatchedSiblings() {
        val entries =
            listOf(
                entry("1", title = "Personal", username = "pat", siteKey = "s.example"),
                entry("2", title = "Work", username = "wendy", siteKey = "s.example"),
                entry("3", title = "Family", username = "fred", siteKey = "s.example"),
            )
        val g = ListRows.build(entries, CategoryFilter.All, "wendy", setOf("s.example"))
        assertEquals(listOf("S+:s.example(1)", "C:2"), shape(g.rows))
        assertEquals(1, g.visibleEntryCount)
    }

    @Test
    fun buildEqualsFilterThenGroup() {
        val entries =
            (0 until 60).map {
                entry("e$it", title = if (it % 3 == 0) "match $it" else "other $it", siteKey = "site${it % 7}.example")
            }
        val expanded = setOf("site1.example", "site4.example")
        val expected = ListRows.group(EntryListFilter.visible(entries, CategoryFilter.All, "match"), expanded)
        val actual = ListRows.build(entries, CategoryFilter.All, "match", expanded)
        assertEquals(shape(expected.rows), shape(actual.rows))
        assertEquals(expected.visibleEntryCount, actual.visibleEntryCount)
    }

    // ---- counts ----

    @Test
    fun visibleEntryCountIsTheEntryCountNotTheRowCount() {
        val entries = (1..6).map { entry("$it", siteKey = if (it <= 4) "a.example" else "b.example") }

        val collapsed = ListRows.group(entries, none)
        assertEquals(2, collapsed.rows.size)
        assertEquals(6, collapsed.visibleEntryCount)

        val expanded = ListRows.group(entries, setOf("a.example"))
        assertEquals(2 + 4, expanded.rows.size)
        assertEquals(6, expanded.visibleEntryCount)
    }

    @Test
    fun diagnosticCountsDescribeGroupingAndIgnoreStaleExpansionKeys() {
        val entries =
            listOf(
                entry("1", siteKey = "a.example"),
                entry("2", siteKey = "a.example"),
                entry("3", siteKey = "b.example"),
                entry("4", siteKey = null),
            )
        val g = ListRows.group(entries, setOf("b.example", "gone.example"))
        assertEquals(4, g.visibleEntryCount)
        assertEquals(2, g.siteGroupCount)
        assertEquals(1, g.expandedSiteGroupCount) // "gone.example" matches nothing visible
        assertEquals(listOf("S:a.example(2)", "S+:b.example(1)", "C:3", "E:4"), shape(g.rows))
    }

    // ---- identity ----

    @Test
    fun duplicateTitlesDoNotMergeEntries() {
        val entries =
            listOf(
                entry("a", title = "Same", siteKey = "s.example"),
                entry("b", title = "Same", siteKey = "s.example"),
                entry("c", title = "Same", siteKey = null),
                entry("d", title = "Same", siteKey = null),
            )
        val g = ListRows.group(entries, setOf("s.example"))
        assertEquals(listOf("S+:s.example(2)", "C:a", "C:b", "E:c", "E:d"), shape(g.rows))
    }

    @Test
    fun multipleProfilesSharingAUrlRemainDistinctChildrenWithTheirOwnIds() {
        val entries =
            listOf(
                entry("1", url = "https://github.com", profileName = "work", siteKey = "github.com"),
                entry("2", url = "https://github.com", profileName = "personal", siteKey = "github.com"),
                entry("3", url = "https://github.com", siteKey = "github.com"),
            )
        val g = ListRows.group(entries, setOf("github.com"))
        val children = g.rows.filterIsInstance<ListRow.ProfileChildRow>()
        assertEquals(listOf("1", "2", "3"), children.map { it.entryId })
        assertTrue(children.all { it.siteKey == "github.com" })
        assertEquals(3, (g.rows[0] as ListRow.SiteGroupRow).profileCount)
    }

    @Test
    fun childAndStandaloneRowsCarryTheirOwnEntryForOpeningDetail() {
        val child = entry("kid", siteKey = "s.example")
        val loner = entry("loner", siteKey = null)
        val g = ListRows.group(listOf(child, loner), setOf("s.example"))
        assertSame(child, (g.rows[1] as ListRow.ProfileChildRow).entry)
        assertSame(loner, (g.rows[2] as ListRow.EntryRow).entry)
    }

    @Test
    fun manyEntriesKeepStoredOrderAsStandaloneRowsWhenUngroupable() {
        val entries = (0 until 500).map { entry("id-${499 - it}") } // deliberately not sorted
        val g = ListRows.group(entries, none)
        assertEquals(entries.map { "E:${it.id}" }, shape(g.rows))
    }

    @Test
    fun groupingALargeListIsLinearAndCorrect() {
        val entries = (0 until 50_000).map { entry("id-$it", siteKey = "site${it % 1000}.example") }
        val g = ListRows.group(entries, none)
        assertEquals(1000, g.rows.size)
        assertEquals(50_000, g.visibleEntryCount)
        assertEquals(1000, g.siteGroupCount)
        assertTrue(g.rows.all { (it as ListRow.SiteGroupRow).profileCount == 50 })
    }

    // ---- view types ----

    @Test
    fun everyRowViewTypeIsInsideTheDeclaredRange() {
        val entries =
            listOf(
                entry("1", siteKey = "a.example"),
                entry("2", siteKey = "a.example"),
                entry("3", siteKey = null),
            )
        val rows = ListRows.group(entries, setOf("a.example")).rows
        assertTrue(rows.all { it.viewType in 0 until ListRow.VIEW_TYPE_COUNT })
        assertEquals(
            setOf(ListRow.VIEW_TYPE_ENTRY, ListRow.VIEW_TYPE_SITE_GROUP, ListRow.VIEW_TYPE_PROFILE_CHILD),
            rows.map { it.viewType }.toSet(),
        )
        assertEquals(3, ListRow.VIEW_TYPE_COUNT)
    }

    // ---- expansion state ----

    @Test
    fun expansionStartsCollapsedAndTogglesBySiteKey() {
        val expanded = ExpandedSites()
        assertFalse(expanded.isExpanded("a.example"))

        assertTrue(expanded.toggle("a.example"))
        assertTrue(expanded.isExpanded("a.example"))
        assertFalse(expanded.isExpanded("b.example"))

        assertFalse(expanded.toggle("a.example"))
        assertFalse(expanded.isExpanded("a.example"))
    }

    @Test
    fun expansionIsKeyedBySiteKeyNotByRowPosition() {
        val expanded = ExpandedSites()
        expanded.toggle("b.example")

        val before = listOf(entry("1", siteKey = "a.example"), entry("2", siteKey = "b.example"))
        assertEquals(
            listOf("S:a.example(1)", "S+:b.example(1)", "C:2"),
            shape(ListRows.group(before, expanded.keysView()).rows),
        )

        // b.example moves to the top of the list; it is still the expanded one.
        val after = listOf(entry("2", siteKey = "b.example"), entry("1", siteKey = "a.example"))
        assertEquals(
            listOf("S+:b.example(1)", "C:2", "S:a.example(1)"),
            shape(ListRows.group(after, expanded.keysView()).rows),
        )
    }

    @Test
    fun expansionSurvivesAFilterThatTemporarilyHidesTheSite() {
        val expanded = ExpandedSites()
        expanded.toggle("a.example")
        val entries = listOf(entry("1", title = "Alpha", siteKey = "a.example"), entry("2", title = "Beta", siteKey = "b.example"))

        val filtered = ListRows.build(entries, CategoryFilter.All, "beta", expanded.keysView())
        assertEquals(listOf("S:b.example(1)"), shape(filtered.rows)) // stale key harmless
        assertEquals(0, filtered.expandedSiteGroupCount)

        val restored = ListRows.build(entries, CategoryFilter.All, "", expanded.keysView())
        assertEquals(listOf("S+:a.example(1)", "C:1", "S:b.example(1)"), shape(restored.rows))
    }

    @Test
    fun clearingExpansionCollapsesEverything() {
        val expanded = ExpandedSites()
        expanded.toggle("a.example")
        expanded.toggle("b.example")
        expanded.clear()
        assertFalse(expanded.isExpanded("a.example"))
        assertFalse(expanded.isExpanded("b.example"))
        assertTrue(expanded.keysView().isEmpty())

        val entries = listOf(entry("1", siteKey = "a.example"))
        assertEquals(listOf("S:a.example(1)"), shape(ListRows.group(entries, expanded.keysView()).rows))
    }

    // ---- empty state (the former renderRows branches; visible ENTRIES, not rows) ----

    @Test
    fun emptyStateNoEntriesWinsOverEverything() {
        assertEquals(ListEmptyState.NO_ENTRIES, ListEmptyState.resolve(0, 0, "", CategoryFilter.All))
        assertEquals(ListEmptyState.NO_ENTRIES, ListEmptyState.resolve(0, 0, "x", CategoryFilter.Uncategorized))
    }

    @Test
    fun emptyStateNoneWhenVisibleEntriesExist() {
        assertEquals(ListEmptyState.NONE, ListEmptyState.resolve(5, 2, "x", CategoryFilter.Category("c")))
    }

    @Test
    fun emptyStateCategoryOnlyFilterWithNoVisibleEntries() {
        assertEquals(ListEmptyState.CATEGORY_EMPTY, ListEmptyState.resolve(5, 0, "", CategoryFilter.Category("c")))
        assertEquals(ListEmptyState.CATEGORY_EMPTY, ListEmptyState.resolve(5, 0, "", CategoryFilter.Uncategorized))
    }

    @Test
    fun emptyStateNoResultsWhenQueryPresentOrCategoryAll() {
        assertEquals(ListEmptyState.NO_RESULTS, ListEmptyState.resolve(5, 0, "x", CategoryFilter.All))
        assertEquals(ListEmptyState.NO_RESULTS, ListEmptyState.resolve(5, 0, "x", CategoryFilter.Category("c")))
    }

    @Test
    fun emptyGroupedListAfterFilteringReflectsZeroVisibleEntries() {
        val entries = listOf(entry("1", title = "Alpha", siteKey = "a.example"))
        val g = ListRows.build(entries, CategoryFilter.All, "zzz", none)
        assertTrue(g.rows.isEmpty())
        assertEquals(
            ListEmptyState.NO_RESULTS,
            ListEmptyState.resolve(entries.size, g.visibleEntryCount, "zzz", CategoryFilter.All),
        )
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

    @Test
    fun profileChildContentShowsTitleUsernameAndProfileButNotTheUrl() {
        val c = ProfileChildContent.from(entry("a", title = "T", username = "bob", url = "https://x.example", profileName = "Work"))
        assertEquals("T", c.title)
        assertEquals("bob", c.username)
        assertEquals("Work", c.profileName)
    }

    @Test
    fun profileChildContentOmitsBlankPartsAndHasNoCarryOver() {
        val full = ProfileChildContent.from(entry("a", title = "A", username = "u", profileName = "p"))
        val bare = ProfileChildContent.from(entry("b", title = "B", username = " ", profileName = ""))
        assertEquals("u", full.username)
        assertEquals("p", full.profileName)
        assertEquals("B", bare.title)
        assertNull(bare.username)
        assertNull(bare.profileName)
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
