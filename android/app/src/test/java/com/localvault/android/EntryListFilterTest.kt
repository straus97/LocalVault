package com.localvault.android

import com.localvault.android.bench.SyntheticEntries
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.EntrySummary

/**
 * Pins the Android list's category + search semantics. The logic was moved
 * out of `MainActivity` verbatim (testability refactor, not a behavior
 * change); these tests exist so any later change -- virtualization, site
 * grouping -- is compared against the behavior that shipped.
 */
class EntryListFilterTest {

    private fun entry(
        title: String = "",
        username: String = "",
        url: String = "",
        profileName: String = "",
        categoryId: String? = null,
        id: String = "id-$title-$username-$url-$profileName",
    ) = EntrySummary(
        id = id,
        title = title,
        profileName = profileName,
        url = url,
        username = username,
        categoryId = categoryId,
    )

    // ---- reference: the exact former MainActivity code, copied verbatim ----

    private fun referenceMatchesCategory(entry: EntrySummary, categoryFilter: CategoryFilter): Boolean =
        when (val filter = categoryFilter) {
            CategoryFilter.All -> true
            CategoryFilter.Uncategorized -> entry.categoryId == null
            is CategoryFilter.Category -> entry.categoryId == filter.id
        }

    private fun referenceMatchesQuery(entry: EntrySummary, query: String): Boolean =
        entry.title.contains(query, ignoreCase = true) ||
            entry.username.contains(query, ignoreCase = true) ||
            entry.url.contains(query, ignoreCase = true) ||
            entry.profileName.contains(query, ignoreCase = true)

    private fun referenceVisible(
        entries: List<EntrySummary>,
        categoryFilter: CategoryFilter,
        query: String,
    ): List<EntrySummary> =
        entries.filter { referenceMatchesCategory(it, categoryFilter) && (query.isEmpty() || referenceMatchesQuery(it, query)) }

    // ---- query semantics ----

    @Test
    fun query_matches_each_of_the_four_fields() {
        assertTrue(EntryListFilter.matchesQuery(entry(title = "Alpha"), "alp"))
        assertTrue(EntryListFilter.matchesQuery(entry(username = "bob@x"), "bob"))
        assertTrue(EntryListFilter.matchesQuery(entry(url = "https://site.example"), "site"))
        assertTrue(EntryListFilter.matchesQuery(entry(profileName = "Work"), "wor"))
    }

    @Test
    fun query_is_case_insensitive_both_directions() {
        assertTrue(EntryListFilter.matchesQuery(entry(title = "GitHub"), "GITHUB"))
        assertTrue(EntryListFilter.matchesQuery(entry(title = "github"), "GitHub"))
    }

    @Test
    fun query_is_case_insensitive_for_cyrillic() {
        assertTrue(EntryListFilter.matchesQuery(entry(title = "Почта"), "ПОЧТА"))
        assertTrue(EntryListFilter.matchesQuery(entry(title = "почта"), "Поч"))
    }

    @Test
    fun query_is_a_substring_match_not_a_prefix_match() {
        assertTrue(EntryListFilter.matchesQuery(entry(title = "My Bank Account"), "bank"))
    }

    @Test
    fun query_does_not_match_when_absent_from_all_fields() {
        assertFalse(EntryListFilter.matchesQuery(entry(title = "a", username = "b", url = "c", profileName = "d"), "zz"))
    }

    @Test
    fun query_is_not_trimmed_or_normalized_by_the_helper() {
        // MainActivity trims the raw search text itself; the helper must not.
        assertFalse(EntryListFilter.matchesQuery(entry(title = "abc"), " abc"))
        assertTrue(EntryListFilter.matchesQuery(entry(title = "a bc"), "a b"))
    }

    @Test
    fun empty_query_matches_everything_through_visible() {
        val entries = listOf(entry(title = "one"), entry(title = "two"))
        assertEquals(entries, EntryListFilter.visible(entries, CategoryFilter.All, ""))
    }

    @Test
    fun empty_string_always_matches_via_contains() {
        // Documents why `visible` short-circuits on an empty query: contains("") is true.
        assertTrue(EntryListFilter.matchesQuery(entry(title = "x"), ""))
    }

    // ---- category semantics ----

    @Test
    fun category_all_accepts_categorized_and_uncategorized() {
        assertTrue(EntryListFilter.matchesCategory(entry(categoryId = "c1"), CategoryFilter.All))
        assertTrue(EntryListFilter.matchesCategory(entry(categoryId = null), CategoryFilter.All))
    }

    @Test
    fun category_uncategorized_accepts_only_null_category() {
        assertTrue(EntryListFilter.matchesCategory(entry(categoryId = null), CategoryFilter.Uncategorized))
        assertFalse(EntryListFilter.matchesCategory(entry(categoryId = "c1"), CategoryFilter.Uncategorized))
    }

    @Test
    fun category_specific_accepts_only_exact_id() {
        assertTrue(EntryListFilter.matchesCategory(entry(categoryId = "c1"), CategoryFilter.Category("c1")))
        assertFalse(EntryListFilter.matchesCategory(entry(categoryId = "c2"), CategoryFilter.Category("c1")))
        assertFalse(EntryListFilter.matchesCategory(entry(categoryId = null), CategoryFilter.Category("c1")))
        assertFalse(EntryListFilter.matchesCategory(entry(categoryId = "C1"), CategoryFilter.Category("c1")))
    }

    @Test
    fun unknown_category_id_yields_empty_list() {
        val entries = listOf(entry(title = "a", categoryId = "c1"), entry(title = "b"))
        assertTrue(EntryListFilter.visible(entries, CategoryFilter.Category("nope"), "").isEmpty())
    }

    // ---- combined behavior ----

    @Test
    fun visible_combines_category_and_query_with_and() {
        val a = entry(title = "Mail A", categoryId = "c1")
        val b = entry(title = "Mail B", categoryId = "c2")
        val c = entry(title = "Bank", categoryId = "c1")
        val entries = listOf(a, b, c)
        assertEquals(listOf(a), EntryListFilter.visible(entries, CategoryFilter.Category("c1"), "mail"))
    }

    @Test
    fun visible_preserves_stored_order() {
        val first = entry(title = "zeta match")
        val second = entry(title = "alpha match")
        val third = entry(title = "mu match")
        assertEquals(
            listOf(first, second, third),
            EntryListFilter.visible(listOf(first, second, third), CategoryFilter.All, "match"),
        )
    }

    @Test
    fun visible_of_empty_input_is_empty() {
        assertTrue(EntryListFilter.visible(emptyList(), CategoryFilter.All, "x").isEmpty())
    }

    // ---- differential check against the verbatim former implementation ----

    @Test
    fun matches_the_former_implementation_on_synthetic_data_for_every_scenario() {
        val entries = SyntheticEntries.generate(2_000)
        val filters =
            listOf(
                CategoryFilter.All,
                CategoryFilter.Uncategorized,
                CategoryFilter.Category(SyntheticEntries.categoryId(0)),
                CategoryFilter.Category(SyntheticEntries.categoryId(3)),
                CategoryFilter.Category("not-a-category"),
            )
        val queries =
            listOf("", "a", "A", "mail", "MAIL", "user00001", "example", "https://", "zzqqxx-no-match", ".", "@", "Account")
        for (filter in filters) {
            for (query in queries) {
                val expected = referenceVisible(entries, filter, query)
                val actual = EntryListFilter.visible(entries, filter, query)
                assertEquals("filter=$filter query='$query'", expected, actual)
            }
        }
    }
}
