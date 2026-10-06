package com.localvault.android

import uniffi.localvault_android_bridge.EntrySummary

/**
 * Transient UI filter; "uncategorized" is a real state of the model (no category id).
 *
 * Moved verbatim out of [MainActivity] (testability refactor only) so the pure
 * list-filter logic below can be exercised without an Activity.
 */
internal sealed class CategoryFilter {
    object All : CategoryFilter()

    object Uncategorized : CategoryFilter()

    class Category(val id: String) : CategoryFilter()
}

/**
 * The Android list's category + search filter over non-secret [EntrySummary]
 * values. Moved verbatim out of [MainActivity] (testability refactor only,
 * no behavior change): [matchesCategory] and [matchesQuery] are the exact
 * former private Activity members, and [visible] is the exact former inline
 * `entries.filter { ... }` expression from `renderRows`.
 *
 * The caller owns query normalization (`MainActivity` trims the raw search
 * text before calling in); nothing here trims or normalizes.
 */
internal object EntryListFilter {

    fun matchesCategory(entry: EntrySummary, filter: CategoryFilter): Boolean =
        when (filter) {
            CategoryFilter.All -> true
            CategoryFilter.Uncategorized -> entry.categoryId == null
            is CategoryFilter.Category -> entry.categoryId == filter.id
        }

    fun matchesQuery(entry: EntrySummary, query: String): Boolean =
        entry.title.contains(query, ignoreCase = true) ||
            entry.username.contains(query, ignoreCase = true) ||
            entry.url.contains(query, ignoreCase = true) ||
            entry.profileName.contains(query, ignoreCase = true)

    fun visible(entries: List<EntrySummary>, filter: CategoryFilter, query: String): List<EntrySummary> =
        entries.filter { matchesCategory(it, filter) && (query.isEmpty() || matchesQuery(it, query)) }
}
