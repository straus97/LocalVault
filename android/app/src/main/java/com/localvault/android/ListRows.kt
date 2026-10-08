package com.localvault.android

import uniffi.localvault_android_bridge.EntrySummary

/**
 * One logical row of the Android LIST screen's virtualized `ListView`.
 *
 * Today the list is flat: exactly one [EntryRow] per visible [EntrySummary],
 * in stored order. The sealed type and the per-row [viewType] exist so a
 * later site/profile grouping slice can add further row kinds without
 * replacing the list container or the adapter's recycling contract again.
 * No grouping is implemented here.
 *
 * Holds only the non-secret [EntrySummary] values the list already had.
 */
internal sealed class ListRow {

    /** Adapter view type; must be in `0 until VIEW_TYPE_COUNT`. */
    abstract val viewType: Int

    /** One entry row. [entryId] is what a tap opens DETAIL for. */
    class EntryRow(val entry: EntrySummary) : ListRow() {
        val entryId: String get() = entry.id

        override val viewType: Int get() = VIEW_TYPE_ENTRY
    }

    companion object {
        const val VIEW_TYPE_ENTRY = 0
        const val VIEW_TYPE_COUNT = 1
    }
}

internal object ListRows {

    /** Filters first (the unchanged [EntryListFilter]), then builds rows. */
    fun build(entries: List<EntrySummary>, filter: CategoryFilter, query: String): List<ListRow> =
        forVisibleEntries(EntryListFilter.visible(entries, filter, query))

    /** Exactly one [ListRow.EntryRow] per entry, same order, no grouping. */
    fun forVisibleEntries(visible: List<EntrySummary>): List<ListRow> = visible.map { ListRow.EntryRow(it) }
}

/**
 * The non-entry message the LIST screen shows below the count. Moved out of
 * the former `renderRows` unchanged: no entries at all wins, then an empty
 * filtered result is "category empty" only for a category-only filter (blank
 * query, category not All) and "no results" otherwise.
 */
internal enum class ListEmptyState {
    NONE,
    NO_ENTRIES,
    CATEGORY_EMPTY,
    NO_RESULTS,
    ;

    companion object {
        fun resolve(totalEntries: Int, visibleRows: Int, query: String, filter: CategoryFilter): ListEmptyState =
            when {
                totalEntries == 0 -> NO_ENTRIES
                visibleRows > 0 -> NONE
                query.isEmpty() && filter != CategoryFilter.All -> CATEGORY_EMPTY
                else -> NO_RESULTS
            }
    }
}

/**
 * What one entry row displays, with absent optional parts as `null` so a
 * recycled row view can always reset (hide) what a previous entry showed.
 * Same composition rules as the former inline `newEntryRow`.
 */
internal class EntryRowContent(val title: String, val username: String?, val subtitle: String?) {
    companion object {
        fun from(entry: EntrySummary): EntryRowContent {
            val site = listOf(entry.url, entry.profileName).filter { it.isNotBlank() }.joinToString(" · ")
            return EntryRowContent(
                title = entry.title,
                username = entry.username.takeIf { it.isNotBlank() },
                subtitle = site.takeIf { it.isNotEmpty() },
            )
        }
    }
}

/**
 * LIST scroll restoration state, in `ListView` coordinates (position 0 is
 * the screen header): the first visible position and that child's top
 * offset in pixels. Replaces the former pixel `ScrollView` offset.
 */
internal data class ListScrollPosition(val firstPosition: Int, val topOffsetPx: Int) {

    /**
     * This position made safe for a list of [positionCount] positions
     * (header + rows + footer): an out-of-range position falls back to the
     * nearest valid one with no offset, never a stale one.
     */
    fun coercedTo(positionCount: Int): ListScrollPosition =
        when {
            positionCount <= 0 || firstPosition < 0 -> TOP
            firstPosition >= positionCount -> ListScrollPosition(positionCount - 1, 0)
            else -> this
        }

    companion object {
        val TOP = ListScrollPosition(0, 0)
    }
}
