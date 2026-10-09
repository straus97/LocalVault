package com.localvault.android

import uniffi.localvault_android_bridge.EntrySummary

/**
 * One logical row of the Android LIST screen's virtualized `ListView`.
 *
 * The rows are derived UI state only -- nothing here is persisted, and the
 * site identity is the bridge-provided `EntrySummary.siteKey` (derived by
 * `localvault-core`; Kotlin never normalizes URLs itself):
 *
 * - [SiteGroupRow]: one per distinct site key among the VISIBLE entries;
 * - [ProfileChildRow]: one per visible entry of an EXPANDED site group,
 *   directly below its group row;
 * - [EntryRow]: an entry with no site key (blank/unparseable URL). The only
 *   standalone entry rows.
 *
 * Holds only non-secret [EntrySummary] values.
 */
internal sealed class ListRow {

    /** Adapter view type; must be in `0 until VIEW_TYPE_COUNT`. */
    abstract val viewType: Int

    /** A standalone (ungroupable) entry. [entryId] is what a tap opens DETAIL for. */
    class EntryRow(val entry: EntrySummary) : ListRow() {
        val entryId: String get() = entry.id

        override val viewType: Int get() = VIEW_TYPE_ENTRY
    }

    /** A site with [profileCount] currently visible entries; a tap toggles [siteKey]. */
    class SiteGroupRow(val siteKey: String, val profileCount: Int, val expanded: Boolean) : ListRow() {
        override val viewType: Int get() = VIEW_TYPE_SITE_GROUP
    }

    /** One visible profile/account of the expanded site [siteKey]. */
    class ProfileChildRow(val siteKey: String, val entry: EntrySummary) : ListRow() {
        val entryId: String get() = entry.id

        override val viewType: Int get() = VIEW_TYPE_PROFILE_CHILD
    }

    companion object {
        const val VIEW_TYPE_ENTRY = 0
        const val VIEW_TYPE_SITE_GROUP = 1
        const val VIEW_TYPE_PROFILE_CHILD = 2
        const val VIEW_TYPE_COUNT = 3
    }
}

/**
 * The result of grouping the visible entries. [rows] is what the adapter
 * shows; [visibleEntryCount] is the number of visible [EntrySummary] objects
 * (what the on-screen count means) and is NOT [rows]`.size`.
 */
internal class GroupedList(
    val rows: List<ListRow>,
    val visibleEntryCount: Int,
    val siteGroupCount: Int,
    val expandedSiteGroupCount: Int,
)

/**
 * Which site groups are expanded, keyed by normalized site key. Pure
 * in-memory UI state: default collapsed, never persisted, and cleared whenever
 * the vault session ends or a new one starts. A key that no longer appears in
 * the visible grouping is simply ignored by [ListRows.group].
 */
internal class ExpandedSites {
    private val keys = HashSet<String>()

    fun isExpanded(siteKey: String): Boolean = siteKey in keys

    /** Flips [siteKey]; returns whether it is now expanded. */
    fun toggle(siteKey: String): Boolean = if (keys.remove(siteKey)) false else keys.add(siteKey)

    fun clear() = keys.clear()

    /** Read-only view for [ListRows.group]; do not retain across toggles. */
    fun keysView(): Set<String> = keys
}

internal object ListRows {

    /**
     * The whole pipeline: the unchanged [EntryListFilter] filters ENTRIES
     * first, and only then are the survivors grouped.
     */
    fun build(entries: List<EntrySummary>, filter: CategoryFilter, query: String, expanded: Set<String>): GroupedList =
        group(EntryListFilter.visible(entries, filter, query), expanded)

    /**
     * Groups already-filtered [visible] entries in one order-preserving O(n)
     * pass: a site's top-level position is its first visible appearance,
     * children keep the visible order, and entries without a site key stay
     * standalone at their natural position. Never sorts.
     */
    fun group(visible: List<EntrySummary>, expanded: Set<String>): GroupedList {
        // Top-level slots in first-appearance order: either a site key (group)
        // or a standalone entry.
        val slots = ArrayList<Slot>()
        val bySite = HashMap<String, ArrayList<EntrySummary>>()

        for (entry in visible) {
            val key = entry.siteKey?.takeIf { it.isNotBlank() }
            if (key == null) {
                slots.add(Slot(null, entry))
                continue
            }
            val members = bySite[key]
            if (members == null) {
                bySite[key] = arrayListOf(entry)
                slots.add(Slot(key, null))
            } else {
                members.add(entry)
            }
        }

        val rows = ArrayList<ListRow>(slots.size)
        var expandedCount = 0
        for (slot in slots) {
            val key = slot.siteKey
            if (key == null) {
                rows.add(ListRow.EntryRow(slot.entry!!))
                continue
            }
            val members = bySite.getValue(key)
            val isExpanded = key in expanded
            rows.add(ListRow.SiteGroupRow(key, members.size, isExpanded))
            if (isExpanded) {
                expandedCount++
                for (member in members) rows.add(ListRow.ProfileChildRow(key, member))
            }
        }

        return GroupedList(rows, visible.size, bySite.size, expandedCount)
    }

    private class Slot(val siteKey: String?, val entry: EntrySummary?)
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
        /** [visibleEntries] is the visible ENTRY count, not the adapter row count. */
        fun resolve(totalEntries: Int, visibleEntries: Int, query: String, filter: CategoryFilter): ListEmptyState =
            when {
                totalEntries == 0 -> NO_ENTRIES
                visibleEntries > 0 -> NONE
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
 * What one profile child row displays. The site (hostname) is already shown by
 * the group row above it, so the child omits the URL and shows only what tells
 * profiles of the same site apart: title, username, profile name.
 */
internal class ProfileChildContent(val title: String, val username: String?, val profileName: String?) {
    companion object {
        fun from(entry: EntrySummary): ProfileChildContent =
            ProfileChildContent(
                title = entry.title,
                username = entry.username.takeIf { it.isNotBlank() },
                profileName = entry.profileName.takeIf { it.isNotBlank() },
            )
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
