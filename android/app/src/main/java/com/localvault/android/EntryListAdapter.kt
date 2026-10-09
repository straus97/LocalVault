package com.localvault.android

import android.content.Context
import android.graphics.Typeface
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Recycling adapter for the LIST screen's framework `ListView` (no AndroidX).
 *
 * Only [ListRow]s are held (non-secret [uniffi.localvault_android_bridge.EntrySummary]
 * values); `ListView` materializes and recycles just the visible row views.
 * There are three view types -- standalone entry, site group, profile child --
 * and `ListView` hands `convertView` back only for the same type. Each holder
 * is additionally type-checked before reuse, and every `bind` resets every
 * optional part, the click target and the expanded indicator, so nothing from
 * a previously bound row can leak into a recycled one.
 *
 * Stable IDs are deliberately off: there is no collision-free Long mapping
 * of entry ids / site keys, and the list does not need one.
 */
internal class EntryListAdapter(
    private val context: Context,
    private val onEntryClick: (String) -> Unit,
    private val onSiteClick: (String) -> Unit,
) : BaseAdapter() {

    private var rows: List<ListRow> = emptyList()

    /** Replaces the whole logical dataset; `ListView` rebinds only what it shows. */
    fun submit(newRows: List<ListRow>) {
        rows = newRows
        notifyDataSetChanged()
    }

    override fun getCount(): Int = rows.size

    override fun getItem(position: Int): ListRow = rows[position]

    override fun getItemId(position: Int): Long = position.toLong()

    override fun hasStableIds(): Boolean = false

    override fun getViewTypeCount(): Int = ListRow.VIEW_TYPE_COUNT

    override fun getItemViewType(position: Int): Int = rows[position].viewType

    override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
        return when (val row = rows[position]) {
            is ListRow.EntryRow -> {
                val holder = (convertView?.tag as? EntryRowHolder) ?: EntryRowHolder.create(context, onEntryClick)
                holder.bind(row)
                holder.root
            }

            is ListRow.SiteGroupRow -> {
                val holder = (convertView?.tag as? SiteGroupHolder) ?: SiteGroupHolder.create(context, onSiteClick)
                holder.bind(row)
                holder.root
            }

            is ListRow.ProfileChildRow -> {
                val holder =
                    (convertView?.tag as? ProfileChildHolder) ?: ProfileChildHolder.create(context, onEntryClick)
                holder.bind(row)
                holder.root
            }
        }
    }

    private class RowViews(context: Context) {
        val density = context.resources.displayMetrics.density

        fun dp(value: Int): Int = (value * density).toInt()
    }

    private companion object {
        fun text(context: Context, size: Float, colorRes: Int, bold: Boolean = false): TextView {
            val view = TextView(context)
            view.textSize = size
            view.setTextColor(context.getColor(colorRes))
            if (bold) view.setTypeface(view.typeface, Typeface.BOLD)
            return view
        }

        fun optionalParams(context: Context): LinearLayout.LayoutParams {
            val params =
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                )
            params.topMargin = RowViews(context).dp(2)
            return params
        }

        /**
         * ListView ignores child margins, so the side gutter and the gap above
         * each card live in a wrapper's padding. [startDp] indents child rows.
         */
        fun wrap(context: Context, card: View, startDp: Int): LinearLayout {
            val v = RowViews(context)
            val wrapper = LinearLayout(context)
            wrapper.orientation = LinearLayout.VERTICAL
            wrapper.setPadding(v.dp(startDp), v.dp(8), v.dp(20), 0)
            wrapper.addView(
                card,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT,
                ),
            )
            return wrapper
        }

        fun bindOptional(view: TextView, text: String?) {
            if (text == null) {
                view.text = ""
                view.visibility = View.GONE
            } else {
                view.text = text
                view.visibility = View.VISIBLE
            }
        }
    }

    // ------------------------------------------------ standalone entry row

    private class EntryRowHolder(
        val root: View,
        private val title: TextView,
        private val username: TextView,
        private val subtitle: TextView,
    ) {
        /** The entry the row currently shows; the click target reads this at tap time. */
        var entryId: String? = null
            private set

        fun bind(row: ListRow.EntryRow) {
            val content = EntryRowContent.from(row.entry)
            entryId = row.entryId
            title.text = content.title
            bindOptional(username, content.username)
            bindOptional(subtitle, content.subtitle)
        }

        companion object {
            fun create(context: Context, onEntryClick: (String) -> Unit): EntryRowHolder {
                val v = RowViews(context)

                val title = text(context, 16f, R.color.lv_text, bold = true)
                val username = text(context, 14f, R.color.lv_text_secondary)
                val subtitle = text(context, 13f, R.color.lv_text_tertiary)

                val card = LinearLayout(context)
                card.orientation = LinearLayout.VERTICAL
                card.setPadding(v.dp(16), v.dp(14), v.dp(16), v.dp(14))
                card.background = context.getDrawable(R.drawable.bg_row)
                card.isClickable = true
                card.addView(title)
                card.addView(username, optionalParams(context))
                card.addView(subtitle, optionalParams(context))

                val holder = EntryRowHolder(wrap(context, card, startDp = 20), title, username, subtitle)
                card.setOnClickListener { holder.entryId?.let(onEntryClick) }
                holder.root.tag = holder
                return holder
            }
        }
    }

    // ------------------------------------------------------- site group row

    private class SiteGroupHolder(
        val root: View,
        private val card: View,
        private val site: TextView,
        private val count: TextView,
        private val indicator: TextView,
    ) {
        /** The site key the row currently shows; the click target reads this at tap time. */
        var siteKey: String? = null
            private set

        fun bind(row: ListRow.SiteGroupRow) {
            val resources = root.resources
            val countText = resources.getQuantityString(R.plurals.site_group_profiles, row.profileCount, row.profileCount)
            siteKey = row.siteKey
            site.text = row.siteKey
            count.text = countText
            indicator.text = if (row.expanded) INDICATOR_EXPANDED else INDICATOR_COLLAPSED
            card.contentDescription =
                resources.getString(
                    if (row.expanded) R.string.site_group_expanded_a11y else R.string.site_group_collapsed_a11y,
                    row.siteKey,
                    countText,
                )
        }

        companion object {
            private const val INDICATOR_COLLAPSED = "▸"
            private const val INDICATOR_EXPANDED = "▾"

            fun create(context: Context, onSiteClick: (String) -> Unit): SiteGroupHolder {
                val v = RowViews(context)

                val site = text(context, 16f, R.color.lv_text, bold = true)
                val count = text(context, 13f, R.color.lv_text_secondary)
                val indicator = text(context, 18f, R.color.lv_primary, bold = true)

                val labels = LinearLayout(context)
                labels.orientation = LinearLayout.VERTICAL
                labels.addView(site)
                labels.addView(count, optionalParams(context))

                val card = LinearLayout(context)
                card.orientation = LinearLayout.HORIZONTAL
                card.gravity = Gravity.CENTER_VERTICAL
                card.setPadding(v.dp(16), v.dp(14), v.dp(16), v.dp(14))
                card.background = context.getDrawable(R.drawable.bg_row)
                card.isClickable = true
                card.addView(labels, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
                card.addView(
                    indicator,
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ),
                )
                // The indicator is decoration; the card's contentDescription carries the state.
                indicator.importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO

                val holder = SiteGroupHolder(wrap(context, card, startDp = 20), card, site, count, indicator)
                card.setOnClickListener { holder.siteKey?.let(onSiteClick) }
                holder.root.tag = holder
                return holder
            }
        }
    }

    // ----------------------------------------------------- profile child row

    private class ProfileChildHolder(
        val root: View,
        private val title: TextView,
        private val username: TextView,
        private val profile: TextView,
    ) {
        /** The entry the row currently shows; the click target reads this at tap time. */
        var entryId: String? = null
            private set

        fun bind(row: ListRow.ProfileChildRow) {
            val content = ProfileChildContent.from(row.entry)
            entryId = row.entryId
            title.text = content.title
            bindOptional(username, content.username)
            bindOptional(profile, content.profileName)
        }

        companion object {
            fun create(context: Context, onEntryClick: (String) -> Unit): ProfileChildHolder {
                val v = RowViews(context)

                val title = text(context, 15f, R.color.lv_text, bold = true)
                val username = text(context, 14f, R.color.lv_text_secondary)
                val profile = text(context, 13f, R.color.lv_text_tertiary)

                val card = LinearLayout(context)
                card.orientation = LinearLayout.VERTICAL
                card.setPadding(v.dp(16), v.dp(12), v.dp(16), v.dp(12))
                card.background = context.getDrawable(R.drawable.bg_row)
                card.isClickable = true
                card.addView(title)
                card.addView(username, optionalParams(context))
                card.addView(profile, optionalParams(context))

                // Indented under the group row.
                val holder = ProfileChildHolder(wrap(context, card, startDp = 36), title, username, profile)
                card.setOnClickListener { holder.entryId?.let(onEntryClick) }
                holder.root.tag = holder
                return holder
            }
        }
    }
}
