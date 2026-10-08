package com.localvault.android

import android.content.Context
import android.graphics.Typeface
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
 * Row views are reused through `convertView`; [EntryRowHolder.bind] always
 * resets every optional part and the click target, so nothing from a
 * previously bound entry can leak into a recycled row.
 *
 * Stable IDs are deliberately off: there is no collision-free Long mapping
 * of entry ids, and a flat list does not need one.
 */
internal class EntryListAdapter(
    private val context: Context,
    private val onEntryClick: (String) -> Unit,
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
        }
    }

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

        private fun bindOptional(view: TextView, text: String?) {
            if (text == null) {
                view.text = ""
                view.visibility = View.GONE
            } else {
                view.text = text
                view.visibility = View.VISIBLE
            }
        }

        companion object {
            fun create(context: Context, onEntryClick: (String) -> Unit): EntryRowHolder {
                val density = context.resources.displayMetrics.density

                fun dp(value: Int): Int = (value * density).toInt()

                fun text(size: Float, colorRes: Int, bold: Boolean = false): TextView {
                    val view = TextView(context)
                    view.textSize = size
                    view.setTextColor(context.getColor(colorRes))
                    if (bold) view.setTypeface(view.typeface, Typeface.BOLD)
                    return view
                }

                fun optionalParams(): LinearLayout.LayoutParams {
                    val params =
                        LinearLayout.LayoutParams(
                            LinearLayout.LayoutParams.MATCH_PARENT,
                            LinearLayout.LayoutParams.WRAP_CONTENT,
                        )
                    params.topMargin = dp(2)
                    return params
                }

                val title = text(16f, R.color.lv_text, bold = true)
                val username = text(14f, R.color.lv_text_secondary)
                val subtitle = text(13f, R.color.lv_text_tertiary)

                val card = LinearLayout(context)
                card.orientation = LinearLayout.VERTICAL
                card.setPadding(dp(16), dp(14), dp(16), dp(14))
                card.background = context.getDrawable(R.drawable.bg_row)
                card.isClickable = true
                card.addView(title)
                card.addView(username, optionalParams())
                card.addView(subtitle, optionalParams())

                // ListView ignores child margins, so the 20dp side gutter and
                // the 8dp gap above each card live in a wrapper's padding.
                val wrapper = LinearLayout(context)
                wrapper.orientation = LinearLayout.VERTICAL
                wrapper.setPadding(dp(20), dp(8), dp(20), 0)
                wrapper.addView(
                    card,
                    LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.WRAP_CONTENT,
                    ),
                )

                val holder = EntryRowHolder(wrapper, title, username, subtitle)
                card.setOnClickListener { holder.entryId?.let(onEntryClick) }
                wrapper.tag = holder
                return holder
            }
        }
    }
}
