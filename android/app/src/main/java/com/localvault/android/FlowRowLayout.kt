package com.localvault.android

import android.content.Context
import android.view.View
import android.view.ViewGroup

/**
 * A row of buttons that wraps onto further lines instead of overflowing.
 *
 * A plain horizontal `LinearLayout` never wraps: when its children's natural
 * widths (long RU labels, platform 88dp Button minimum width, larger font
 * scale) exceed the screen, the trailing children are clipped. Here every
 * child is measured with `AT_MOST(width)` -- so even a single oversized
 * label wraps its own text rather than pushing past the edge -- and children
 * that do not fit on the current line move to the next one.
 *
 * Children added with `endAligned = true` sit against the end edge of their
 * line (used to keep Edit / Delete / Lock on the trailing side as before).
 * Child margins and the layout's own padding are not used; spacing is the
 * constructor's fixed gap.
 */
internal class FlowRowLayout(
    context: Context,
    private val gapPx: Int,
    private val lineGapPx: Int,
) : ViewGroup(context) {

    class LayoutParams(val endAligned: Boolean) : ViewGroup.LayoutParams(WRAP_CONTENT, WRAP_CONTENT)

    fun addAction(view: View, endAligned: Boolean = false) {
        addView(view, LayoutParams(endAligned))
    }

    override fun checkLayoutParams(p: ViewGroup.LayoutParams?): Boolean = p is LayoutParams

    override fun generateDefaultLayoutParams(): ViewGroup.LayoutParams = LayoutParams(false)

    override fun generateLayoutParams(p: ViewGroup.LayoutParams?): ViewGroup.LayoutParams = LayoutParams(false)

    private fun laidOutChildren(): List<View> = (0 until childCount).map { getChildAt(it) }.filter { it.visibility != GONE }

    private fun isEnd(child: View): Boolean = (child.layoutParams as? LayoutParams)?.endAligned == true

    override fun onMeasure(widthMeasureSpec: Int, heightMeasureSpec: Int) {
        val widthMode = MeasureSpec.getMode(widthMeasureSpec)
        val widthSize = MeasureSpec.getSize(widthMeasureSpec)
        val unbounded = widthMode == MeasureSpec.UNSPECIFIED
        val available = if (unbounded) Int.MAX_VALUE / 4 else widthSize
        val childWidthSpec =
            MeasureSpec.makeMeasureSpec(available, if (unbounded) MeasureSpec.UNSPECIFIED else MeasureSpec.AT_MOST)
        val childHeightSpec = MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED)

        val children = laidOutChildren()
        children.forEach { it.measure(childWidthSpec, childHeightSpec) }
        val widths = children.map { it.measuredWidth }
        val lines = FlowLineLayout.breakLines(widths, available, gapPx)

        val (widest, height) =
            FlowLineLayout.contentSize(widths, children.map { it.measuredHeight }, lines, gapPx, lineGapPx)
        val measuredWidth = if (widthMode == MeasureSpec.EXACTLY) widthSize else widest
        setMeasuredDimension(resolveSize(measuredWidth, widthMeasureSpec), resolveSize(height, heightMeasureSpec))
    }

    override fun onLayout(changed: Boolean, l: Int, t: Int, r: Int, b: Int) {
        val available = r - l
        val rtl = layoutDirection == LAYOUT_DIRECTION_RTL
        val children = laidOutChildren()
        val widths = children.map { it.measuredWidth }
        val endAligned = children.map { isEnd(it) }

        var y = 0
        FlowLineLayout.breakLines(widths, available, gapPx).forEach { line ->
            val lineHeight = line.maxOf { children[it].measuredHeight }
            val xs = FlowLineLayout.place(widths, endAligned, line, available, gapPx)
            for (i in line) {
                val child = children[i]
                val x = if (rtl) available - xs[i - line.first] - child.measuredWidth else xs[i - line.first]
                val top = y + (lineHeight - child.measuredHeight) / 2
                child.layout(x, top, x + child.measuredWidth, top + child.measuredHeight)
            }
            y += lineHeight + lineGapPx
        }
    }
}
