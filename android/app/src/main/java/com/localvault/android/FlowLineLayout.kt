package com.localvault.android

/**
 * Pure line-breaking / placement arithmetic behind [FlowRowLayout], kept free
 * of Android classes so the "no action can leave the viewport" guarantee is
 * unit-testable on the JVM.
 *
 * Contract: every item width is already clamped to the available width (the
 * view measures children with `AT_MOST(available)`), so a line is never wider
 * than `available` and an item is never placed past its right edge.
 */
internal object FlowLineLayout {
    /**
     * Greedily splits [widths] into consecutive lines (inclusive index ranges).
     * An item starts a new line when it would not fit after the previous
     * item plus [spacing]; the first item of a line is always accepted.
     */
    fun breakLines(widths: List<Int>, available: Int, spacing: Int): List<IntRange> {
        val lines = ArrayList<IntRange>()
        var start = 0
        var used = 0
        for (i in widths.indices) {
            if (i > start && used + spacing + widths[i] > available) {
                lines.add(start until i)
                start = i
                used = widths[i]
            } else {
                used = if (i == start) widths[i] else used + spacing + widths[i]
            }
        }
        if (widths.isNotEmpty()) lines.add(start until widths.size)
        return lines
    }

    /** Content size (widest line, summed line heights plus [lineGap]s) of already broken [lines]. */
    fun contentSize(
        widths: List<Int>,
        heights: List<Int>,
        lines: List<IntRange>,
        gap: Int,
        lineGap: Int,
    ): Pair<Int, Int> {
        var height = 0
        var widest = 0
        lines.forEachIndexed { index, line ->
            height += line.maxOf { heights[it] }
            if (index > 0) height += lineGap
            widest = maxOf(widest, lineWidth(widths, line, gap))
        }
        return widest to height
    }

    fun lineWidth(widths: List<Int>, line: IntRange, spacing: Int): Int =
        line.sumOf { widths[it] } + spacing * (line.count() - 1)

    /**
     * Left-to-right x offsets for the items of one [line], indexed from
     * `line.first`. Start-aligned items pack from x = 0 in order;
     * end-aligned items pack against [available], keeping their order.
     * Because the line fits, the two groups never overlap.
     */
    fun place(
        widths: List<Int>,
        endAligned: List<Boolean>,
        line: IntRange,
        available: Int,
        spacing: Int,
    ): IntArray {
        val xs = IntArray(line.count())
        var left = 0
        for (i in line) {
            if (!endAligned[i]) {
                xs[i - line.first] = left
                left += widths[i] + spacing
            }
        }
        var right = available
        for (i in line.reversed()) {
            if (endAligned[i]) {
                right -= widths[i]
                xs[i - line.first] = right
                right -= spacing
            }
        }
        return xs
    }
}
