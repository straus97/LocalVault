package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the arithmetic behind the DETAIL top-action row: lines never exceed the
 * available width, no action is dropped or reordered, and every action stays
 * fully inside [0, available] -- for RU/EN label widths, narrow screens and
 * larger font scales. (The measured view itself is exercised on a device.)
 */
class FlowLineLayoutTest {
    private fun lines(widths: List<Int>, available: Int, spacing: Int = 8) =
        FlowLineLayout.breakLines(widths, available, spacing)

    @Test
    fun emptyInputHasNoLines() {
        assertTrue(lines(emptyList(), 300).isEmpty())
    }

    @Test
    fun everythingThatFitsStaysOnOneLine() {
        assertEquals(listOf(0..3), lines(listOf(60, 80, 80, 70), 314))
    }

    @Test
    fun exactFitStaysOnOneLineAndOnePixelLessWraps() {
        // 100 + 8 + 100 = 208
        assertEquals(listOf(0..1), lines(listOf(100, 100), 208))
        assertEquals(listOf(0..0, 1..1), lines(listOf(100, 100), 207))
    }

    @Test
    fun overflowingItemMovesToNextLineInOrder() {
        // Back, Edit, Delete, Lock at a width where Lock cannot join line 1.
        assertEquals(listOf(0..2, 3..3), lines(listOf(76, 94, 88, 133), 280))
    }

    @Test
    fun itemAsWideAsTheLineGetsALineOfItsOwn() {
        assertEquals(listOf(0..0, 1..1, 2..2), lines(listOf(50, 280, 50), 280))
    }

    @Test
    fun endAlignedItemsPackAgainstTheEndAndStartItemsFromZero() {
        val widths = listOf(76, 94, 88, 88)
        val xs = FlowLineLayout.place(widths, listOf(false, true, true, true), 0..3, 400, 8)
        assertEquals(0, xs[0])
        assertEquals(400 - 88, xs[3])
        assertEquals(400 - 88 - 8 - 88, xs[2])
        assertEquals(400 - 88 - 8 - 88 - 8 - 94, xs[1])
        assertEquals(400, xs[3] + widths[3])
    }

    @Test
    fun wrappedLineKeepsEndAlignmentForItsOwnItems() {
        val widths = listOf(76, 94, 88, 133)
        val endAligned = listOf(false, true, true, true)
        val all = FlowLineLayout.breakLines(widths, 280, 8)
        val second = all[1]
        val xs = FlowLineLayout.place(widths, endAligned, second, 280, 8)
        assertEquals(280 - 133, xs[0]) // Lock sits flush against the end edge of line 2
    }

    /**
     * Estimated natural dp widths of Back / Edit / Delete / Lock at 1.0 font
     * scale: text width only (15sp, approx.), RU and EN. The text part scales
     * with the font; padding (20dp for Back, 28dp for the others) does not, and
     * the three secondary buttons keep the platform 88dp minimum width.
     */
    private fun naturalWidths(ru: Boolean, fontScale: Double): List<Int> {
        val text = if (ru) listOf(56, 66, 58, 105) else listOf(46, 30, 40, 30)
        val back = (text[0] * fontScale).toInt() + 20
        val secondary = text.drop(1).map { maxOf(88, (it * fontScale).toInt() + 28) }
        return listOf(back) + secondary
    }

    @Test
    fun noActionIsEverClippedAcrossLocalesWidthsAndFontScales() {
        for (ru in listOf(true, false)) {
            for (available in listOf(240, 280, 320, 353, 411)) {
                for (scale in listOf(1.0, 1.15, 1.3, 1.5, 2.0)) {
                    // Each child is measured AT_MOST(available), so it is clamped here too.
                    val widths = naturalWidths(ru, scale).map { minOf(it, available) }
                    val endAligned = listOf(false, true, true, true)
                    val lines = FlowLineLayout.breakLines(widths, available, 8)

                    // Every action appears exactly once, in order.
                    assertEquals(widths.indices.toList(), lines.flatMap { it.toList() })

                    for (line in lines) {
                        assertTrue(
                            "line too wide ru=$ru avail=$available scale=$scale",
                            FlowLineLayout.lineWidth(widths, line, 8) <= available,
                        )
                        val xs = FlowLineLayout.place(widths, endAligned, line, available, 8)
                        for (i in line) {
                            val x = xs[i - line.first]
                            assertTrue("clipped at start", x >= 0)
                            assertTrue("clipped at end ru=$ru avail=$available scale=$scale", x + widths[i] <= available)
                        }
                        // No two actions on a line overlap.
                        val spans = line.map { xs[it - line.first] to xs[it - line.first] + widths[it] }.sortedBy { it.first }
                        spans.zipWithNext().forEach { (a, b) -> assertTrue("overlap", a.second <= b.first) }
                    }
                }
            }
        }
    }
}
