package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Scenario checks for the three rows that are built with [FlowRowLayout]:
 * DETAIL top bar, recent-vault card actions and the LIST header (title +
 * Add entry + Lock), at 100% / 150% / 200% font scale in RU and EN.
 *
 * Each row is "measured" the way the view does it: every child gets
 * `AT_MOST(available)` (see [measureChild]), then [FlowLineLayout] breaks and
 * places the lines -- the same code [FlowRowLayout] runs. Only the natural
 * text widths are modelled (chars x dp-per-char x scale + padding); real glyph
 * widths differ, which is why the assertions are structural (nothing leaves the
 * row, nothing is squeezed below its natural width) and not pixel-exact.
 * On-device rendering is verified separately by hand.
 */
class FlowRowScenarioTest {
    private data class Child(val text: String, val endAligned: Boolean, val padding: Int, val minWidth: Int, val sp: Double, val bold: Boolean = false)

    private val scales = listOf(1.0, 1.5, 2.0)
    private val gap = 8

    private fun natural(child: Child, ru: Boolean, scale: Double): Int {
        val perChar = child.sp * (if (ru) 0.53 else 0.48) * (if (child.bold) 1.1 else 1.0)
        return maxOf(child.minWidth, (child.text.length * perChar * scale).toInt() + child.padding)
    }

    /** Child width after `measure(AT_MOST(available))`. */
    private fun measureChild(natural: Int, available: Int) = minOf(natural, available)

    private fun secondary(text: String, end: Boolean = true) = Child(text, end, padding = 28, minWidth = 88, sp = 15.0)
    private fun textButton(text: String, end: Boolean = true) = Child(text, end, padding = 20, minWidth = 0, sp = 15.0)

    private class Result(val naturals: List<Int>, val widths: List<Int>, val lines: List<IntRange>, val xs: Map<Int, Int>)

    private fun layout(children: List<Child>, ru: Boolean, scale: Double, available: Int): Result {
        val naturals = children.map { natural(it, ru, scale) }
        val widths = naturals.map { measureChild(it, available) }
        val lines = FlowLineLayout.breakLines(widths, available, gap)
        val xs = HashMap<Int, Int>()
        for (line in lines) {
            val placed = FlowLineLayout.place(widths, children.map { it.endAligned }, line, available, gap)
            for (i in line) xs[i] = placed[i - line.first]
        }
        return Result(naturals, widths, lines, xs)
    }

    private fun assertReachable(r: Result, available: Int, label: String) {
        assertEquals("$label: every child laid out once", r.widths.indices.toList(), r.lines.flatMap { it.toList() })
        for (i in r.widths.indices) {
            val x = r.xs.getValue(i)
            assertTrue("$label: child $i starts left of the row", x >= 0)
            assertTrue("$label: child $i ends past the row", x + r.widths[i] <= available)
            // Never squeezed: a child gets its natural width unless the row itself is narrower.
            assertEquals("$label: child $i squeezed", minOf(r.naturals[i], available), r.widths[i])
        }
        for (line in r.lines) {
            val spans = line.map { r.xs.getValue(it) to r.xs.getValue(it) + r.widths[it] }.sortedBy { it.first }
            spans.zipWithNext().forEach { (a, b) -> assertTrue("$label: overlap", a.second <= b.first) }
        }
    }

    @Test
    fun detailTopBarStaysReachable() {
        for (ru in listOf(true, false)) for (scale in scales) for (available in listOf(353, 280)) {
            val children = if (ru) {
                listOf(textButton("‹ Назад", false), secondary("Изменить"), secondary("Удалить"), secondary("Заблокировать"))
            } else {
                listOf(textButton("‹ Back", false), secondary("Edit"), secondary("Delete"), secondary("Lock"))
            }
            assertReachable(layout(children, ru, scale, available), available, "detail ru=$ru x$scale w=$available")
        }
    }

    @Test
    fun recentVaultCardActionsStayReachableAndAreNeverSqueezed() {
        for (ru in listOf(true, false)) for (scale in scales) for (available in listOf(321, 248)) {
            val children = if (ru) {
                listOf(textButton("Разрешить редактирование"), textButton("Удалить из истории"))
            } else {
                listOf(textButton("Enable editing"), textButton("Remove from history"))
            }
            assertReachable(layout(children, ru, scale, available), available, "recent ru=$ru x$scale w=$available")
            // read-write vault: only the remove action
            assertReachable(layout(children.drop(1), ru, scale, available), available, "recent-rw ru=$ru x$scale w=$available")
        }
    }

    @Test
    fun recentVaultCardActionsStackAtLargeFontRu() {
        // 200%, 393dp-class phone: the two actions cannot share a line; each gets its own.
        val r = layout(
            listOf(textButton("Разрешить редактирование"), textButton("Удалить из истории")),
            ru = true,
            scale = 2.0,
            available = 321,
        )
        assertEquals(2, r.lines.size)
    }

    @Test
    fun oldLinearLayoutGaveTheSecondActionOnlyTheLeftoverWidth() {
        // Documents the root cause: LinearLayout measures later children with
        // what the earlier ones left over, so the 2nd button got a sliver.
        val available = 321
        val first = natural(textButton("Разрешить редактирование"), ru = true, scale = 2.0)
        val second = natural(textButton("Удалить из истории"), ru = true, scale = 2.0)
        val leftover = available - minOf(first, available)
        assertTrue("2nd button natural=$second, leftover=$leftover", leftover < second)
        assertTrue("leftover would be a sliver, got $leftover", leftover < 40)
    }

    @Test
    fun listHeaderTitleAddAndLockStayReachableAndTitleIsNotSqueezed() {
        for (ru in listOf(true, false)) for (scale in scales) for (available in listOf(353, 280)) {
            val children = listOf(
                Child("LocalVault", endAligned = false, padding = 0, minWidth = 0, sp = 22.0, bold = true),
                secondary(if (ru) "Добавить запись" else "Add entry"),
                secondary(if (ru) "Заблокировать" else "Lock"),
            )
            val r = layout(children, ru, scale, available)
            assertReachable(r, available, "list header ru=$ru x$scale w=$available")
            // Title keeps its full natural width on the first line (never a few characters).
            assertEquals(0, r.lines.first().first)
            assertEquals(r.naturals[0], r.widths[0])
        }
    }

    @Test
    fun listHeaderPlacesButtonsOnTheEndEdge() {
        val r = layout(
            listOf(
                Child("LocalVault", endAligned = false, padding = 0, minWidth = 0, sp = 22.0, bold = true),
                secondary("Add entry"),
                secondary("Lock"),
            ),
            ru = false,
            scale = 1.0,
            available = 353,
        )
        assertEquals(1, r.lines.size)
        assertEquals(353, r.xs.getValue(2) + r.widths[2]) // Lock flush with the end
        assertEquals(0, r.xs.getValue(0))
    }

    @Test
    fun listHeaderWrapsButtonsBelowTheTitleAtLargeFontRu() {
        val r = layout(
            listOf(
                Child("LocalVault", endAligned = false, padding = 0, minWidth = 0, sp = 22.0, bold = true),
                secondary("Добавить запись"),
                secondary("Заблокировать"),
            ),
            ru = true,
            scale = 2.0,
            available = 353,
        )
        assertTrue(r.lines.size >= 2)
        assertEquals(listOf(0), r.lines.first().toList())
    }

    @Test
    fun categoryRenameDeleteStayReachable() {
        // Card inner width = screen content width - 32dp card padding.
        for (ru in listOf(true, false)) for (scale in scales) for (available in listOf(321, 248)) {
            val children = listOf(
                secondary(if (ru) "Переименовать" else "Rename", end = false),
                secondary(if (ru) "Удалить" else "Delete", end = false),
            )
            val r = layout(children, ru, scale, available)
            assertReachable(r, available, "category ru=$ru x$scale w=$available")
        }
    }

    @Test
    fun categoryActionsStackAtLargeFontRuAndSitStartAligned() {
        val r = layout(
            listOf(secondary("Переименовать", end = false), secondary("Удалить", end = false)),
            ru = true,
            scale = 2.0,
            available = 321,
        )
        assertEquals(2, r.lines.size)
        assertEquals(0, r.xs.getValue(0))
        assertEquals(0, r.xs.getValue(1))
    }

    @Test
    fun contentSizeSumsLineHeightsAndGaps() {
        val widths = listOf(200, 200, 100)
        val heights = listOf(40, 56, 40)
        val lines = FlowLineLayout.breakLines(widths, 308, 8) // [0], [1,2]
        assertEquals(listOf(0..0, 1..2), lines)
        assertEquals((308 to 40 + 4 + 56), FlowLineLayout.contentSize(widths, heights, lines, 8, 4))
    }
}
