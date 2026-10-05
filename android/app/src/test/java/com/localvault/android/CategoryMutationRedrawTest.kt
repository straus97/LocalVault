package com.localvault.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pins the B5b-5/B5b-6 stale-generation redraw policy `finishCategoryMutation`
 * relies on: a successful category mutation that outlives a Back-out
 * navigation must still redraw the two screens whose content depends on the
 * cache it just refreshed (LIST, CATEGORY_MANAGE), and nothing else.
 */
class CategoryMutationRedrawTest {

    @Test
    fun list_is_redrawn() {
        assertTrue(shouldRedrawAfterStaleCategoryMutation(CategoryMutationRedrawTarget.LIST))
    }

    @Test
    fun category_manage_is_redrawn() {
        assertTrue(shouldRedrawAfterStaleCategoryMutation(CategoryMutationRedrawTarget.CATEGORY_MANAGE))
    }

    // DETAIL and ENTRY_EDIT (and every other screen) are deliberately not
    // distinct values of CategoryMutationRedrawTarget -- they have no
    // dependency on the category/entry cache this policy guards, so
    // MainActivity's own screen -> target mapping collapses all of them to
    // the same OTHER value. Both are asserted explicitly here as named
    // representatives of that case, even though they exercise the same
    // underlying value, so this policy's two real screens of interest are
    // never confused with "every screen we didn't think of."

    @Test
    fun detail_is_left_untouched() {
        assertFalse(shouldRedrawAfterStaleCategoryMutation(CategoryMutationRedrawTarget.OTHER))
    }

    @Test
    fun entry_edit_is_left_untouched() {
        assertFalse(shouldRedrawAfterStaleCategoryMutation(CategoryMutationRedrawTarget.OTHER))
    }
}
