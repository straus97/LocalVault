package com.localvault.android

import android.text.InputType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Entry-editor Show/Hide password. State logic and input-type arithmetic are
 * tested directly. LIMITATION: actual EditText behavior (text/selection
 * preservation across setInputType, keyboard restart, rendering of the eye
 * icon, large-font/narrow layout) cannot run in a plain JVM test; those parts
 * are pinned by a static scan of MainActivity.kt and need on-device checks.
 */
class PasswordVisibilityTest {

    @Test
    fun default_state_is_hidden_with_the_existing_password_input_type() {
        val v = PasswordVisibility()
        assertFalse(v.shown)
        assertEquals(InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD, v.inputType)
    }

    @Test
    fun toggle_flips_and_returns_new_state() {
        val v = PasswordVisibility()
        assertTrue(v.toggle())
        assertTrue(v.shown)
        assertEquals(PasswordVisibility.SHOWN_INPUT_TYPE, v.inputType)
        assertFalse(v.toggle())
        assertEquals(PasswordVisibility.HIDDEN_INPUT_TYPE, v.inputType)
    }

    @Test
    fun reset_hides_and_reports_whether_it_changed() {
        val v = PasswordVisibility()
        assertFalse(v.reset())
        v.toggle()
        assertTrue(v.reset())
        assertFalse(v.shown)
        assertFalse(v.reset())
    }

    @Test
    fun shown_type_is_visible_password_text_with_suggestions_suppressed() {
        val t = PasswordVisibility.SHOWN_INPUT_TYPE
        assertEquals(InputType.TYPE_CLASS_TEXT, t and InputType.TYPE_MASK_CLASS)
        assertEquals(InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD, t and InputType.TYPE_MASK_VARIATION)
        assertTrue(t and InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS != 0)
        assertEquals(0, t and InputType.TYPE_TEXT_FLAG_MULTI_LINE)
    }

    @Test
    fun a_fresh_instance_is_hidden_so_state_is_never_carried_over() {
        val a = PasswordVisibility()
        a.toggle()
        assertFalse(PasswordVisibility().shown)
    }

    // ---- static scan of the wiring

    private val source: String by lazy {
        File("src/main/java/com/localvault/android/MainActivity.kt").readText()
    }

    private fun body(signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("missing $signature", start >= 0)
        return source.substring(start, source.indexOf("\n    }\n", start))
    }

    @Test
    fun apply_preserves_selection_and_ime_options_and_never_touches_text() {
        val b = body("private fun applyEditPasswordVisibility()")
        assertTrue(b.contains("selectionStart") && b.contains("setSelection"))
        assertTrue(b.contains("val imeOptions = field.imeOptions") && b.contains("field.setImeOptions(imeOptions)"))
        assertFalse(b.contains("setText") || b.contains(".text ="))
    }

    @Test
    fun toggle_path_has_no_clipboard_logging_or_persistence() {
        for (sig in listOf(
            "private fun newEditPasswordRow(",
            "private fun toggleEditPasswordVisibility()",
            "private fun resetEditPasswordVisibility()",
            "private fun applyEditPasswordVisibility()",
            "private fun applyEditPasswordToggleAppearance()",
        )) {
            val b = body(sig)
            assertFalse(sig, Regex("""clipboard|Log.|println|putBoolean|SharedPreferences|Bundle|setText""").containsMatchIn(b))
        }
    }

    @Test
    fun visibility_is_reset_on_stop_edit_exit_and_every_render() {
        assertTrue(body("override fun onStop()").contains("resetEditPasswordVisibility()"))
        assertTrue(body("private fun clearEntryEditState()").contains("resetEditPasswordVisibility()"))
        assertTrue(source.contains("editPasswordToggle = null\n        editPasswordVisibility.reset()"))
    }

    @Test
    fun visibility_is_not_saved_in_instance_state() {
        assertFalse(body("override fun onSaveInstanceState(outState: Bundle)").contains("PasswordVisibility"))
        assertFalse(body("override fun onSaveInstanceState(outState: Bundle)").contains("editPassword"))
    }

    @Test
    fun edit_field_starts_hidden_and_toggle_has_accessible_labels() {
        assertTrue(source.contains("pwField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD"))
        val b = body("private fun applyEditPasswordToggleAppearance()")
        assertTrue(b.contains("R.string.hide_password") && b.contains("R.string.show_password"))
        assertTrue(b.contains("contentDescription"))
    }

    @Test
    fun en_and_ru_labels_exist() {
        val en = File("src/main/res/values/strings.xml").readText()
        val ru = File("src/main/res/values-ru/strings.xml").readText()
        for (s in listOf(en, ru)) {
            assertTrue(s.contains("name=\"show_password\"") && s.contains("name=\"hide_password\""))
        }
    }
}
