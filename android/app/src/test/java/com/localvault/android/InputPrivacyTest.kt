package com.localvault.android

import android.text.InputType
import android.view.inputmethod.EditorInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Keyboard-privacy flags. The bit arithmetic is tested directly; the
 * per-field application is verified by a static scan of MainActivity.kt
 * because EditText cannot be instantiated in a plain JVM test.
 */
class InputPrivacyTest {

    // ---- bit arithmetic

    @Test
    fun adds_flag_to_unspecified_ime_options() {
        val result = InputPrivacy.withNoPersonalizedLearning(0)
        assertEquals(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING, result)
    }

    @Test
    fun preserves_every_ime_action() {
        val actions =
            listOf(
                EditorInfo.IME_ACTION_NONE,
                EditorInfo.IME_ACTION_GO,
                EditorInfo.IME_ACTION_SEARCH,
                EditorInfo.IME_ACTION_SEND,
                EditorInfo.IME_ACTION_NEXT,
                EditorInfo.IME_ACTION_DONE,
            )
        for (action in actions) {
            val result = InputPrivacy.withNoPersonalizedLearning(action)
            assertEquals("action $action", action, result and EditorInfo.IME_MASK_ACTION)
            assertTrue(result and EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING != 0)
        }
    }

    @Test
    fun preserves_other_ime_flags_and_is_idempotent() {
        val base = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_EXTRACT_UI
        val once = InputPrivacy.withNoPersonalizedLearning(base)
        assertTrue(once and EditorInfo.IME_FLAG_NO_EXTRACT_UI != 0)
        assertEquals(once, InputPrivacy.withNoPersonalizedLearning(once))
    }

    @Test
    fun identifier_text_is_plain_text_with_only_no_suggestions_added() {
        val type = InputPrivacy.IDENTIFIER_TEXT
        assertEquals(InputType.TYPE_CLASS_TEXT, type and InputType.TYPE_MASK_CLASS)
        assertTrue(type and InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS != 0)
        // No layout/semantics change: no variation (URI/email/password), no capitalization, no multiline, no autocorrect.
        assertEquals(0, type and InputType.TYPE_MASK_VARIATION)
        assertEquals(0, type and InputType.TYPE_TEXT_FLAG_CAP_SENTENCES)
        assertEquals(0, type and InputType.TYPE_TEXT_FLAG_CAP_WORDS)
        assertEquals(0, type and InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS)
        assertEquals(0, type and InputType.TYPE_TEXT_FLAG_MULTI_LINE)
        assertEquals(0, type and InputType.TYPE_TEXT_FLAG_AUTO_CORRECT)
    }

    // ---- static scan of the field-creation paths

    private val source: String by lazy {
        File("src/main/java/com/localvault/android/MainActivity.kt").readText()
    }

    private fun functionBody(signature: String): String {
        val start = source.indexOf(signature)
        assertTrue("missing $signature", start >= 0)
        val end = source.indexOf("\n    }\n", start)
        return source.substring(start, end)
    }

    @Test
    fun edit_text_is_constructed_only_by_the_shared_factory() {
        val constructions = Regex("""\bEditText\(""").findAll(source).count()
        assertEquals(1, constructions)
        assertTrue(functionBody("private fun newField()").contains("EditText(this)"))
    }

    @Test
    fun shared_factory_requests_no_personalized_learning() {
        assertTrue(functionBody("private fun newField()").contains("InputPrivacy.withNoPersonalizedLearning"))
    }

    @Test
    fun every_explicit_ime_options_assignment_keeps_the_flag() {
        val factory = functionBody("private fun newField()")
        val assignments = source.lines().filter { Regex("""\.imeOptions\s*=""").containsMatchIn(it) }
        assertTrue(assignments.isNotEmpty())
        for (line in assignments) {
            if (factory.contains(line.trim())) continue
            assertTrue(
                "imeOptions assignment drops the flag: $line",
                line.contains("IME_FLAG_NO_PERSONALIZED_LEARNING") || line.contains("withNoPersonalizedLearning"),
            )
        }
    }

    @Test
    fun existing_ime_actions_are_unchanged() {
        assertTrue(functionBody("private fun newSearchField()").contains("IME_ACTION_SEARCH"))
        assertTrue(functionBody("private fun newPasswordField()").contains("IME_ACTION_DONE"))
        assertTrue(functionBody("private fun renderCreatePassword()").contains("IME_ACTION_NEXT"))
        assertTrue(functionBody("private fun renderCreatePassword()").contains("IME_ACTION_DONE"))
        assertTrue(functionBody("private fun renderTotpSetup()").contains("IME_ACTION_NONE"))
    }

    @Test
    fun secret_fields_keep_password_masking() {
        assertTrue(functionBody("private fun newPasswordField()").contains("TYPE_TEXT_VARIATION_PASSWORD"))
        assertTrue(functionBody("private fun renderCreatePassword()").contains("TYPE_TEXT_VARIATION_PASSWORD"))
        val totp = functionBody("private fun renderTotpSetup()")
        assertTrue(totp.contains("TYPE_TEXT_VARIATION_PASSWORD"))
        assertTrue(totp.contains("TYPE_TEXT_FLAG_NO_SUGGESTIONS"))
        val edit = functionBody("private fun renderEntryEdit()")
        assertTrue(edit.contains("pwField.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD"))
        // Multiline notes semantics untouched.
        assertTrue(edit.contains("InputType.TYPE_TEXT_FLAG_MULTI_LINE"))
    }

    @Test
    fun identifier_fields_use_no_suggestions_but_prose_fields_do_not() {
        val edit = functionBody("private fun renderEntryEdit()")
        for (name in listOf("urlField", "usernameField", "tagsField")) {
            assertTrue(name, edit.contains("$name.inputType = InputPrivacy.IDENTIFIER_TEXT"))
        }
        for (name in listOf("titleField", "profileField", "notesField")) {
            assertTrue(name, !edit.contains("$name.inputType = InputPrivacy"))
        }
    }
}
