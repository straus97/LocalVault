package com.localvault.android

import android.text.InputType
import android.view.inputmethod.EditorInfo

/**
 * Pure helpers for the keyboard-privacy flags applied to LocalVault text
 * fields. Kept free of View/Context so the bit arithmetic is JVM-testable.
 *
 * Both flags are requests, not guarantees: an IME may ignore
 * IME_FLAG_NO_PERSONALIZED_LEARNING (it only asks the keyboard not to learn
 * from typed text), and a malicious keyboard can read everything typed. They
 * reduce accidental retention by well-behaved keyboards (suggestion/learning
 * dictionaries) and nothing more.
 */
internal object InputPrivacy {
    /** Adds the no-personalized-learning request, preserving any IME action and other flags. */
    fun withNoPersonalizedLearning(imeOptions: Int): Int = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING

    /**
     * Plain single-line text with spell-check/auto-correct suggestions
     * suppressed. For identifier-like values (URL, username, tags) where a
     * suggestion strip or auto-correction is both a retention path and a
     * source of silent corruption. Keeps the keyboard layout and capitalization
     * behavior of ordinary text (no URI/email/password variation).
     */
    const val IDENTIFIER_TEXT: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
}
