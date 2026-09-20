package com.localvault.android.proof

import android.app.Activity
import android.os.Bundle
import android.os.SystemClock
import android.widget.TextView
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.verifyCompatibilityFixture

/**
 * 1T-B1b architecture proof only. Proves: Kotlin -> generated UniFFI/JNA
 * binding -> localvault-android-bridge -> localvault-core -> the existing
 * encrypted persisted vault format, and back, with only a non-secret result
 * crossing the boundary. Not the real LocalVault Android UI.
 *
 * The FFI calls stay synchronous (each includes a real Argon2id derivation),
 * but they run on one dedicated background thread so the Android main thread
 * is never blocked. The fixture and both passwords below are committed,
 * public test-only material (see src-tauri/tests/compat_baseline.rs) -- not
 * real secrets -- but are still handled as secret-shaped: never logged,
 * never displayed, never retained beyond the proof call.
 */
class ProofActivity : Activity() {

    private companion object {
        const val FIXTURE_ASSET_NAME = "compat_fixture.bin"
        const val KNOWN_GOOD_PASSWORD = "compat-baseline-master-password-test-only"
        const val KNOWN_BAD_PASSWORD = "definitely-wrong-password-test-only"
        const val TITLE = "LocalVault Android bridge"
    }

    private lateinit var resultView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        resultView = TextView(this)
        resultView.setPadding(48, 96, 48, 48)
        resultView.textSize = 16f
        resultView.text = "$TITLE\n\nRunning compatibility proof..."
        setContentView(resultView)

        Thread { finishProofOnUiThread(runProof()) }.start()
    }

    private fun finishProofOnUiThread(summary: String) {
        runOnUiThread {
            if (!isFinishing && !isDestroyed) {
                resultView.text = summary
            }
        }
    }

    /**
     * Runs both synchronous proof calls (off the main thread) and returns only
     * a non-secret summary: PASS/FAIL, schema number and elapsed timings. No
     * password, fixture byte, decrypted content or error text is included.
     */
    private fun runProof(): String {
        val fixtureBytes =
            try {
                assets.open(FIXTURE_ASSET_NAME).use { it.readBytes() }
            } catch (error: Exception) {
                return "$TITLE\n\nProof: FAIL"
            }

        val positiveStart = SystemClock.elapsedRealtime()
        val positiveLine =
            try {
                val result = verifyCompatibilityFixture(fixtureBytes, KNOWN_GOOD_PASSWORD)
                "Positive path: PASS (schema ${result.schemaVersion})"
            } catch (error: BridgeException) {
                "Positive path: FAIL (${error.javaClass.simpleName})"
            } catch (error: Throwable) {
                "Positive path: FAIL"
            }
        val positiveMs = SystemClock.elapsedRealtime() - positiveStart

        val negativeStart = SystemClock.elapsedRealtime()
        val negativeLine =
            try {
                verifyCompatibilityFixture(fixtureBytes, KNOWN_BAD_PASSWORD)
                "Negative path: FAIL (unexpectedly succeeded)"
            } catch (error: BridgeException.AuthenticationFailed) {
                "Negative path: PASS (rejected as expected)"
            } catch (error: BridgeException) {
                "Negative path: FAIL (${error.javaClass.simpleName})"
            } catch (error: Throwable) {
                "Negative path: FAIL"
            }
        val negativeMs = SystemClock.elapsedRealtime() - negativeStart

        return listOf(
            TITLE,
            "",
            positiveLine,
            negativeLine,
            "",
            "Positive: $positiveMs ms",
            "Negative: $negativeMs ms",
            "Total: ${positiveMs + negativeMs} ms",
        ).joinToString(separator = "\n")
    }
}
