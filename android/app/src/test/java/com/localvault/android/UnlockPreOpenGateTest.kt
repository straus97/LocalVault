package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

/**
 * Proves, by call-count assertion rather than a boolean predicate alone,
 * that [runUnlockPreOpenGate] never invokes its opener with bytes other
 * than the ones its own single read produced, and never invokes it at all
 * when reconciliation (or the recovery store itself) blocks opening.
 */
class UnlockPreOpenGateTest {

    private val vaultUri = "content://provider/document/vault"

    private val savedContent = "saved-primary-content".toByteArray()
    private val baselineContent = "pre-write-baseline-content".toByteArray()
    private val unrelatedContent = "neither-baseline-nor-expected-content".toByteArray()
    private val ordinaryContent = "ordinary-no-marker-content".toByteArray()

    private val marker = RecoveryMarker(
        vaultUri = vaultUri,
        baselineSha256 = Sha256.hex(baselineContent),
        expectedNewSha256 = Sha256.hex(savedContent),
        timestampMs = 1_000L,
    )

    @Test
    fun no_marker_opens_with_the_exact_ordinary_bytes() {
        var openCalls = 0

        val result = runUnlockPreOpenGate(
            readMarker = { null },
            readCurrentBytes = { ordinaryContent },
            clearMarker = { fail("must not clear when there is no marker") },
            openPrimary = { bytes -> openCalls++; assertSame(ordinaryContent, bytes); "session" },
        )

        assertEquals(1, openCalls)
        val opened = result as UnlockGateResult.Opened<String>
        assertSame(ordinaryContent, opened.envelopeBytes)
        assertNull(opened.reconciliationOutcome)
    }

    @Test
    fun saved_marker_opens_with_the_exact_reconciled_bytes_and_clears_the_marker() {
        var openCalls = 0
        var clearCalls = 0

        val result = runUnlockPreOpenGate(
            readMarker = { marker },
            readCurrentBytes = { savedContent },
            clearMarker = { clearCalls++ },
            openPrimary = { bytes -> openCalls++; assertSame(savedContent, bytes); "session" },
        )

        assertEquals(1, openCalls)
        assertEquals(1, clearCalls)
        val opened = result as UnlockGateResult.Opened<String>
        assertSame(savedContent, opened.envelopeBytes)
        assertEquals(ReconciliationOutcome.SAVED, opened.reconciliationOutcome)
    }

    @Test
    fun not_saved_marker_opens_with_the_exact_baseline_bytes_and_clears_the_marker() {
        var openCalls = 0
        var clearCalls = 0

        val result = runUnlockPreOpenGate(
            readMarker = { marker },
            readCurrentBytes = { baselineContent },
            clearMarker = { clearCalls++ },
            openPrimary = { bytes -> openCalls++; assertSame(baselineContent, bytes); "session" },
        )

        assertEquals(1, openCalls)
        assertEquals(1, clearCalls)
        val opened = result as UnlockGateResult.Opened<String>
        assertSame(baselineContent, opened.envelopeBytes)
        assertEquals(ReconciliationOutcome.NOT_SAVED, opened.reconciliationOutcome)
    }

    @Test
    fun unknown_outcome_never_invokes_the_opener_and_keeps_the_marker() {
        val result = runUnlockPreOpenGate(
            readMarker = { marker },
            readCurrentBytes = { unrelatedContent },
            clearMarker = { fail("must not clear on UNKNOWN_NEEDS_RECOVERY") },
            openPrimary = { fail("opener must not be invoked on UNKNOWN_NEEDS_RECOVERY"); "unreachable" },
        )

        assertTrue(result is UnlockGateResult.RecoveryNeeded<*>)
        assertEquals(Sha256.hex(unrelatedContent), (result as UnlockGateResult.RecoveryNeeded<*>).unresolvedPrimarySha256)
    }

    @Test
    fun read_failure_with_marker_blocks_opening_without_clearing() {
        val result = runUnlockPreOpenGate(
            readMarker = { marker },
            readCurrentBytes = { throw IOException("provider unavailable") },
            clearMarker = { fail("must not clear when the primary could not even be read") },
            openPrimary = { fail("opener must not be invoked"); "unreachable" },
        )

        assertTrue(result is UnlockGateResult.RecoveryNeeded<*>)
        assertNull((result as UnlockGateResult.RecoveryNeeded<*>).unresolvedPrimarySha256)
    }

    @Test
    fun read_failure_without_marker_propagates_and_never_opens() {
        val error = IOException("provider unavailable")

        val thrown =
            try {
                runUnlockPreOpenGate(
                    readMarker = { null },
                    readCurrentBytes = { throw error },
                    clearMarker = { fail("must not clear when there is no marker") },
                    openPrimary = { fail("opener must not be invoked"); "unreachable" },
                )
                null
            } catch (caught: IOException) {
                caught
            }

        assertSame(error, thrown)
    }

    @Test
    fun marker_read_failure_blocks_opening_and_opener_is_never_invoked() {
        val result = runUnlockPreOpenGate(
            readMarker = { throw IllegalStateException("recovery store unavailable") },
            readCurrentBytes = { fail("must not even attempt the primary read"); ordinaryContent },
            clearMarker = { fail("must not clear") },
            openPrimary = { fail("opener must not be invoked"); "unreachable" },
        )

        assertTrue(result is UnlockGateResult.RecoveryNeeded<*>)
        assertNull((result as UnlockGateResult.RecoveryNeeded<*>).unresolvedPrimarySha256)
    }

    @Test
    fun clear_marker_failure_after_resolved_outcome_blocks_opening() {
        var openCalls = 0

        val result = runUnlockPreOpenGate(
            readMarker = { marker },
            readCurrentBytes = { savedContent },
            clearMarker = { throw IllegalStateException("recovery store unavailable") },
            openPrimary = { openCalls++; "unreachable" },
        )

        assertEquals(0, openCalls)
        assertTrue(result is UnlockGateResult.RecoveryNeeded<*>)
        assertEquals(Sha256.hex(savedContent), (result as UnlockGateResult.RecoveryNeeded<*>).unresolvedPrimarySha256)
    }
}
