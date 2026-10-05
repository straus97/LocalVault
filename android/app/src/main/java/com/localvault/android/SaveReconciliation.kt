package com.localvault.android

/**
 * The result of comparing a vault's current on-disk content against an
 * unresolved [RecoveryMarker] left by an interrupted save (accepted 1T-B5
 * storage/mutation architecture review, Revision 3, section 5's
 * lifecycle-interruption table).
 */
enum class ReconciliationOutcome {
    /** The primary's current hash matches the marker's expected-new hash:
     * the interrupted save actually completed. */
    SAVED,

    /** The primary's current hash matches the marker's baseline hash: the
     * interrupted save never touched the primary. */
    NOT_SAVED,

    /** The primary's current hash matches neither: its state is genuinely
     * unknown and a recovery-snapshot restore should be offered. The
     * marker is deliberately left in place in this case so the offer
     * persists until the user acts. */
    UNKNOWN_NEEDS_RECOVERY,
}

/**
 * Pure decision function: given an unresolved marker and the vault's
 * current on-disk content hash, decides what actually happened. Contains no
 * I/O and reads no clock, so it needs no fake/seam to unit test -- this is
 * deliberate, so the reconciliation *decision* stays correct regardless of
 * whatever execution context (thread, coroutine scope, etc.) B5a's
 * implementation ultimately uses to run the write itself.
 */
fun reconcile(marker: RecoveryMarker, currentPrimarySha256: String): ReconciliationOutcome {
    return when (currentPrimarySha256) {
        marker.expectedNewSha256 -> ReconciliationOutcome.SAVED
        marker.baselineSha256 -> ReconciliationOutcome.NOT_SAVED
        else -> ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY
    }
}

/**
 * Outcome of [runUnlockPreOpenGate]: either the primary may be opened --
 * carrying the opened value plus the exact envelope bytes and
 * reconciliation outcome (if any) that produced it -- or opening must not
 * be attempted at all.
 */
sealed class UnlockGateResult<out T> {
    data class Opened<out T>(
        val value: T,
        val envelopeBytes: ByteArray,
        val reconciliationOutcome: ReconciliationOutcome?,
    ) : UnlockGateResult<T>()

    /**
     * [unresolvedPrimarySha256] is the hash of the current primary at the
     * moment reconciliation blocked opening it -- `null` when no hash could
     * even be established (the primary couldn't be read, or the recovery
     * store itself couldn't be consulted). [RecoveryNeeded] carries no
     * envelope bytes at all: that is what structurally guarantees
     * `openPrimary` was never invoked to produce this result, not merely a
     * documented convention.
     */
    data class RecoveryNeeded<out T>(val unresolvedPrimarySha256: String?) : UnlockGateResult<T>()
}

/**
 * The entire pre-open decision for an ordinary unlock, in one seam
 * (accepted 1T-B5 storage/mutation architecture review, Revision 3,
 * section 5's lifecycle-interruption table: next-unlock reconciliation
 * must run against raw disk truth *before* normal use resumes, and must
 * never let a parse/decrypt attempt on an unresolved primary preempt it).
 *
 * [readMarker] and [readCurrentBytes] are each invoked at most once;
 * whatever bytes [readCurrentBytes] returns are the *same* bytes both the
 * reconciliation hash and (when permitted) [openPrimary] see -- there is no
 * second, independent read anywhere in this path, so reconciliation's
 * decision and the bytes actually opened can never diverge.
 *
 * Every recovery-store access ([readMarker], [clearMarker]) is individually
 * guarded: a failure there fails closed into [UnlockGateResult.RecoveryNeeded]
 * rather than throwing out of this function uncaught, or silently falling
 * through to [openPrimary] while recovery state is unknown. The one case
 * that does rethrow -- [readCurrentBytes] failing when no marker exists --
 * propagates unchanged so the caller's own ordinary read-failure
 * classification still applies, exactly as it did before this function
 * existed.
 *
 * No Android/Uri/SafDocumentIo type appears in this signature, and
 * [openPrimary] is generic over the opened value, so this is fully
 * exercisable in a plain JVM test with a call-counting fake in place of a
 * real `openVault`.
 */
fun <T> runUnlockPreOpenGate(
    readMarker: () -> RecoveryMarker?,
    readCurrentBytes: () -> ByteArray,
    clearMarker: () -> Unit,
    openPrimary: (envelopeBytes: ByteArray) -> T,
): UnlockGateResult<T> {
    val marker =
        try {
            readMarker()
        } catch (error: Exception) {
            // Can't even determine whether a save is unresolved -- fail
            // closed. No SHA to pin: the primary was never read.
            return UnlockGateResult.RecoveryNeeded(null)
        }

    val currentBytes =
        try {
            readCurrentBytes()
        } catch (error: Exception) {
            // No marker -> an ordinary read failure; let the caller's
            // existing classification handle it unchanged, by rethrowing.
            // A marker exists -> disk truth can't be established against
            // it; fail closed into recovery.
            if (marker == null) throw error
            return UnlockGateResult.RecoveryNeeded(null)
        }

    if (marker == null) {
        return UnlockGateResult.Opened(openPrimary(currentBytes), currentBytes, null)
    }

    val currentSha256 = Sha256.hex(currentBytes)
    val outcome = reconcile(marker, currentSha256)
    if (outcome == ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY) {
        return UnlockGateResult.RecoveryNeeded(currentSha256)
    }

    try {
        clearMarker()
    } catch (error: Exception) {
        // Resolved by disk truth, but could not be durably recorded --
        // stay conservative rather than open with an unresolved marker
        // silently left behind. The next unlock attempt reconciles (and
        // tries to clear) again from scratch; this one still never opens.
        return UnlockGateResult.RecoveryNeeded(currentSha256)
    }
    return UnlockGateResult.Opened(openPrimary(currentBytes), currentBytes, outcome)
}
