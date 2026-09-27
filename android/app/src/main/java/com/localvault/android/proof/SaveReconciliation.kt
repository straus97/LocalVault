package com.localvault.android.proof

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
 * Call before showing a vault's contents after any unlock. Returns `null`
 * if there is nothing to reconcile (the common case: no save was in flight
 * when the app last locked or died). On [ReconciliationOutcome.SAVED] or
 * [ReconciliationOutcome.NOT_SAVED] the marker is cleared, since the
 * outcome is now known; on [ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY]
 * it is left in place so the recovery offer persists.
 */
class SaveReconciler(private val io: SafDocumentIo, private val recovery: RecoverySnapshotStore) {

    fun reconcileOnUnlock(vaultUri: String): ReconciliationOutcome? {
        val marker = recovery.readMarker(vaultUri) ?: return null

        val outcome =
            try {
                reconcile(marker, Sha256.hex(io.readAll(vaultUri)))
            } catch (ignored: Exception) {
                ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY
            }

        if (outcome != ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY) {
            recovery.clearMarker(vaultUri)
        }

        return outcome
    }
}
