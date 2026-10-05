package com.localvault.android

/**
 * Outcome of one [RecoverySnapshotRestorer.restore] attempt. Deliberately
 * structured, like [SaveOutcome], so every branch is distinguishable
 * without carrying any secret-bearing or raw-exception detail.
 */
sealed class RestoreOutcome {
    /** The ONLY outcome that may be reported as restore success to the user. */
    object Success : RestoreOutcome()

    /**
     * No destructive write was attempted. The caller must not report
     * success. Returned whenever: no marker exists any more (resolved or
     * forgotten elsewhere); the recovery store itself couldn't be
     * consulted; reconciliation against a fresh read explicitly resolved
     * SAVED/NOT_SAVED; the current primary no longer matches the pinned
     * `unresolvedPrimarySha256` passed to [RecoverySnapshotRestorer.restore];
     * or that pinned SHA was `null` to begin with (a null pin can never by
     * itself authorize a destructive write). [freshOutcome]/[freshPrimarySha256]
     * are `null` only when nothing could even be determined (e.g. a
     * recovery-store read failure); otherwise they are the just-computed
     * values, letting the caller re-pin and require a fresh confirmation
     * when the vault is still genuinely unresolved.
     */
    data class RecheckRequired(
        val freshOutcome: ReconciliationOutcome?,
        val freshPrimarySha256: String?,
    ) : RestoreOutcome()

    /** Marker exists but no snapshot bytes are available (genuinely absent,
     * or the recovery store could not be read) -- nothing to restore from;
     * zero primary writes attempted. */
    object SnapshotMissing : RestoreOutcome()

    /** Marker and snapshot both exist, but the snapshot's own SHA-256 no
     * longer equals `marker.baselineSha256` -- the private copy itself is
     * damaged/truncated/stale relative to what the marker says it should
     * be. Distinct from [SnapshotMissing] (absent vs. present-but-wrong)
     * for diagnostics/tests, even though both currently map to the same
     * generic user-facing failure message. Zero primary writes attempted;
     * marker and snapshot are both left exactly as they are. */
    object SnapshotInvalid : RestoreOutcome()

    object ProviderNotWritable : RestoreOutcome()

    /** The write or its readback-verification failed. Marker and snapshot
     * are left exactly as they were -- the snapshot remains the known-good
     * recovery copy for a future attempt. */
    object WriteFailed : RestoreOutcome()

    /** Verified write succeeded, but durably clearing the marker afterward
     * could not be confirmed. NEVER [Success]: the primary genuinely holds
     * the restored (baseline) bytes, but the caller must still treat this
     * as needing a fresh unlock, whose own reconciliation -- now comparing
     * against a primary matching the marker's baseline_sha256 -- resolves
     * NOT_SAVED and clears the marker normally. Snapshot is never deleted
     * here. */
    object RestoredButMarkerClearFailed : RestoreOutcome()
}

/**
 * Explicit, user-confirmed-only restoration of a vault's private pre-write
 * recovery snapshot back into its primary document (accepted 1T-B5
 * storage/mutation architecture review, Revision 3, section 4 step 11b /
 * section 5: the legitimate recovery offer for an unresolved save). Takes
 * no [uniffi.localvault_android_bridge.VaultSessionInterface] and no
 * password -- restoring is pure ciphertext-to-ciphertext copying, exactly
 * like every other recovery-store operation.
 */
class RecoverySnapshotRestorer(
    private val io: SafDocumentIo,
    private val recovery: RecoverySnapshotStore,
) {
    /**
     * [unresolvedPrimarySha256] is the SHA pinned when the recovery screen
     * was last (re-)shown; `null` only when that pinning attempt couldn't
     * even read the primary. Best-effort SAF stale protection only -- like
     * [VaultSaveCoordinator]'s own two-stale-check discipline, this narrows
     * but cannot eliminate the window between the reread below and the
     * destructive write; SAF offers no exclusive-lock primitive to close
     * it entirely.
     *
     * Every [RecoverySnapshotStore]/[SafDocumentIo] call here is
     * individually guarded: none can propagate an uncaught exception out
     * of this function, so a caller driving this off a background thread
     * can never have that thread die silently before producing a result.
     * No raw exception text or secret-bearing detail is ever placed into
     * the returned [RestoreOutcome].
     */
    fun restore(vaultUri: String, unresolvedPrimarySha256: String?): RestoreOutcome {
        val marker =
            try {
                recovery.readMarker(vaultUri)
            } catch (error: Exception) {
                return RestoreOutcome.RecheckRequired(null, null)
            } ?: return RestoreOutcome.RecheckRequired(null, null)

        val snapshotBytes =
            try {
                recovery.readSnapshotBytes(vaultUri)
            } catch (error: Exception) {
                null
            } ?: return RestoreOutcome.SnapshotMissing

        // The snapshot was write/readback-verified when it was originally
        // created (RecoverySnapshotStore.writeAndVerify), but that does not
        // prove it is still intact now -- it could have been damaged or
        // truncated since. Fail closed rather than write a corrupted
        // "known-good" copy into the primary and then clear the marker.
        if (Sha256.hex(snapshotBytes) != marker.baselineSha256) {
            return RestoreOutcome.SnapshotInvalid
        }

        val currentBytes =
            try {
                io.readAll(vaultUri)
            } catch (error: Exception) {
                return RestoreOutcome.WriteFailed
            }
        val currentSha256 = Sha256.hex(currentBytes)
        val freshOutcome = reconcile(marker, currentSha256)

        if (freshOutcome != ReconciliationOutcome.UNKNOWN_NEEDS_RECOVERY) {
            // Something else already resolved this -- never overwrite a
            // state reconciliation itself can explain. Best-effort clear:
            // swallow any failure here (no crash, no false claim) -- a
            // fresh unlock's own reconciliation reaches the same correct
            // conclusion again and retries clearing then.
            try {
                recovery.clearMarker(vaultUri)
            } catch (ignored: Exception) {
            }
            return RestoreOutcome.RecheckRequired(freshOutcome, currentSha256)
        }

        // A null pin can NEVER by itself authorize a destructive write. It
        // means either this is the first restore attempt after an unlock
        // preflight that could not read the primary at all, or a previous
        // recheck already fired. Either way: pin the just-observed SHA and
        // require a brand-new explicit confirmation (a fresh recovery
        // screen render + another Restore tap) before any write is even
        // considered. Zero writes on this call.
        if (unresolvedPrimarySha256 == null) {
            return RestoreOutcome.RecheckRequired(freshOutcome, currentSha256)
        }

        // A non-null pin that no longer matches the current primary means
        // it moved since it was pinned -- never overwritten. The caller
        // must not clear/reset this pin on a retryable failure, so a stale
        // write is never silently re-authorized merely because an earlier
        // attempt happened to fail for an unrelated reason (e.g. a
        // transient grant problem).
        if (currentSha256 != unresolvedPrimarySha256) {
            return RestoreOutcome.RecheckRequired(freshOutcome, currentSha256)
        }

        // Both live capability checks are guarded: ContentResolverSafDocumentIo's
        // own hasPersistedWriteGrant does not catch internally (unlike its
        // supportsWrite), and this seam's contract must not assume every
        // SafDocumentIo implementation is non-throwing either way -- a
        // failure here is exactly the same "not safely writable" signal as
        // a live check that returns false.
        val writable =
            try {
                io.hasPersistedWriteGrant(vaultUri) && io.supportsWrite(vaultUri)
            } catch (error: Exception) {
                false
            }
        if (!writable) {
            return RestoreOutcome.ProviderNotWritable
        }

        try {
            io.writeTruncated(vaultUri, snapshotBytes)
        } catch (error: Exception) {
            return RestoreOutcome.WriteFailed
        }

        val readback =
            try {
                io.readAll(vaultUri)
            } catch (error: Exception) {
                return RestoreOutcome.WriteFailed
            }
        if (!readback.contentEquals(snapshotBytes)) return RestoreOutcome.WriteFailed

        return try {
            recovery.clearMarker(vaultUri)
            // Verify, don't just trust the call -- matches writeAndVerify's
            // own readback-verify philosophy; also catches a silent
            // AtomicFile/File.delete() failure that throws nothing (the
            // more realistic failure mode than an exception here).
            if (recovery.readMarker(vaultUri) != null) {
                RestoreOutcome.RestoredButMarkerClearFailed
            } else {
                RestoreOutcome.Success
            }
        } catch (error: Exception) {
            RestoreOutcome.RestoredButMarkerClearFailed
        }
    }
}
