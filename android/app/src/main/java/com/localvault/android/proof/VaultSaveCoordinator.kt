package com.localvault.android.proof

import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.EntryInput
import uniffi.localvault_android_bridge.VaultSessionInterface

/**
 * Outcome of one [VaultSaveCoordinator] save attempt. Deliberately distinct
 * from [BridgeException]: some of these outcomes (e.g. [ChangedExternally],
 * [WriteFailed]) never reach the Rust bridge at all -- they are decided
 * entirely on the Kotlin side against bytes this class already holds
 * (accepted 1T-B5 review, Revision 3, section 8).
 */
sealed class SaveOutcome {
    object Success : SaveOutcome()

    /** Write eligibility could not be freshly established (no live
     * persisted write grant, or the provider does not currently report
     * this document as writable). Never attempted. */
    object ProviderNotWritable : SaveOutcome()

    /** Either stale-source check found the primary's content did not match
     * the tracked baseline. The primary was never written to in this
     * attempt; the stage (if any) was discarded and no marker was left
     * pending -- reopen the vault to continue. */
    object ChangedExternally : SaveOutcome()

    /** The durable private recovery snapshot could not be written and
     * verified. The primary was never touched. */
    object RecoverySnapshotFailed : SaveOutcome()

    /** The staged mutation itself was rejected by the bridge (validation,
     * an already-pending stage, a locked session, ...). */
    data class ValidationFailed(val error: BridgeException) : SaveOutcome()

    /** The primary write, its readback, or the byte-equality check failed.
     * The primary may be in an unknown/partial state; the recovery
     * snapshot written before this attempt is the safe copy. The marker is
     * deliberately left unresolved. */
    object WriteFailed : SaveOutcome()

    /** An I/O failure reading the primary before any write was attempted. */
    data class UnexpectedError(val error: Exception) : SaveOutcome()
}

/**
 * Executes the accepted two-stale-check save sequence (1T-B5 storage/
 * mutation architecture review, Revision 3, section 4) for mutating one
 * already write-enabled vault. One coordinator instance is meant to live
 * alongside one unlocked [VaultSessionInterface], tracking the in-memory
 * baseline hash established at open time and advanced after each
 * successful save -- mirroring desktop's `UnlockedVaultSession.envelope`
 * tracking, just expressed as a raw-byte hash instead of a parsed struct
 * (accepted review, section 6).
 *
 * This class performs no picker/Activity interaction and holds no Rust
 * secret state itself (that lives inside [session]); it is safe to
 * construct and use only for a vault whose write grant and picker flow are
 * already resolved (see [VaultCreationCoordinator] and the enable-editing
 * flow in `MainActivity` for what must happen first).
 *
 * Execution context: this class does no threading of its own -- callers
 * must invoke [saveUpdateEntry] off the main thread, exactly as
 * `MainActivity.runUnlock` already does for `openVault` via a plain
 * `Thread { ... }.start()`. That existing pattern already satisfies the
 * accepted review's requirement that an in-flight write not be
 * automatically cancelled merely because the Activity receives `onStop`: a
 * bare `Thread` is not parented to the Activity lifecycle at all, so no new
 * executor/coroutine/WorkManager/foreground-service mechanism is introduced
 * here (Revision 3, section 12's resolution of that question).
 */
class VaultSaveCoordinator(
    private val session: VaultSessionInterface,
    private val io: SafDocumentIo,
    private val recovery: RecoverySnapshotStore,
    initialEnvelopeBytes: ByteArray,
) {
    @Volatile
    private var baselineSha256: String = Sha256.hex(initialEnvelopeBytes)

    /**
     * Stages, saves and commits a non-TOTP update to [entryId]. [nowMs] is
     * caller-supplied wall-clock time; this class reads no clock, matching
     * the bridge's own convention.
     *
     * [onAfterMarkerWritten], when non-null, is invoked exactly once, after
     * the durable recovery snapshot and marker (steps 4-5) already exist on
     * disk and before the second stale-source check (step 7) reads the
     * primary again. Production callers must leave this `null`; its only
     * purpose is deterministic real-device QA fault injection for two
     * Revision 3 acceptance scenarios that both hinge on exactly this
     * moment -- an external change racing the save (aborted cleanly by
     * step 7 before any primary write), and an interrupted write left for
     * next-unlock reconciliation to resolve as NOT_SAVED (killed here,
     * before the primary was ever touched) -- without which a tester would
     * otherwise have to race a manual file edit or a manual background/kill
     * against this method's own execution.
     *
     * [onAfterPrimaryWrite], when non-null, is invoked exactly once, after
     * the primary document has been successfully written with explicit
     * "wt" (step 8) and before readback verification, marker clearing, or
     * `commit_staged_save` (steps 9-11a). Also production-`null`-only; its
     * purpose is the third Revision 3 acceptance scenario -- process death
     * strictly *after* the physical write but *before* LocalVault could
     * verify or claim success -- so next-unlock reconciliation can be
     * proven to resolve the lingering marker as SAVED from disk truth,
     * rather than merely NOT_SAVED.
     *
     * Both hooks leave this method's behavior identical to before either
     * existed when left `null` (every real production call site, until
     * 1T-B5b deliberately wires one).
     */
    fun saveUpdateEntry(
        vaultUri: String,
        entryId: String,
        input: EntryInput,
        nowMs: Long,
        onAfterMarkerWritten: (() -> Unit)? = null,
        onAfterPrimaryWrite: (() -> Unit)? = null,
    ): SaveOutcome {
        if (!io.hasPersistedWriteGrant(vaultUri) || !io.supportsWrite(vaultUri)) {
            return SaveOutcome.ProviderNotWritable
        }

        // Step 1-2: first stale check, against the tracked baseline.
        val currentBytes =
            try {
                io.readAll(vaultUri)
            } catch (error: Exception) {
                return SaveOutcome.UnexpectedError(error)
            }
        if (Sha256.hex(currentBytes) != baselineSha256) {
            return SaveOutcome.ChangedExternally
        }

        // Step 3: stage.
        val stagedBytes =
            try {
                session.stageUpdateEntry(entryId, input, nowMs)
            } catch (error: BridgeException) {
                return SaveOutcome.ValidationFailed(error)
            }
        val expectedNewSha256 = Sha256.hex(stagedBytes)

        // Step 4-5: durable private recovery snapshot + marker. Fail closed
        // if this cannot be written and verified -- the primary is never
        // touched without it.
        val snapshotOk =
            recovery.writeAndVerify(vaultUri, currentBytes, baselineSha256, expectedNewSha256, nowMs)
        if (!snapshotOk) {
            session.discardStagedSave()
            return SaveOutcome.RecoverySnapshotFailed
        }

        // Step 6 (optional SAF sibling `.backup`) is intentionally not
        // performed here: it requires tree/parent access this app does not
        // request by default (accepted review, section 3) and is a
        // best-effort complement, never a prerequisite for a safe save.

        onAfterMarkerWritten?.invoke()

        // Step 7: second stale check, immediately before the primary write.
        val recheckBytes =
            try {
                io.readAll(vaultUri)
            } catch (error: Exception) {
                session.discardStagedSave()
                recovery.clearMarker(vaultUri)
                return SaveOutcome.UnexpectedError(error)
            }
        if (Sha256.hex(recheckBytes) != baselineSha256) {
            // LocalVault never touched the primary in this attempt: clear
            // the marker (nothing pending to reconcile) and do not offer
            // the recovery snapshot -- it reflects our now-stale view, not
            // the externally changed content.
            session.discardStagedSave()
            recovery.clearMarker(vaultUri)
            return SaveOutcome.ChangedExternally
        }

        // Step 8: the point of no return. From here, an interruption must
        // not claim an outcome -- see SaveReconciler for how the *next*
        // unlock resolves whatever happens from this point on.
        try {
            io.writeTruncated(vaultUri, stagedBytes)
        } catch (error: Exception) {
            return SaveOutcome.WriteFailed
        }

        onAfterPrimaryWrite?.invoke()

        // Step 9-10: mandatory readback verification, exact byte equality.
        val readback =
            try {
                io.readAll(vaultUri)
            } catch (error: Exception) {
                return SaveOutcome.WriteFailed
            }
        if (!readback.contentEquals(stagedBytes)) {
            return SaveOutcome.WriteFailed
        }

        // Step 11a: commit. Only now may the caller report success.
        session.commitStagedSave()
        recovery.clearMarker(vaultUri)
        baselineSha256 = expectedNewSha256

        return SaveOutcome.Success
    }
}
