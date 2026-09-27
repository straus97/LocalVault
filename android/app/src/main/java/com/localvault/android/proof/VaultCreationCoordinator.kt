package com.localvault.android.proof

import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.PendingVaultCreationInterface
import uniffi.localvault_android_bridge.VaultSession
import uniffi.localvault_android_bridge.beginCreateVault

/**
 * Outcome of one [VaultCreationCoordinator] attempt.
 *
 * [ValidationFailedBeforeWrite] and [ValidationFailedAfterWrite] are
 * deliberately distinct (1T-B5b-3): the former means no document write was
 * ever attempted in this call (the document and persisted grant are still
 * exactly as the caller left them, so the same attempt may safely retry
 * against the same document), the latter means the initial ciphertext has
 * already been physically written and read back, so retrying against this
 * document/candidate is not safe -- the caller must abandon it via the
 * shared abort-cleanup procedure.
 */
sealed class CreateVaultOutcome {
    data class Success(val session: VaultSession) : CreateVaultOutcome()
    object ProviderNotWritable : CreateVaultOutcome()
    data class ValidationFailedBeforeWrite(val error: BridgeException) : CreateVaultOutcome()
    data class ValidationFailedAfterWrite(val error: BridgeException) : CreateVaultOutcome()
    object WriteFailed : CreateVaultOutcome()
    data class UnexpectedError(val error: Exception) : CreateVaultOutcome()
}

/**
 * Performs steps 7-12 of the accepted 1T-B5 vault-creation flow (storage/
 * mutation architecture review, Revision 3, section 9) -- everything from
 * `begin_create_vault` onward, for a document [documentUri] that
 * `ACTION_CREATE_DOCUMENT` has already returned.
 *
 * Steps 1-6 (launching the picker, and collecting the master password only
 * after it returns) are deliberately the caller's responsibility and are
 * NOT part of this class: the whole point of the accepted reorder is that
 * no Rust secret state (a `PendingVaultCreation`, a Vault Key, an in-flight
 * master password) is ever constructed before or during that picker
 * Activity, which the existing immediate-lock invariant could otherwise
 * zeroize mid-flight. This class must only ever be invoked after the
 * picker has already returned and the app is foreground again.
 *
 * [beginCreation] defaults to the real top-level bridge call; a test
 * substitutes a fake returning [PendingVaultCreationInterface] (the
 * interface UniFFI generates alongside the concrete, native-backed
 * `PendingVaultCreation`), the same substitution pattern
 * [VaultSaveCoordinator] already uses for [uniffi.localvault_android_bridge.VaultSessionInterface].
 * `verifyAndFinalize`'s success path still returns a concrete, native-backed
 * `VaultSession` (mirroring the Rust function's own return type), so it
 * remains impossible to fake a true end-to-end success at the JVM level --
 * only the failure/interruption branches before that point are
 * substitutable, which is exactly the coverage this checkpoint's test plan
 * calls for.
 */
class VaultCreationCoordinator(
    private val io: SafDocumentIo,
    private val beginCreation: (String, Long) -> PendingVaultCreationInterface =
        { password, nowMs -> beginCreateVault(password, nowMs) },
) {

    /**
     * [onPendingCreated], when non-null, is invoked exactly once, immediately
     * after [beginCreation] returns a live [PendingVaultCreationInterface] and
     * before any further step. Production callers use this only to let the
     * caller (`MainActivity`) hold a reference so it can call `.discard()`
     * synchronously and immediately from `onStop` if the app backgrounds
     * while this call is still in flight -- this class performs no
     * threading or lifecycle handling of its own (see the class doc comment
     * and [VaultSaveCoordinator]'s identical bare-`Thread` convention), so
     * without this hook the caller would have no way to reach the pending
     * state at all until this synchronous call returns.
     *
     * [onAfterInitialWrite], when non-null, is invoked exactly once, after
     * the initial ciphertext has been physically written (`io.writeTruncated`)
     * and before the mandatory readback/verification. Production callers
     * must leave this `null`; it exists solely for deterministic real-device
     * QA fault injection (mirroring [VaultSaveCoordinator]'s
     * `onAfterPrimaryWrite`), gated entirely by the caller's own real
     * `ApplicationInfo.FLAG_DEBUGGABLE` check -- this class does not gate it
     * itself.
     */
    fun createVault(
        documentUri: String,
        masterPassword: String,
        nowMs: Long,
        onPendingCreated: ((PendingVaultCreationInterface) -> Unit)? = null,
        onAfterInitialWrite: (() -> Unit)? = null,
    ): CreateVaultOutcome {
        // Both the durable persisted write grant and the provider's live
        // write capability must hold immediately before beginCreation --
        // mirroring VaultSaveCoordinator's identical double check for the
        // ordinary transactional save path. A persisted grant can vanish
        // between the picker's grant-intersection check and this call (the
        // user revoking it via system settings, the provider's own grant
        // lifecycle, etc.); relying on supportsWrite alone would let a
        // vault be written, verified and recorded READ_WRITE after its
        // durable write authorization had already disappeared.
        if (!io.hasPersistedWriteGrant(documentUri) || !io.supportsWrite(documentUri)) {
            return CreateVaultOutcome.ProviderNotWritable
        }

        val pending =
            try {
                beginCreation(masterPassword, nowMs)
            } catch (error: BridgeException) {
                return CreateVaultOutcome.ValidationFailedBeforeWrite(error)
            }

        onPendingCreated?.invoke(pending)

        val initialBytes =
            try {
                pending.initialEnvelopeBytes()
            } catch (error: BridgeException) {
                safeDiscard(pending)
                return CreateVaultOutcome.ValidationFailedBeforeWrite(error)
            }

        try {
            io.writeTruncated(documentUri, initialBytes)
        } catch (error: Exception) {
            safeDiscard(pending)
            return CreateVaultOutcome.WriteFailed
        }

        onAfterInitialWrite?.invoke()

        val readback =
            try {
                io.readAll(documentUri)
            } catch (error: Exception) {
                safeDiscard(pending)
                return CreateVaultOutcome.WriteFailed
            }

        // verify_and_finalize consumes `pending` on both success and
        // failure (see the bridge's own doc comment), so no extra discard()
        // is needed in either branch below.
        return try {
            CreateVaultOutcome.Success(pending.verifyAndFinalize(readback))
        } catch (error: BridgeException.OperationFailed) {
            CreateVaultOutcome.WriteFailed
        } catch (error: BridgeException) {
            CreateVaultOutcome.ValidationFailedAfterWrite(error)
        }
    }

    /**
     * Best-effort discard that tolerates the caller (`MainActivity`, via
     * `onPendingCreated`) having already discarded this same [pending]
     * concurrently on an onStop/onDestroy-driven abandonment race. The
     * bridge documents its own `discard()` as idempotent, so a second call
     * is expected to be a safe no-op regardless; this wrapper exists so
     * that even an unexpected exception from that call can never escape and
     * replace the already-decided terminal/retryable outcome above with a
     * misleading one.
     */
    private fun safeDiscard(pending: PendingVaultCreationInterface) {
        try {
            pending.discard()
        } catch (ignored: Throwable) {
        }
    }
}
