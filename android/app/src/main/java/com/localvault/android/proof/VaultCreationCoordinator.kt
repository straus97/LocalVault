package com.localvault.android.proof

import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.VaultSession
import uniffi.localvault_android_bridge.beginCreateVault

/** Outcome of one [VaultCreationCoordinator] attempt. */
sealed class CreateVaultOutcome {
    data class Success(val session: VaultSession) : CreateVaultOutcome()
    object ProviderNotWritable : CreateVaultOutcome()
    data class ValidationFailed(val error: BridgeException) : CreateVaultOutcome()
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
 */
class VaultCreationCoordinator(private val io: SafDocumentIo) {

    fun createVault(documentUri: String, masterPassword: String, nowMs: Long): CreateVaultOutcome {
        if (!io.supportsWrite(documentUri)) {
            return CreateVaultOutcome.ProviderNotWritable
        }

        val pending =
            try {
                beginCreateVault(masterPassword, nowMs)
            } catch (error: BridgeException) {
                return CreateVaultOutcome.ValidationFailed(error)
            }

        val initialBytes =
            try {
                pending.initialEnvelopeBytes()
            } catch (error: BridgeException) {
                pending.discard()
                return CreateVaultOutcome.ValidationFailed(error)
            }

        try {
            io.writeTruncated(documentUri, initialBytes)
        } catch (error: Exception) {
            pending.discard()
            return CreateVaultOutcome.WriteFailed
        }

        val readback =
            try {
                io.readAll(documentUri)
            } catch (error: Exception) {
                pending.discard()
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
            CreateVaultOutcome.ValidationFailed(error)
        }
    }
}
