package com.localvault.android.proof

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.PendingVaultCreationInterface
import uniffi.localvault_android_bridge.VaultSession

/**
 * Exercises [VaultCreationCoordinator]'s failure/interruption branches
 * (1T-B5b-3's outcome split) against [FakeSafDocumentIo] and a
 * [FakePendingVaultCreation] substituted in place of the real
 * `beginCreateVault`/`PendingVaultCreation` -- both tied to the native ARM64
 * Android bridge `.so`, categorically unloadable on the host JVM this test
 * runs on. `PendingVaultCreationInterface.verifyAndFinalize` still declares a
 * concrete, native-backed [VaultSession] return type (mirroring the Rust
 * function's own return type), so a genuine end-to-end *success* remains
 * real-device-QA-only; every failure/interruption branch before that point,
 * and the outcome-classification boundary itself (before vs. after the
 * initial write), is exactly what this file covers.
 */
class VaultCreationCoordinatorTest {

    private val documentUri = "content://test/doc"

    /** [PendingVaultCreationInterface] fake: never able to produce a real
     * [VaultSession] (see the class doc comment above), so [verifyAndFinalize]
     * only ever throws here -- exactly the two terminal-after-write branches
     * this checkpoint needs distinguished from the two before-write ones. */
    private class FakePendingVaultCreation(
        private val initialBytes: ByteArray = ByteArray(0),
        private val initialBytesException: BridgeException? = null,
        private val verifyException: BridgeException = BridgeException.OperationFailed(),
    ) : PendingVaultCreationInterface {
        var discardCount = 0
            private set

        override fun discard() {
            discardCount++
        }

        override fun initialEnvelopeBytes(): ByteArray {
            initialBytesException?.let { throw it }
            return initialBytes
        }

        override fun verifyAndFinalize(readbackBytes: ByteArray): VaultSession {
            throw verifyException
        }
    }

    @Test
    fun never_attempts_begin_create_vault_when_the_document_is_not_writable() {
        val io = FakeSafDocumentIo()
        io.writeSupported = false
        var beginCalled = false

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> beginCalled = true; error("must not be called") })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.ProviderNotWritable, outcome)
        assertTrue(!beginCalled)
        assertTrue(io.writes.isEmpty())
    }

    /**
     * Mirrors [VaultSaveCoordinator]'s identical double check for the
     * ordinary save path: a live `supportsWrite` alone is not enough --
     * the durable persisted write grant can have vanished independently
     * (revoked via system settings, provider grant lifecycle, ...) between
     * the picker's own grant-intersection check and this call.
     */
    @Test
    fun never_attempts_begin_create_vault_when_the_persisted_write_grant_is_missing() {
        val io = FakeSafDocumentIo()
        io.writeGrant = false
        var beginCalled = false

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> beginCalled = true; error("must not be called") })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.ProviderNotWritable, outcome)
        assertTrue(!beginCalled)
        assertTrue(io.writes.isEmpty())
    }

    @Test
    fun begin_create_vault_failure_maps_to_validation_failed_before_write_with_no_pending_state() {
        val io = FakeSafDocumentIo()
        val error = BridgeException.InvalidInput()

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> throw error })
                .createVault(documentUri, "", 1_000L)

        assertEquals(CreateVaultOutcome.ValidationFailedBeforeWrite(error), outcome)
        assertTrue(io.writes.isEmpty())
    }

    @Test
    fun initial_envelope_bytes_failure_discards_pending_and_maps_to_validation_failed_before_write() {
        val io = FakeSafDocumentIo()
        val error = BridgeException.OperationFailed()
        val pending = FakePendingVaultCreation(initialBytesException = error)

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> pending })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.ValidationFailedBeforeWrite(error), outcome)
        assertEquals(1, pending.discardCount)
        assertTrue(io.writes.isEmpty())
    }

    @Test
    fun write_failure_discards_pending_and_is_terminal() {
        val io = FakeSafDocumentIo()
        io.writeException = java.io.IOException("provider refused the write")
        val pending = FakePendingVaultCreation(initialBytes = "envelope".toByteArray())

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> pending })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.WriteFailed, outcome)
        assertEquals(1, pending.discardCount)
    }

    @Test
    fun readback_failure_after_a_successful_write_discards_pending_and_is_terminal() {
        val io = FakeSafDocumentIo()
        io.readException = java.io.IOException("provider lost the document")
        val pending = FakePendingVaultCreation(initialBytes = "envelope".toByteArray())

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> pending })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.WriteFailed, outcome)
        assertEquals(1, pending.discardCount)
        assertEquals(1, io.writes.size)
    }

    @Test
    fun verify_and_finalize_operation_failed_after_a_real_write_is_write_failed_not_validation_failed() {
        val io = FakeSafDocumentIo()
        val pending =
            FakePendingVaultCreation(
                initialBytes = "envelope".toByteArray(),
                verifyException = BridgeException.OperationFailed(),
            )

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> pending })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.WriteFailed, outcome)
    }

    @Test
    fun verify_and_finalize_rejection_after_a_real_write_is_distinguishable_from_a_before_write_failure() {
        val io = FakeSafDocumentIo()
        val error = BridgeException.AuthenticationFailed()
        val pending = FakePendingVaultCreation(initialBytes = "envelope".toByteArray(), verifyException = error)

        val outcome =
            VaultCreationCoordinator(io, beginCreation = { _, _ -> pending })
                .createVault(documentUri, "password", 1_000L)

        assertEquals(CreateVaultOutcome.ValidationFailedAfterWrite(error), outcome)
        assertTrue(outcome !is CreateVaultOutcome.ValidationFailedBeforeWrite)
    }

    @Test
    fun on_pending_created_hook_fires_exactly_once_before_any_document_write() {
        val io = FakeSafDocumentIo()
        val pending = FakePendingVaultCreation(initialBytes = "envelope".toByteArray())
        var hookCallCount = 0
        var writesAtHookTime = -1
        var capturedPending: PendingVaultCreationInterface? = null

        VaultCreationCoordinator(io, beginCreation = { _, _ -> pending }).createVault(
            documentUri,
            "password",
            1_000L,
            onPendingCreated = {
                hookCallCount++
                writesAtHookTime = io.writes.size
                capturedPending = it
            },
        )

        assertEquals(1, hookCallCount)
        assertEquals(0, writesAtHookTime)
        assertEquals(pending, capturedPending)
        assertEquals(1, io.writes.size)
    }

    @Test
    fun on_after_initial_write_hook_fires_only_after_the_write_and_before_verify_and_finalize() {
        val io = FakeSafDocumentIo()
        val calls = mutableListOf<String>()
        val pending =
            object : PendingVaultCreationInterface {
                override fun discard() {}

                override fun initialEnvelopeBytes(): ByteArray {
                    calls += "initialEnvelopeBytes"
                    return "envelope".toByteArray()
                }

                override fun verifyAndFinalize(readbackBytes: ByteArray): VaultSession {
                    calls += "verifyAndFinalize"
                    throw BridgeException.OperationFailed()
                }
            }

        VaultCreationCoordinator(io, beginCreation = { _, _ -> pending }).createVault(
            documentUri,
            "password",
            1_000L,
            onAfterInitialWrite = { calls += "onAfterInitialWrite" },
        )

        assertEquals(listOf("initialEnvelopeBytes", "onAfterInitialWrite", "verifyAndFinalize"), calls)
    }
}
