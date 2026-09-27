package com.localvault.android.proof

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * [VaultCreationCoordinator.createVault] calls the real top-level
 * `beginCreateVault` function, which needs the native ARM64 Android bridge
 * `.so` -- categorically unloadable on the host JVM this test runs on. So
 * only the one path that returns *before* ever reaching that native call
 * can be exercised here; everything past it is a real-device QA item (see
 * this continuation's report on picker-ordering coverage for why the
 * ordering invariant itself -- no Rust secret state before/during a picker
 * Activity -- is not automatable at this layer either).
 */
class VaultCreationCoordinatorTest {

    @Test
    fun never_attempts_begin_create_vault_when_the_document_is_not_writable() {
        val io = FakeSafDocumentIo()
        io.writeSupported = false

        val outcome = VaultCreationCoordinator(io).createVault("content://test/doc", "password", 1_000L)

        // If beginCreateVault (native) had been attempted, this test would
        // have thrown before reaching this assertion, since no native
        // library is loaded on the host JVM -- the test passing at all is
        // itself proof the native call was never made for this input.
        assertEquals(CreateVaultOutcome.ProviderNotWritable, outcome)
    }
}
