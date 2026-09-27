package com.localvault.android.proof

import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.CategoryInput
import uniffi.localvault_android_bridge.CategorySummary
import uniffi.localvault_android_bridge.EntryDetails
import uniffi.localvault_android_bridge.EntryInput
import uniffi.localvault_android_bridge.EntrySummary
import uniffi.localvault_android_bridge.TotpStatus
import uniffi.localvault_android_bridge.VaultSessionInterface

/**
 * [VaultSessionInterface] fake for plain JVM unit tests. `VaultSession`
 * itself is a UniFFI-generated object backed by the native bridge library
 * (an ARM64 Android `.so`, unloadable on the host JVM this test runs on),
 * so [VaultSaveCoordinator] depends on the interface specifically to allow
 * this substitution -- no native code, no `.so`, is ever touched by these
 * tests.
 */
class FakeVaultSession(
    private val stagedBytes: ByteArray = ByteArray(0),
    private val stageException: BridgeException? = null,
    private val onStage: (() -> Unit)? = null,
) : VaultSessionInterface {

    var stageCount = 0
        private set
    var commitCount = 0
        private set
    var discardCount = 0
        private set

    /** Which `stage*` method(s) were actually invoked, in call order --
     * used to prove a [VaultSaveCoordinator] wrapper reaches exactly the
     * one bridge call it names, not some other mutation. */
    val stagedMethodCalls = mutableListOf<String>()

    /** Shared by every `stage*` override below: records which method was
     * called, applies the configured exception/hook, and returns the
     * configured bytes -- only one of these is ever invoked per save
     * attempt, so a single shared [stagedBytes]/[stageException]/[onStage]
     * configuration is sufficient for all six. */
    private fun stage(methodName: String): ByteArray {
        stageCount++
        stagedMethodCalls += methodName
        stageException?.let { throw it }
        onStage?.invoke()
        return stagedBytes
    }

    override fun commitStagedSave() {
        commitCount++
    }

    override fun discardStagedSave() {
        discardCount++
    }

    override fun entryDetails(entryId: String): EntryDetails = throw UnsupportedOperationException()

    override fun entryPassword(entryId: String): String = throw UnsupportedOperationException()

    override fun listCategories(): List<CategorySummary> = emptyList()

    override fun listEntries(): List<EntrySummary> = emptyList()

    override fun lock() {}

    override fun stageUpdateEntry(entryId: String, input: EntryInput, nowMs: Long): ByteArray =
        stage("stageUpdateEntry")

    override fun stageCreateEntry(input: EntryInput, nowMs: Long): ByteArray =
        stage("stageCreateEntry")

    override fun stageDeleteEntry(entryId: String, nowMs: Long): ByteArray =
        stage("stageDeleteEntry")

    override fun stageCreateCategory(input: CategoryInput, nowMs: Long): ByteArray =
        stage("stageCreateCategory")

    override fun stageUpdateCategory(categoryId: String, input: CategoryInput, nowMs: Long): ByteArray =
        stage("stageUpdateCategory")

    override fun stageDeleteCategory(categoryId: String, nowMs: Long): ByteArray =
        stage("stageDeleteCategory")

    override fun totpStatus(entryId: String, unixTimeSeconds: Long): TotpStatus =
        throw UnsupportedOperationException()
}
