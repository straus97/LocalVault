package com.localvault.android.proof

/**
 * In-memory [RecoverySnapshotStore] fake for plain JVM unit tests. Upholds
 * the same contract the real `AtomicFile`-backed implementation must (write
 * a marker only alongside a verified snapshot; `clearMarker` never deletes
 * the snapshot; `forget` deletes both), so tests written against it exercise
 * real coordinator/reconciler logic, not fake-specific behavior.
 */
class FakeRecoverySnapshotStore : RecoverySnapshotStore {

    private val snapshots = mutableMapOf<String, ByteArray>()
    private val markers = mutableMapOf<String, RecoveryMarker>()

    /** When true, [writeAndVerify] fails as though the durable write or its
     * readback verification failed, leaving no snapshot/marker behind. */
    var failWrites: Boolean = false

    var writeAndVerifyCallCount = 0
        private set

    override fun writeAndVerify(
        vaultUri: String,
        preWriteBytes: ByteArray,
        baselineSha256: String,
        expectedNewSha256: String,
        nowMs: Long,
    ): Boolean {
        writeAndVerifyCallCount++
        if (failWrites) return false

        snapshots[vaultUri] = preWriteBytes
        markers[vaultUri] = RecoveryMarker(vaultUri, baselineSha256, expectedNewSha256, nowMs)
        return true
    }

    override fun readMarker(vaultUri: String): RecoveryMarker? = markers[vaultUri]

    override fun readSnapshotBytes(vaultUri: String): ByteArray? = snapshots[vaultUri]

    override fun clearMarker(vaultUri: String) {
        markers.remove(vaultUri)
    }

    override fun forget(vaultUri: String) {
        snapshots.remove(vaultUri)
        markers.remove(vaultUri)
    }
}
