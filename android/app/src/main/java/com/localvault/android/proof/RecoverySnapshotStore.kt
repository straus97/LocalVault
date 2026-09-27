package com.localvault.android.proof

import android.content.Context
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException

/**
 * Durable record of one in-flight or unresolved save attempt for a vault
 * URI: the baseline hash the save started from, and the hash the primary is
 * expected to have if the save actually completed. Ciphertext-adjacent
 * metadata only -- no plaintext, no keys.
 */
data class RecoveryMarker(
    val vaultUri: String,
    val baselineSha256: String,
    val expectedNewSha256: String,
    val timestampMs: Long,
)

/**
 * Durable, ciphertext-only pre-write recovery data for one vault URI
 * (identified by its URI string -- see [SafDocumentIo]'s doc comment for
 * why `android.net.Uri` itself is kept out of this interface), kept in
 * app-private persistent storage (never cache -- see the accepted 1T-B5
 * storage/mutation architecture review, Revision 3, sections 4 and 7, for
 * why a cache-backed fallback is not an acceptable sole recovery guarantee).
 *
 * At most one snapshot and one marker exist per vault URI at a time. The
 * snapshot is never the authoritative vault and is never listed as an
 * openable document.
 */
interface RecoverySnapshotStore {
    /**
     * Durably writes [preWriteBytes] and reads them back to verify, then
     * records an unresolved marker for [baselineSha256]/[expectedNewSha256].
     * Returns `false` (leaving no snapshot/marker in place) if the write or
     * its verification failed -- callers must fail closed in that case and
     * never touch the primary document.
     */
    fun writeAndVerify(
        vaultUri: String,
        preWriteBytes: ByteArray,
        baselineSha256: String,
        expectedNewSha256: String,
        nowMs: Long,
    ): Boolean

    /** The current marker for [vaultUri], or `null` if none exists (the
     * common case: no save is in flight or unresolved). */
    fun readMarker(vaultUri: String): RecoveryMarker?

    /** The snapshot's ciphertext bytes, or `null` if none exists. */
    fun readSnapshotBytes(vaultUri: String): ByteArray?

    /**
     * Removes the marker for [vaultUri] without deleting the snapshot
     * itself. Used both when a save completes successfully (the marker's
     * job is done; the snapshot is left in place, to be superseded by the
     * next save's snapshot) and when a save is cleanly aborted before ever
     * touching the primary (the second-stale-check abort path, accepted
     * review Revision 3 section 4 step 7b) -- in both cases nothing is left
     * unresolved.
     */
    fun clearMarker(vaultUri: String)

    /** Deletes both the snapshot and its marker entirely: the "forget
     * vault" cleanup (accepted review, Revision 3, section 7). */
    fun forget(vaultUri: String)
}

fun RecoverySnapshotStore.hasUnresolvedMarker(vaultUri: String): Boolean = readMarker(vaultUri) != null

/**
 * What to do with an automatically-evicted recent-vault entry's persisted
 * SAF grant and recovery state (post-B5a-QA fix: an automatic eviction --
 * e.g. the recent list's 5-item cap pushing out its oldest entry -- carries
 * no user intent to relinquish the vault, unlike explicit "forget", and has
 * no dialog opportunity to warn about an unresolved save. It must therefore
 * never destroy recovery state a genuinely unresolved save still depends
 * on, even though leaving an ordinary (resolved) vault's recovery state
 * around forever would otherwise orphan it with no other cleanup path).
 */
enum class EvictionOutcome {
    /** No save is unresolved for this vault: safe to release its grant and
     * delete its recovery snapshot/marker, exactly like explicit forget's
     * no-warning branch. */
    RELEASE_AND_FORGET,

    /** An unresolved save exists for this vault: leave its grant and
     * recovery state untouched so it remains reachable and reconcilable
     * even though it no longer appears in the recent list. */
    KEEP,
}

fun evictionOutcomeFor(hasUnresolvedMarker: Boolean): EvictionOutcome =
    if (hasUnresolvedMarker) EvictionOutcome.KEEP else EvictionOutcome.RELEASE_AND_FORGET

class FileRecoverySnapshotStore(context: Context) : RecoverySnapshotStore {

    private val directory: File = File(context.filesDir, "vault_recovery").apply { mkdirs() }

    private fun keyFor(vaultUri: String): String = Sha256.hex(vaultUri.toByteArray(Charsets.UTF_8))

    private fun snapshotFile(vaultUri: String) = AtomicFile(File(directory, "${keyFor(vaultUri)}.snapshot"))

    private fun sidecarFile(vaultUri: String) = AtomicFile(File(directory, "${keyFor(vaultUri)}.sidecar.json"))

    override fun writeAndVerify(
        vaultUri: String,
        preWriteBytes: ByteArray,
        baselineSha256: String,
        expectedNewSha256: String,
        nowMs: Long,
    ): Boolean {
        if (!atomicWrite(snapshotFile(vaultUri), preWriteBytes)) {
            return false
        }

        val readBack = readAtomic(snapshotFile(vaultUri)) ?: return false
        if (!readBack.contentEquals(preWriteBytes)) {
            return false
        }

        val marker =
            JSONObject()
                .put(FIELD_VAULT_URI, vaultUri)
                .put(FIELD_BASELINE, baselineSha256)
                .put(FIELD_EXPECTED_NEW, expectedNewSha256)
                .put(FIELD_TIMESTAMP, nowMs)
                .toString()
                .toByteArray(Charsets.UTF_8)

        return atomicWrite(sidecarFile(vaultUri), marker)
    }

    override fun readMarker(vaultUri: String): RecoveryMarker? {
        val bytes = readAtomic(sidecarFile(vaultUri)) ?: return null

        return try {
            val json = JSONObject(String(bytes, Charsets.UTF_8))
            RecoveryMarker(
                vaultUri = json.getString(FIELD_VAULT_URI),
                baselineSha256 = json.getString(FIELD_BASELINE),
                expectedNewSha256 = json.getString(FIELD_EXPECTED_NEW),
                timestampMs = json.getLong(FIELD_TIMESTAMP),
            )
        } catch (ignored: Exception) {
            null
        }
    }

    override fun readSnapshotBytes(vaultUri: String): ByteArray? = readAtomic(snapshotFile(vaultUri))

    override fun clearMarker(vaultUri: String) {
        sidecarFile(vaultUri).delete()
    }

    override fun forget(vaultUri: String) {
        snapshotFile(vaultUri).delete()
        sidecarFile(vaultUri).delete()
    }

    private fun atomicWrite(file: AtomicFile, bytes: ByteArray): Boolean {
        val stream =
            try {
                file.startWrite()
            } catch (ignored: Exception) {
                return false
            }

        return try {
            stream.write(bytes)
            file.finishWrite(stream)
            true
        } catch (error: Exception) {
            file.failWrite(stream)
            false
        }
    }

    private fun readAtomic(file: AtomicFile): ByteArray? {
        return try {
            file.readFully()
        } catch (ignored: FileNotFoundException) {
            null
        } catch (ignored: Exception) {
            null
        }
    }

    companion object {
        private const val FIELD_VAULT_URI = "vaultUri"
        private const val FIELD_BASELINE = "baselineSha256"
        private const val FIELD_EXPECTED_NEW = "expectedNewSha256"
        private const val FIELD_TIMESTAMP = "timestampMs"
    }
}
