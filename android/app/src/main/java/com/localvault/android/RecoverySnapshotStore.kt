package com.localvault.android

import android.content.Context
import android.util.AtomicFile
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files

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

    /**
     * The current marker for [vaultUri], or `null` **only** when its absence
     * is genuinely established (the common case: no save is in flight or
     * unresolved). A marker that exists but cannot be read or decoded is
     * never reported as `null`: implementations throw (see
     * [RecoveryMarkerUnreadableException] for the malformed case), so
     * callers can never mistake damaged recovery state for "nothing pending".
     */
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
     *
     * Idempotent when no marker exists. Returns normally only once the marker
     * is verifiably gone; if an existing marker could not be removed it
     * throws, and the caller must not treat the save/recovery as resolved.
     */
    fun clearMarker(vaultUri: String)

    /** Deletes both the snapshot and its marker entirely: the "forget
     * vault" cleanup (accepted review, Revision 3, section 7). */
    fun forget(vaultUri: String)
}

/**
 * Fail-closed "is anything unresolved for this vault": `true` when a marker
 * exists **or** when the marker state cannot be determined (an unreadable or
 * malformed marker is not evidence of a resolved save). Used by callers that
 * decide whether recovery state may be discarded (automatic eviction, the
 * forget-vault warning), which must never read an uncertain state as clean.
 */
fun RecoverySnapshotStore.hasUnresolvedMarker(vaultUri: String): Boolean =
    try {
        readMarker(vaultUri) != null
    } catch (error: Exception) {
        true
    }

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

/**
 * [saveInFlight] is true while a save's thread may still be running (see
 * `MutationOwnership.reopenBlocked`): its marker may not exist yet or may be
 * written right after the marker check, so nothing may be released or
 * forgotten for any evicted vault until it finishes.
 */
fun evictionOutcomeFor(hasUnresolvedMarker: Boolean, saveInFlight: Boolean = false): EvictionOutcome =
    if (hasUnresolvedMarker || saveInFlight) EvictionOutcome.KEEP else EvictionOutcome.RELEASE_AND_FORGET

/**
 * A recovery marker file exists but its contents could not be decoded.
 * Deliberately an [IOException] (not a null result): damaged recovery
 * metadata is an unknown state, never "no save pending". Carries no marker
 * content in its message.
 */
class RecoveryMarkerUnreadableException(cause: Throwable? = null) :
    IOException("recovery marker exists but could not be decoded", cause)

/** Encoding of a [RecoveryMarker] to and from its on-disk bytes. Separate from
 * the store so the store's read/clear logic is testable without `org.json`. */
internal interface MarkerCodec {
    fun encode(marker: RecoveryMarker): ByteArray

    /** Throws on any malformed input; must never return a partial marker. */
    fun decode(bytes: ByteArray): RecoveryMarker
}

/** The production on-disk marker format (unchanged: a flat JSON object). */
internal object JsonMarkerCodec : MarkerCodec {
    private const val FIELD_VAULT_URI = "vaultUri"
    private const val FIELD_BASELINE = "baselineSha256"
    private const val FIELD_EXPECTED_NEW = "expectedNewSha256"
    private const val FIELD_TIMESTAMP = "timestampMs"

    override fun encode(marker: RecoveryMarker): ByteArray =
        JSONObject()
            .put(FIELD_VAULT_URI, marker.vaultUri)
            .put(FIELD_BASELINE, marker.baselineSha256)
            .put(FIELD_EXPECTED_NEW, marker.expectedNewSha256)
            .put(FIELD_TIMESTAMP, marker.timestampMs)
            .toString()
            .toByteArray(Charsets.UTF_8)

    override fun decode(bytes: ByteArray): RecoveryMarker {
        val json = JSONObject(String(bytes, Charsets.UTF_8))
        return RecoveryMarker(
            vaultUri = json.getString(FIELD_VAULT_URI),
            baselineSha256 = json.getString(FIELD_BASELINE),
            expectedNewSha256 = json.getString(FIELD_EXPECTED_NEW),
            timestampMs = json.getLong(FIELD_TIMESTAMP),
        )
    }
}

/**
 * The slice of `android.util.AtomicFile` that [FileRecoverySnapshotStore]
 * uses, as a seam: the framework class is stubbed out in plain JVM unit tests,
 * and the store's absent-vs-failed and delete-verification logic below must be
 * testable against a real filesystem. Semantics are exactly AtomicFile's:
 * [readFully] throws [FileNotFoundException] when it finds no file (and
 * recovers from its own backup first), and [delete] is `void` -- it ignores
 * the results of the underlying `File.delete()` calls.
 */
internal interface AtomicBlob {
    val baseFile: File

    fun readFully(): ByteArray

    fun delete()

    fun startWrite(): FileOutputStream

    fun finishWrite(stream: FileOutputStream)

    fun failWrite(stream: FileOutputStream)
}

internal class AndroidAtomicBlob(private val file: AtomicFile) : AtomicBlob {
    override val baseFile: File get() = file.baseFile

    override fun readFully(): ByteArray = file.readFully()

    override fun delete() = file.delete()

    override fun startWrite(): FileOutputStream = file.startWrite()

    override fun finishWrite(stream: FileOutputStream) = file.finishWrite(stream)

    override fun failWrite(stream: FileOutputStream) = file.failWrite(stream)
}

class FileRecoverySnapshotStore internal constructor(
    private val directory: File,
    private val blobFor: (File) -> AtomicBlob,
    private val codec: MarkerCodec,
) : RecoverySnapshotStore {

    constructor(context: Context) : this(
        File(context.filesDir, "vault_recovery"),
        { file -> AndroidAtomicBlob(AtomicFile(file)) },
        JsonMarkerCodec,
    )

    init {
        directory.mkdirs()
    }

    private fun keyFor(vaultUri: String): String = Sha256.hex(vaultUri.toByteArray(Charsets.UTF_8))

    private fun snapshotFile(vaultUri: String) = blobFor(File(directory, "${keyFor(vaultUri)}.snapshot"))

    private fun sidecarFile(vaultUri: String) = blobFor(File(directory, "${keyFor(vaultUri)}.sidecar.json"))

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

        val marker = codec.encode(RecoveryMarker(vaultUri, baselineSha256, expectedNewSha256, nowMs))

        return atomicWrite(sidecarFile(vaultUri), marker)
    }

    /**
     * `null` only when [isDefinitelyAbsent] establishes there is no marker.
     * Every other outcome that is not a decoded marker -- a file that exists
     * but cannot be opened or read, a storage/permission failure, malformed
     * contents -- throws, so the unlock pre-open gate (which treats any
     * [readMarker] exception as unresolved recovery) can never be bypassed by
     * damaged recovery state.
     */
    override fun readMarker(vaultUri: String): RecoveryMarker? {
        val bytes = readAtomicStrict(sidecarFile(vaultUri)) ?: return null

        return try {
            codec.decode(bytes)
        } catch (error: Exception) {
            throw RecoveryMarkerUnreadableException(error)
        }
    }

    override fun readSnapshotBytes(vaultUri: String): ByteArray? = readAtomic(snapshotFile(vaultUri))

    /**
     * `AtomicFile.delete()` returns nothing and ignores the results of the
     * `File.delete()` calls it makes for its three artifacts (base, `.bak`
     * backup and `.new` temporary write file), so a failed delete is invisible
     * to it. The marker is therefore re-checked on disk afterwards: clearing
     * returns normally only when all three are verifiably gone (existence that
     * cannot be determined counts as not gone). Clearing a marker that is
     * already absent passes the same check, so it stays idempotent.
     *
     * Only this cleanup check looks at `.new`. [readMarker] deliberately does
     * not: like `AtomicFile.exists()`, it treats only base and `.bak` as a
     * committed marker, and an uncommitted `.new` is an incomplete write.
     */
    override fun clearMarker(vaultUri: String) {
        val marker = sidecarFile(vaultUri)
        marker.delete()
        if (!isDefinitelyAbsent(marker) || !isDefinitelyNotPresent(marker, NEW_SUFFIX)) {
            throw IOException("recovery marker still present after delete")
        }
    }

    override fun forget(vaultUri: String) {
        snapshotFile(vaultUri).delete()
        sidecarFile(vaultUri).delete()
    }

    private fun atomicWrite(file: AtomicBlob, bytes: ByteArray): Boolean {
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

    /** Lenient read for the snapshot: `null` for "missing or unreadable".
     * Its callers already treat both identically (restore reports
     * `SnapshotMissing`; `writeAndVerify` fails its read-back). */
    private fun readAtomic(file: AtomicBlob): ByteArray? {
        return try {
            file.readFully()
        } catch (ignored: FileNotFoundException) {
            null
        } catch (ignored: Exception) {
            null
        }
    }

    /**
     * Returns the file's bytes, `null` only if genuinely absent, and throws
     * for anything else. `AtomicFile.readFully()` first recovers from its own
     * backup file if one exists (that supported recovery is left to it, so a
     * recoverable marker is returned, never reported missing). Its
     * [FileNotFoundException] is not proof of absence on its own --
     * `FileInputStream` throws it for an existing file it cannot open
     * (permission denied, a directory, ...) -- so it is confirmed against the
     * filesystem first.
     */
    private fun readAtomicStrict(file: AtomicBlob): ByteArray? {
        return try {
            file.readFully()
        } catch (notFound: FileNotFoundException) {
            if (isDefinitelyAbsent(file)) null else throw notFound
        }
    }

    /**
     * True only when neither the base file nor `AtomicFile`'s backup of it
     * exists. [Files.notExists] is `false` when existence cannot be
     * determined, so an indeterminate state is never reported as absent. The
     * `.bak` name is `AtomicFile`'s documented backup suffix: a backup still
     * present after `readFully()` failed to restore it is a live marker
     * `AtomicFile` could not recover, not an absent one.
     */
    private fun isDefinitelyAbsent(file: AtomicBlob): Boolean =
        isDefinitelyNotPresent(file, "") && isDefinitelyNotPresent(file, BACKUP_SUFFIX)

    /** [Files.notExists] for `<base><suffix>`: false when it exists or cannot be determined. */
    private fun isDefinitelyNotPresent(file: AtomicBlob, suffix: String): Boolean =
        Files.notExists(File(file.baseFile.path + suffix).toPath())

    companion object {
        private const val BACKUP_SUFFIX = ".bak"
        private const val NEW_SUFFIX = ".new"
    }
}
