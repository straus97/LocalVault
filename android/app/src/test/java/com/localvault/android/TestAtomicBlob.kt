package com.localvault.android

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Real-filesystem stand-in for `android.util.AtomicFile` (which is stubbed out
 * in plain JVM unit tests), following the framework class's documented
 * semantics: three artifacts (base, legacy `<base>.bak`, temporary
 * `<base>.new`); a write goes to `.new` and replaces the base only on
 * `finishWrite`; `readFully` first restores a leftover `.bak` over the base
 * file, then reads the base file (never `.new`) and throws
 * [java.io.FileNotFoundException] if it cannot open it; and `delete` is `void`
 * and ignores the results of its `File.delete()` calls on all three.
 *
 * Everything the store does on top of this -- distinguishing absent from
 * unreadable, verifying that a delete took effect -- runs for real against
 * files in a test-owned directory. The only injectable faults are ones the
 * real filesystem cannot produce portably.
 */
internal class TestAtomicBlob(override val baseFile: File) : AtomicBlob {

    private val backup = File(baseFile.path + ".bak")
    private val newFile = File(baseFile.path + ".new")

    /** Models `AtomicFile`'s `File.renameTo(...)` failing silently when it
     * tries to restore a leftover backup. */
    var restoreFromBackupFails = false

    /** Models `AtomicFile.delete()` silently failing to remove anything. */
    var deleteIsIneffective = false

    /** When set, [readFully] throws this instead of reading (a storage or
     * permission failure other than file-not-found). */
    var readFailure: Throwable? = null

    override fun readFully(): ByteArray {
        readFailure?.let { throw it }
        if (backup.exists()) {
            baseFile.delete()
            if (!restoreFromBackupFails) backup.renameTo(baseFile)
        }
        return FileInputStream(baseFile).use { it.readBytes() }
    }

    override fun delete() {
        if (deleteIsIneffective) return
        baseFile.delete()
        backup.delete()
        newFile.delete()
    }

    // Writes go to the temporary `.new` file; the base file is replaced only
    // by finishWrite, so a write that never finishes leaves an uncommitted
    // `.new` and an intact base. (Reads still honor a leftover legacy `.bak`.)
    override fun startWrite(): FileOutputStream {
        newFile.delete()
        return FileOutputStream(newFile)
    }

    override fun finishWrite(stream: FileOutputStream) {
        stream.flush()
        stream.fd.sync()
        stream.close()
        backup.delete()
        baseFile.delete()
        if (!newFile.renameTo(baseFile)) throw IOException("could not commit new file")
    }

    override fun failWrite(stream: FileOutputStream) {
        stream.close()
        newFile.delete()
    }
}

/**
 * Strict stand-in for the JSON marker codec (`org.json` is stubbed out in
 * plain JVM unit tests): four `|`-separated fields, anything else throws.
 * What this does and does not cover is stated in
 * [FileRecoverySnapshotStoreTest].
 */
internal object TestMarkerCodec : MarkerCodec {
    override fun encode(marker: RecoveryMarker): ByteArray =
        "${marker.vaultUri}|${marker.baselineSha256}|${marker.expectedNewSha256}|${marker.timestampMs}"
            .toByteArray(Charsets.UTF_8)

    override fun decode(bytes: ByteArray): RecoveryMarker {
        val parts = String(bytes, Charsets.UTF_8).split("|")
        require(parts.size == 4) { "malformed marker" }
        return RecoveryMarker(parts[0], parts[1], parts[2], parts[3].toLong())
    }
}
