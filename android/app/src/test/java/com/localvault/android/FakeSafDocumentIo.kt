package com.localvault.android

import java.io.FileNotFoundException

/**
 * In-memory [SafDocumentIo] fake for plain JVM unit tests. Deliberately
 * small -- it exists only to exercise [VaultSaveCoordinator]/[RecoverySnapshotRestorer]
 * logic without a real `ContentResolver`, per the accepted 1T-B5 review's
 * guidance against overengineering this seam.
 */
class FakeSafDocumentIo(
    initialDocuments: Map<String, ByteArray> = emptyMap(),
) : SafDocumentIo {

    private val documents = initialDocuments.toMutableMap()

    var writeGrant: Boolean = true
    var writeSupported: Boolean = true
    var readException: Exception? = null
    var writeException: Exception? = null

    /** When set, [hasPersistedWriteGrant] throws this instead of returning normally. */
    var writeGrantException: Exception? = null

    /** When set, [supportsWrite] throws this instead of returning normally. */
    var writeSupportedException: Exception? = null

    /** When set, transforms the bytes actually persisted by [writeTruncated]
     * -- used to simulate a provider that silently does not honor "wt"
     * truncation, or a truncated/partial write, without needing a real
     * provider to reproduce it. */
    var writeTransform: ((ByteArray) -> ByteArray)? = null

    val writes = mutableListOf<ByteArray>()
    var readCount = 0

    /** Invoked at the start of every [readAll] call, before it returns --
     * used to inject an external change between two sequential reads. */
    var onBeforeRead: (() -> Unit)? = null

    fun setContent(documentUri: String, bytes: ByteArray) {
        documents[documentUri] = bytes
    }

    fun contentOf(documentUri: String): ByteArray? = documents[documentUri]

    override fun readAll(documentUri: String): ByteArray {
        readCount++
        onBeforeRead?.invoke()
        readException?.let { throw it }
        return documents[documentUri] ?: throw FileNotFoundException(documentUri)
    }

    override fun writeTruncated(documentUri: String, bytes: ByteArray) {
        writeException?.let { throw it }
        writes.add(bytes)
        documents[documentUri] = writeTransform?.invoke(bytes) ?: bytes
    }

    override fun supportsWrite(documentUri: String): Boolean {
        writeSupportedException?.let { throw it }
        return writeSupported
    }

    override fun hasPersistedWriteGrant(documentUri: String): Boolean {
        writeGrantException?.let { throw it }
        return writeGrant
    }
}
