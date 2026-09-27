package com.localvault.android.proof

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.IOException

/**
 * The small set of ContentResolver/SAF operations the save and creation
 * coordinators need. Kept as a narrow seam -- not a general virtual
 * filesystem abstraction -- so a fake implementing this interface can
 * exercise the coordinators' stale-check/verification logic in a plain JVM
 * unit test, per the accepted 1T-B5 storage/mutation architecture review's
 * test-plan guidance to avoid overengineering this boundary.
 *
 * Documents are identified by their URI *string* rather than [Uri] itself:
 * `android.net.Uri` is one of the Android-framework classes AGP's unit-test
 * stub jar throws on by default (no Robolectric is added here -- see the
 * accepted review's own guidance against overengineering this boundary), so
 * keeping it out of this interface lets every caller of it (the save and
 * creation coordinators, the reconciler) be exercised in a plain JVM test
 * with a fake. Only this concrete, ContentResolver-touching implementation
 * needs a real `Uri`, via `Uri.parse`.
 */
interface SafDocumentIo {
    /** Reads the entire current content of the document at [documentUri]. */
    fun readAll(documentUri: String): ByteArray

    /**
     * Writes [bytes] to [documentUri] using explicit truncate-write ("wt")
     * mode -- never ambiguous bare "w", whose truncate behavior is
     * provider-dependent. If the provider rejects "wt" itself, this throws;
     * callers must treat that as "this document/provider is not safely
     * writable" and fail closed, never fall back to "w".
     */
    fun writeTruncated(documentUri: String, bytes: ByteArray)

    /**
     * Whether the provider currently reports [documentUri] as supporting
     * write (`DocumentsContract.Document.FLAG_SUPPORTS_WRITE`). Always
     * queried live against the provider, never cached or assumed from a
     * stored hint.
     */
    fun supportsWrite(documentUri: String): Boolean

    /**
     * Whether a currently persisted URI permission grants live write access
     * to [documentUri]. Always queried live against
     * `ContentResolver.persistedUriPermissions`, never from any stored
     * recent-vault UX hint -- a stored flag is never an authorization
     * source (accepted review, Revision 3, sections 3, 6 and 15).
     */
    fun hasPersistedWriteGrant(documentUri: String): Boolean
}

class ContentResolverSafDocumentIo(private val context: Context) : SafDocumentIo {

    private val resolver: ContentResolver
        get() = context.contentResolver

    override fun readAll(documentUri: String): ByteArray {
        val uri = Uri.parse(documentUri)
        val stream = resolver.openInputStream(uri)
            ?: throw IOException("provider returned no input stream for $uri")
        return stream.use { it.readBytes() }
    }

    override fun writeTruncated(documentUri: String, bytes: ByteArray) {
        val uri = Uri.parse(documentUri)
        val stream = resolver.openOutputStream(uri, "wt")
            ?: throw IOException("provider returned no output stream for mode \"wt\" on $uri")
        stream.use {
            it.write(bytes)
            it.flush()
        }
    }

    override fun supportsWrite(documentUri: String): Boolean {
        val uri = Uri.parse(documentUri)
        return try {
            resolver.query(
                uri,
                arrayOf(DocumentsContract.Document.COLUMN_FLAGS),
                null,
                null,
                null,
            )?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val flags = cursor.getInt(0)
                    (flags and DocumentsContract.Document.FLAG_SUPPORTS_WRITE) != 0
                } else {
                    false
                }
            } ?: false
        } catch (ignored: Exception) {
            false
        }
    }

    override fun hasPersistedWriteGrant(documentUri: String): Boolean {
        val uri = Uri.parse(documentUri)
        return resolver.persistedUriPermissions.any { it.uri == uri && it.isWritePermission }
    }
}
