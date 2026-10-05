package com.localvault.android

import java.security.MessageDigest

/**
 * Hex-encoded SHA-256 of raw bytes.
 *
 * Per the accepted 1T-B5 storage/mutation architecture review (Revision 3,
 * section 6), the exact SHA-256 of a vault document's raw encrypted bytes --
 * not envelope-struct equality, and not SAF metadata such as size or
 * last-modified time -- is the authoritative signal for "has the source
 * changed since I last saw it". This object is used for that check and
 * nowhere else; it never touches plaintext.
 */
object Sha256 {
    fun hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val builder = StringBuilder(digest.size * 2)
        for (byte in digest) {
            builder.append(String.format("%02x", byte))
        }
        return builder.toString()
    }
}
