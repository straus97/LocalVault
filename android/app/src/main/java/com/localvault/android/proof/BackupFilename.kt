package com.localvault.android.proof

/**
 * True when [displayName] matches the automatic rolling backup naming
 * convention both this app and desktop use (`<name>.backup`, e.g.
 * `LocalSave.lvault.backup`) -- the exact naming that caused a real,
 * documented QA confusion between a vault's primary and backup files.
 * Used to show an explicit warning before opening or saving to such a
 * document (accepted 1T-B5 storage/mutation architecture review, Revision
 * 3, section 7).
 */
fun isLikelyBackupFilename(displayName: String): Boolean {
    return displayName.endsWith(".backup", ignoreCase = true)
}
