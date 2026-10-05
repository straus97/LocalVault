package com.localvault.android

import android.content.ContentResolver
import android.content.Intent
import android.net.Uri

/**
 * UX-only hint about whether a recent vault is believed writable, persisted
 * in [RecentVaultStore]. Never an authorization source: every write attempt
 * independently re-validates via [SafDocumentIo.hasPersistedWriteGrant] and
 * [SafDocumentIo.supportsWrite] regardless of this value (accepted 1T-B5
 * storage/mutation architecture review, Revision 3, sections 3, 6 and 15).
 */
enum class VaultGrant {
    READ_ONLY,
    READ_WRITE,
}

/**
 * The permission flags a picker result's `Intent` actually reports, as
 * opposed to what an outgoing `ACTION_OPEN_DOCUMENT`/`ACTION_CREATE_DOCUMENT`
 * intent requested. A provider may grant fewer permissions than requested;
 * this must never be assumed equal to the request (accepted review, Revision
 * 3, section 3).
 */
data class GrantedPermissions(val read: Boolean, val write: Boolean, val persistable: Boolean)

fun grantedPermissionsFrom(resultFlags: Int): GrantedPermissions {
    return GrantedPermissions(
        read = (resultFlags and Intent.FLAG_GRANT_READ_URI_PERMISSION) != 0,
        write = (resultFlags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION) != 0,
        persistable = (resultFlags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION) != 0,
    )
}

/**
 * Takes only the persistable permissions [granted] actually reports, one
 * flag at a time, catching `SecurityException` per flag so a provider that
 * allows the in-process grant but rejects persisting it never silently
 * looks successful. Returns the [VaultGrant] this process can actually rely
 * on being persisted across restarts -- [VaultGrant.READ_WRITE] only if both
 * the read and write persistable grants were actually confirmed.
 */
fun takeGrantedPersistablePermissions(
    contentResolver: ContentResolver,
    uri: Uri,
    granted: GrantedPermissions,
): VaultGrant {
    if (!granted.persistable) {
        return VaultGrant.READ_ONLY
    }

    val readTaken = granted.read && tryTakePersistable(contentResolver, uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
    val writeTaken = granted.write && tryTakePersistable(contentResolver, uri, Intent.FLAG_GRANT_WRITE_URI_PERMISSION)

    return resolveGrant(readTaken, writeTaken)
}

/**
 * Pure decision: [VaultGrant.READ_WRITE] only if both persistable
 * permissions were actually confirmed taken, never merely requested.
 * Factored out of [takeGrantedPersistablePermissions] so this decision is
 * unit-testable without a real `ContentResolver`.
 */
fun resolveGrant(readTaken: Boolean, writeTaken: Boolean): VaultGrant {
    return if (readTaken && writeTaken) VaultGrant.READ_WRITE else VaultGrant.READ_ONLY
}

private fun tryTakePersistable(contentResolver: ContentResolver, uri: Uri, flag: Int): Boolean {
    return try {
        contentResolver.takePersistableUriPermission(uri, flag)
        true
    } catch (ignored: SecurityException) {
        false
    }
}
