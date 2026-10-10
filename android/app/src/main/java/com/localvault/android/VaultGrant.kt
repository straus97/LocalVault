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

/**
 * UX hint for a vault whose live write availability is [writeAvailable]. Only
 * ever derived from a live permission/provider check, never the other way
 * around: the hint is not an authorization source.
 */
fun grantHintFor(writeAvailable: Boolean): VaultGrant =
    if (writeAvailable) VaultGrant.READ_WRITE else VaultGrant.READ_ONLY

/**
 * Hint stored when an existing vault is (re)opened through the read-only
 * picker or selected from history: it follows whether a persisted WRITE
 * grant still exists, so a vault that was already upgraded is not blindly
 * downgraded back to [VaultGrant.READ_ONLY]. No provider I/O is implied --
 * provider capability is re-checked at unlock and at every save.
 */
fun reopenGrantHint(hasPersistedWriteGrant: Boolean): VaultGrant = grantHintFor(hasPersistedWriteGrant)

/**
 * Whether an unlocked vault must be treated as read-only: either check
 * failing (or throwing, which callers map to `false`) means no save can
 * succeed. Fail closed.
 */
fun isVaultReadOnly(hasPersistedWriteGrant: Boolean, providerSupportsWrite: Boolean): Boolean =
    !(hasPersistedWriteGrant && providerSupportsWrite)

/**
 * "Enable editing" must upgrade exactly the document it was launched for.
 * Compared on the URI string (the same identity [RecentVaultStore] uses).
 * Two different URIs are never assumed to name the same physical file, and a
 * missing request (e.g. lost across process death) cannot be verified, so it
 * is rejected too.
 */
fun isRequestedDocument(requestedUri: String?, returnedUri: String?): Boolean =
    requestedUri != null && returnedUri != null && requestedUri == returnedUri

/** How a picker result relates to the pending "Enable editing" request. */
enum class EnableEditingTargetCheck {
    /** Exactly the requested document. */
    MATCH,

    /** A different document (strict URI inequality). */
    MISMATCH,

    /** The request itself was lost (e.g. Activity recreated without it): unverifiable, fail closed. */
    LOST,
}

fun checkEnableEditingTarget(requestedUri: String?, returnedUri: String?): EnableEditingTargetCheck =
    when {
        requestedUri == null -> EnableEditingTargetCheck.LOST
        isRequestedDocument(requestedUri, returnedUri) -> EnableEditingTargetCheck.MATCH
        else -> EnableEditingTargetCheck.MISMATCH
    }

/**
 * The document URI an outstanding "Enable editing" picker was launched for.
 * Holds one non-secret string; [snapshot]/[restore] let it survive Activity
 * recreation through saved instance state (never durable preferences). It
 * carries no session, key or form state.
 */
class PendingEnableEditingTarget {
    private var uri: String? = null

    fun begin(requestedUri: String) {
        uri = requestedUri
    }

    /** The value to write into saved instance state, or null when no request is pending. */
    fun snapshot(): String? = uri

    fun restore(saved: String?) {
        uri = saved
    }

    /** Returns the pending target and clears it, so a result is validated at most once. */
    fun consume(): String? {
        val current = uri
        uri = null
        return current
    }
}

enum class EnableEditingOutcome {
    /** Persisted READ+WRITE confirmed and the provider reports write support. */
    ENABLED,

    /** The picker/provider did not give (or would not persist) both grants. */
    NOT_GRANTED,

    /** Grants were persisted but the provider does not support writing this document. */
    PROVIDER_NOT_WRITABLE,
}

fun enableEditingOutcome(takenGrant: VaultGrant, providerSupportsWrite: Boolean): EnableEditingOutcome =
    when {
        takenGrant != VaultGrant.READ_WRITE -> EnableEditingOutcome.NOT_GRANTED
        !providerSupportsWrite -> EnableEditingOutcome.PROVIDER_NOT_WRITABLE
        else -> EnableEditingOutcome.ENABLED
    }

private fun tryTakePersistable(contentResolver: ContentResolver, uri: Uri, flag: Int): Boolean {
    return try {
        contentResolver.takePersistableUriPermission(uri, flag)
        true
    } catch (ignored: SecurityException) {
        false
    }
}
