package com.localvault.android

import android.content.Intent
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * `Intent.FLAG_GRANT_*` constants are plain `public static final int`
 * fields, not methods -- reading them does not hit AGP's unit-test "not
 * mocked" stub path, so this pure logic is directly testable without
 * Robolectric.
 */
class VaultGrantTest {

    @Test
    fun granted_permissions_reports_only_flags_actually_present() {
        val requestedAll =
            Intent.FLAG_GRANT_READ_URI_PERMISSION or
                Intent.FLAG_GRANT_WRITE_URI_PERMISSION or
                Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION

        val granted = grantedPermissionsFrom(requestedAll)

        assertEquals(GrantedPermissions(read = true, write = true, persistable = true), granted)
    }

    @Test
    fun provider_granting_fewer_flags_than_requested_is_reported_accurately() {
        // A provider may return read+persistable only, even though write
        // was also requested (accepted review, Revision 3, section 3) --
        // the result must reflect exactly what was granted, not the request.
        val actuallyGranted =
            Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION

        val granted = grantedPermissionsFrom(actuallyGranted)

        assertEquals(GrantedPermissions(read = true, write = false, persistable = true), granted)
    }

    @Test
    fun no_flags_granted_reports_all_false() {
        val granted = grantedPermissionsFrom(0)

        assertEquals(GrantedPermissions(read = false, write = false, persistable = false), granted)
    }

    @Test
    fun resolve_grant_is_read_write_only_when_both_confirmed_taken() {
        assertEquals(VaultGrant.READ_WRITE, resolveGrant(readTaken = true, writeTaken = true))
    }

    @Test
    fun resolve_grant_falls_back_to_read_only_if_write_persist_failed() {
        // A provider may allow the in-process grant but reject persisting
        // it (SecurityException) -- the caller must never treat that as
        // read-write.
        assertEquals(VaultGrant.READ_ONLY, resolveGrant(readTaken = true, writeTaken = false))
    }

    @Test
    fun resolve_grant_falls_back_to_read_only_if_read_persist_failed() {
        assertEquals(VaultGrant.READ_ONLY, resolveGrant(readTaken = false, writeTaken = true))
    }

    @Test
    fun resolve_grant_is_read_only_if_neither_confirmed() {
        assertEquals(VaultGrant.READ_ONLY, resolveGrant(readTaken = false, writeTaken = false))
    }
}
