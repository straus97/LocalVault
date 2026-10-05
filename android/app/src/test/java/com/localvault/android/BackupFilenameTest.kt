package com.localvault.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BackupFilenameTest {

    @Test
    fun matches_the_real_documented_backup_naming_convention() {
        assertTrue(isLikelyBackupFilename("LocalSave.lvault.backup"))
    }

    @Test
    fun matches_case_insensitively() {
        assertTrue(isLikelyBackupFilename("LocalSave.lvault.BACKUP"))
    }

    @Test
    fun does_not_match_an_ordinary_primary_vault_name() {
        assertFalse(isLikelyBackupFilename("LocalSave.lvault"))
    }

    @Test
    fun does_not_match_a_name_that_merely_contains_backup() {
        assertFalse(isLikelyBackupFilename("backup-of-my-passwords.lvault"))
    }

    @Test
    fun empty_name_is_not_a_backup() {
        assertFalse(isLikelyBackupFilename(""))
    }
}
