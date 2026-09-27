package com.localvault.android.proof

import android.content.Context
import android.net.Uri
import org.json.JSONArray
import org.json.JSONObject

/**
 * One remembered vault: NON-SECRET metadata only (document Uri, display
 * name, and a UX-only write-grant hint).
 *
 * [grant] is never an authorization source -- it exists only so the UI can
 * decide whether to offer "Enable editing" without a synchronous permission
 * check on every screen paint. Every actual write independently
 * re-validates the live persisted grant and provider capability regardless
 * of this value (accepted 1T-B5 storage/mutation architecture review,
 * Revision 3, sections 3, 6 and 15).
 */
data class RecentVault(val uri: Uri, val name: String, val grant: VaultGrant = VaultGrant.READ_ONLY)

/**
 * Tiny SharedPreferences-backed history of recently opened vault documents,
 * most recent first.
 *
 * Persisted fields are exactly `uri` (the document Uri string) and `name` (its
 * display name), in recency order. Nothing derived from vault contents, no
 * master password, no keys and no entries are ever stored here. The vault file
 * itself is never touched by removing an item.
 */
class RecentVaultStore(context: Context) {

    private val prefs =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun load(): List<RecentVault> {
        val raw = prefs.getString(KEY_ITEMS, null) ?: return emptyList()

        return try {
            val array = JSONArray(raw)
            val result = ArrayList<RecentVault>(array.length())

            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                val uri = item.optString(FIELD_URI, "")
                if (uri.isEmpty()) continue
                val grant =
                    if (item.optString(FIELD_GRANT, "") == VaultGrant.READ_WRITE.name) {
                        VaultGrant.READ_WRITE
                    } else {
                        // Older stored entries (pre-1T-B5a) and anything
                        // unrecognized default to the safer, more
                        // conservative hint.
                        VaultGrant.READ_ONLY
                    }
                result.add(RecentVault(Uri.parse(uri), item.optString(FIELD_NAME, ""), grant))
            }

            result
        } catch (error: Exception) {
            emptyList()
        }
    }

    /**
     * Moves [vault] to the front (replacing any entry for the same Uri) and
     * trims to [MAX_ITEMS]. Returns the entries that were evicted so the caller
     * can release their persisted Uri permissions.
     */
    fun promote(vault: RecentVault): List<RecentVault> {
        val rest = load().filter { it.uri != vault.uri }
        val updated = listOf(vault) + rest
        val kept = updated.take(MAX_ITEMS)

        save(kept)
        return updated.drop(MAX_ITEMS)
    }

    fun remove(uri: Uri) {
        save(load().filter { it.uri != uri })
    }

    /**
     * Updates the UX-only write-grant hint for [uri], if it is present in
     * history. A no-op for a vault not in history. Never itself grants or
     * revokes anything -- see [RecentVault.grant]'s documentation.
     */
    fun updateGrant(uri: Uri, grant: VaultGrant) {
        save(load().map { if (it.uri == uri) it.copy(grant = grant) else it })
    }

    private fun save(items: List<RecentVault>) {
        val array = JSONArray()
        for (item in items) {
            array.put(
                JSONObject()
                    .put(FIELD_URI, item.uri.toString())
                    .put(FIELD_NAME, item.name)
                    .put(FIELD_GRANT, item.grant.name),
            )
        }

        prefs.edit().putString(KEY_ITEMS, array.toString()).apply()
    }

    companion object {
        const val MAX_ITEMS = 5

        private const val PREFS_NAME = "recent_vaults"
        private const val KEY_ITEMS = "items"
        private const val FIELD_URI = "uri"
        private const val FIELD_NAME = "name"
        private const val FIELD_GRANT = "grant"
    }
}
