package com.localvault.android.proof

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.text.InputType
import android.view.View
import android.view.Window
import android.view.WindowInsets
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.ByteArrayOutputStream
import java.io.IOException
import uniffi.localvault_android_bridge.BridgeException
import uniffi.localvault_android_bridge.EntrySummary
import uniffi.localvault_android_bridge.VaultSession
import uniffi.localvault_android_bridge.openVault

/**
 * First real LocalVault Android slice (1T-B2): pick an existing vault with the
 * system document picker, unlock it through localvault-core (via the Rust
 * bridge, off the main thread), show a read-only entry list, and lock.
 *
 * Security shape:
 *  - The decrypted vault lives only inside the Rust-owned [VaultSession]. Kotlin
 *    holds only non-secret [EntrySummary] rows, and only while unlocked.
 *  - The master password is read from the input, the input is wiped, and the
 *    String is passed straight to the synchronous bridge call on a background
 *    thread. It is never stored, saved, logged or shown. The JVM cannot
 *    deterministically zeroize Strings, so no erasure of that copy is claimed.
 *  - The vault is locked whenever the Activity leaves the foreground.
 *  - The document Uri is kept in memory only (no persisted permission).
 *  - This slice is read-only: the vault file is never written.
 */
class MainActivity : Activity() {

    private enum class Screen { NO_FILE, FILE_SELECTED, UNLOCKING, UNLOCKED }

    private class VaultReadException : Exception()

    private companion object {
        const val REQUEST_PICK_VAULT = 1

        // Mirrors the desktop adapter's vault file size bound.
        const val MAX_VAULT_FILE_BYTES = 32L * 1024 * 1024

        const val MSG_AUTH = "Unable to unlock vault. Check the master password and file."
        const val MSG_FORMAT = "This file is not a supported LocalVault vault."
        const val MSG_READ = "Unable to read the selected file."
        const val MSG_GENERIC = "Unable to unlock vault."
        const val MSG_EMPTY_PASSWORD = "Enter the master password."
    }

    private lateinit var content: LinearLayout

    private var screen = Screen.NO_FILE
    private var vaultUri: Uri? = null
    private var vaultName: String = ""
    private var statusMessage: String? = null

    private var session: VaultSession? = null
    private var entries: List<EntrySummary> = emptyList()
    private var passwordField: EditText? = null

    // Bumped on every lock/stop/destroy so a late background result for an
    // abandoned unlock is discarded (and its session closed) instead of shown.
    private var unlockGeneration = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // The framework ActionBar is dropped: with targetSdk 36 the window is
        // edge-to-edge (enforced on Android 15+), and the ActionBar overlay was
        // drawn on top of the body, hiding the first controls. The screen draws
        // its own "LocalVault" heading instead. Must precede setContentView.
        requestWindowFeature(Window.FEATURE_NO_TITLE)

        // Keep entry text out of screenshots and the recent-apps thumbnail.
        // (Intentional: this also blocks screenshots and is unrelated to layout.)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        content = LinearLayout(this)
        content.orientation = LinearLayout.VERTICAL
        content.setPadding(dp(16), dp(16), dp(16), dp(32))

        val scroll = ScrollView(this)
        scroll.addView(content)

        // Edge-to-edge: inset the body by the system bars, display cutout and
        // keyboard so nothing is drawn under them.
        scroll.setOnApplyWindowInsetsListener { view, insets ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                val bars =
                    insets.getInsets(
                        WindowInsets.Type.systemBars() or
                            WindowInsets.Type.displayCutout() or
                            WindowInsets.Type.ime(),
                    )
                view.setPadding(bars.left, bars.top, bars.right, bars.bottom)
            } else {
                @Suppress("DEPRECATION")
                view.setPadding(
                    insets.systemWindowInsetLeft,
                    insets.systemWindowInsetTop,
                    insets.systemWindowInsetRight,
                    insets.systemWindowInsetBottom,
                )
            }
            WindowInsets.CONSUMED
        }

        setContentView(scroll)

        render()
    }

    override fun onStop() {
        super.onStop()

        if (screen == Screen.UNLOCKED || screen == Screen.UNLOCKING) {
            lockVault()
        } else {
            passwordField?.let { wipe(it) }
        }
    }

    override fun onDestroy() {
        unlockGeneration++
        val current = session
        session = null
        entries = emptyList()
        closeQuietly(current)

        super.onDestroy()
    }

    @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode != REQUEST_PICK_VAULT || resultCode != RESULT_OK) return
        val uri = data?.data ?: return

        vaultUri = uri
        vaultName = queryDisplayName(uri) ?: "Selected vault"
        statusMessage = null
        screen = Screen.FILE_SELECTED
        render()
    }

    // ---------------------------------------------------------------- actions

    @Suppress("DEPRECATION")
    private fun openPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"
        startActivityForResult(intent, REQUEST_PICK_VAULT)
    }

    private fun startUnlock() {
        val uri = vaultUri ?: return
        val field = passwordField ?: return

        val password = field.text.toString()
        if (password.isEmpty()) {
            statusMessage = MSG_EMPTY_PASSWORD
            render()
            return
        }

        wipe(field)

        val generation = ++unlockGeneration
        statusMessage = null
        screen = Screen.UNLOCKING
        render()

        Thread { runUnlock(uri, password, generation) }.start()
    }

    private fun lockVault() {
        unlockGeneration++

        val current = session
        session = null
        entries = emptyList()
        closeQuietly(current)

        statusMessage = null
        screen = if (vaultUri != null) Screen.FILE_SELECTED else Screen.NO_FILE
        render()
    }

    // ------------------------------------------------------ background unlock

    /** Runs on a dedicated background thread: file read + Argon2id + list. */
    private fun runUnlock(uri: Uri, password: String, generation: Int) {
        var opened: VaultSession? = null
        var rows: List<EntrySummary> = emptyList()
        var message: String? = null

        try {
            val envelopeBytes = readVaultBytes(uri)
            opened = openVault(envelopeBytes, password)
            rows = opened.listEntries()
        } catch (error: BridgeException.AuthenticationFailed) {
            message = MSG_AUTH
        } catch (error: BridgeException.UnsupportedFormat) {
            message = MSG_FORMAT
        } catch (error: VaultReadException) {
            message = MSG_READ
        } catch (error: IOException) {
            message = MSG_READ
        } catch (error: SecurityException) {
            message = MSG_READ
        } catch (error: Throwable) {
            message = MSG_GENERIC
        }

        if (message != null) {
            closeQuietly(opened)
            opened = null
        }

        val result = opened
        runOnUiThread { finishUnlock(generation, result, rows, message) }
    }

    private fun readVaultBytes(uri: Uri): ByteArray {
        val stream = contentResolver.openInputStream(uri) ?: throw VaultReadException()

        stream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(64 * 1024)
            var total = 0L

            while (true) {
                val read = input.read(buffer)
                if (read < 0) break

                total += read
                if (total > MAX_VAULT_FILE_BYTES) throw VaultReadException()

                output.write(buffer, 0, read)
            }

            return output.toByteArray()
        }
    }

    /** Back on the main thread. */
    private fun finishUnlock(
        generation: Int,
        opened: VaultSession?,
        rows: List<EntrySummary>,
        message: String?,
    ) {
        if (generation != unlockGeneration || screen != Screen.UNLOCKING || isFinishing || isDestroyed) {
            closeQuietly(opened)
            return
        }

        if (opened == null) {
            statusMessage = message ?: MSG_GENERIC
            screen = Screen.FILE_SELECTED
        } else {
            session = opened
            entries = rows
            statusMessage = null
            screen = Screen.UNLOCKED
        }

        render()
    }

    private fun closeQuietly(target: VaultSession?) {
        if (target == null) return

        try {
            target.lock()
        } catch (ignored: Throwable) {
        }

        try {
            target.close()
        } catch (ignored: Throwable) {
        }
    }

    // ---------------------------------------------------------------- helpers

    private fun queryDisplayName(uri: Uri): String? =
        try {
            contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (column >= 0 && cursor.moveToFirst()) cursor.getString(column) else null
            }
        } catch (error: Exception) {
            null
        }

    /** Best-effort overwrite of the typed characters; not a zeroization claim. */
    private fun wipe(field: EditText) {
        val editable = field.text ?: return
        val length = editable.length
        if (length > 0) editable.replace(0, length, " ".repeat(length))
        editable.clear()
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    // ---------------------------------------------------------------- render

    private fun render() {
        content.removeAllViews()
        passwordField = null

        addText("LocalVault", bold = true, size = 24f, topMargin = 0)

        when (screen) {
            Screen.NO_FILE -> {
                addStatus()
                addButton("Choose vault") { openPicker() }
            }

            Screen.FILE_SELECTED -> {
                addText("Vault:", bold = true)
                addText(vaultName)
                addText("Master password:", bold = true, topMargin = 16)
                addPasswordField()
                addStatus()
                addButton("Unlock", topMargin = 16) { startUnlock() }
                addButton("Choose a different vault") { openPicker() }
            }

            Screen.UNLOCKING -> {
                addText("Unlocking...", bold = true)
            }

            Screen.UNLOCKED -> {
                addText(vaultName, bold = true)
                addButton("Lock") { lockVault() }
                addText(if (entries.isEmpty()) "No entries." else "Entries: ${entries.size}", topMargin = 8)

                for (entry in entries) {
                    addText(entry.title, bold = true, topMargin = 12)

                    val detail =
                        listOf(entry.profileName, entry.username, entry.url)
                            .filter { it.isNotBlank() }
                            .joinToString(" · ")
                    if (detail.isNotEmpty()) addText(detail, size = 13f)
                }
            }
        }
    }

    private fun addText(text: String, bold: Boolean = false, size: Float = 16f, topMargin: Int = 0) {
        val view = TextView(this)
        view.text = text
        view.textSize = size
        if (bold) view.setTypeface(view.typeface, Typeface.BOLD)
        addToContent(view, topMargin)
    }

    private fun addStatus() {
        val message = statusMessage ?: return
        addText(message, topMargin = 8)
    }

    private fun addButton(label: String, topMargin: Int = 8, onClick: () -> Unit) {
        val button = Button(this)
        button.text = label
        button.setOnClickListener { onClick() }
        addToContent(button, topMargin)
    }

    private fun addPasswordField() {
        val field = EditText(this)
        field.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        field.imeOptions = EditorInfo.IME_ACTION_DONE or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        field.setSingleLine()
        field.isSaveEnabled = false
        field.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        field.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                startUnlock()
                true
            } else {
                false
            }
        }

        passwordField = field
        addToContent(field, 0)
    }

    private fun addToContent(view: View, topMargin: Int) {
        val params =
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
        params.topMargin = dp(topMargin)
        content.addView(view, params)
    }
}
