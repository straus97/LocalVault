package com.localvault.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Static validation of the backup / data-extraction resources and the manifest
 * wiring. This proves the files exist, parse, and name every storage domain;
 * it is NOT evidence of what any particular OEM's backup or device-transfer
 * implementation does at runtime.
 */
class BackupRulesTest {

    private val domains =
        setOf(
            "root", "file", "database", "sharedpref", "external",
            "device_root", "device_file", "device_database", "device_sharedpref",
        )

    private fun parse(path: String): Element {
        val file = File(path)
        assertTrue("$path must exist", file.isFile)
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = true
        return factory.newDocumentBuilder().parse(file).documentElement
    }

    private fun children(parent: Element, tag: String): List<Element> {
        val out = ArrayList<Element>()
        val nodes = parent.childNodes
        for (i in 0 until nodes.length) {
            val node = nodes.item(i)
            if (node is Element && node.tagName == tag) out.add(node)
        }
        return out
    }

    private fun assertExcludesEverything(section: Element) {
        assertTrue("no includes allowed in ${section.tagName}", children(section, "include").isEmpty())
        val excludes = children(section, "exclude")
        assertEquals(domains, excludes.map { it.getAttribute("domain") }.toSet())
        for (exclude in excludes) assertEquals(".", exclude.getAttribute("path"))
    }

    @Test
    fun data_extraction_rules_exclude_all_domains_from_cloud_and_device_transfer() {
        val root = parse("src/main/res/xml/data_extraction_rules.xml")
        assertEquals("data-extraction-rules", root.tagName)

        val cloud = children(root, "cloud-backup")
        val transfer = children(root, "device-transfer")
        assertEquals(1, cloud.size)
        assertEquals(1, transfer.size)
        assertExcludesEverything(cloud[0])
        assertExcludesEverything(transfer[0])
    }

    @Test
    fun legacy_full_backup_content_excludes_all_domains() {
        val root = parse("src/main/res/xml/backup_rules.xml")
        assertEquals("full-backup-content", root.tagName)
        assertExcludesEverything(root)
    }

    @Test
    fun manifest_keeps_allow_backup_false_and_references_both_rule_files() {
        val manifest = parse("src/main/AndroidManifest.xml")
        val application = children(manifest, "application").single()
        val ns = "http://schemas.android.com/apk/res/android"

        assertEquals("false", application.getAttributeNS(ns, "allowBackup"))
        assertEquals("@xml/data_extraction_rules", application.getAttributeNS(ns, "dataExtractionRules"))
        assertEquals("@xml/backup_rules", application.getAttributeNS(ns, "fullBackupContent"))
    }

    @Test
    fun manifest_requests_no_permissions() {
        val manifest = parse("src/main/AndroidManifest.xml")
        assertTrue(children(manifest, "uses-permission").isEmpty())
        assertTrue(children(manifest, "uses-permission-sdk-23").isEmpty())
    }

    @Test
    fun private_storage_locations_are_covered_by_excluded_domains() {
        // Documents the storage the exclusions are meant to protect: recovery
        // snapshots under filesDir (domain "file") and SharedPreferences
        // ("sharedpref"). If a new storage location appears, this fails.
        val dir = File("src/main/java/com/localvault/android")
        val text = dir.listFiles { f -> f.extension == "kt" }!!.joinToString("\n") { it.readText() }
        assertTrue(text.contains("context.filesDir"))
        assertTrue(text.contains("getSharedPreferences"))
        assertTrue("no databases expected", !text.contains("openOrCreateDatabase") && !text.contains("getDatabasePath"))
        assertTrue("no external files expected", !text.contains("getExternalFilesDir") && !text.contains("externalFilesDir"))
        assertTrue("domains file and sharedpref are excluded", domains.containsAll(listOf("file", "sharedpref")))
    }
}
