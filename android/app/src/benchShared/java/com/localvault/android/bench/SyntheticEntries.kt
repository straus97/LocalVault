package com.localvault.android.bench

import java.util.Random
import java.util.UUID
import uniffi.localvault_android_bridge.EntrySummary

/**
 * Deterministic, completely synthetic [EntrySummary] data for the Android
 * list benchmarks. Compiled into BOTH the plain-JVM unit-test source set and
 * the on-device androidTest source set (see `sourceSets` in build.gradle.kts),
 * so the data-only benchmark and the on-device view-rebuild benchmark run
 * against byte-identical datasets, and so a later before/after comparison
 * (virtualization, grouping) uses the same data.
 *
 * Nothing here is derived from a real vault: every title, user name, URL and
 * profile name is assembled from the fixed word pools below, every domain
 * ends in the reserved `.example` TLD, and every id is drawn from the seeded
 * generator. There is no password, TOTP or notes data at all ([EntrySummary]
 * carries none).
 */
internal object SyntheticEntries {

    const val DEFAULT_SEED = 20260101L
    const val CATEGORY_COUNT = 8

    private val prefixes =
        listOf(
            "Nimbus", "Quartz", "Lumen", "Harbor", "Falcon", "Cobalt", "Maple", "Orbit",
            "Vertex", "Willow", "Ember", "Zenith", "Atlas", "Birch", "Cedar", "Delta",
            "Echo", "Fjord", "Glacier", "Helix", "Iris", "Juniper", "Kestrel", "Lotus",
        )
    private val suffixes =
        listOf(
            "Mail", "Bank", "Cloud", "Shop", "Games", "Pay", "Travel", "Social",
            "Docs", "Music", "Video", "News", "Health", "Fit", "Learn", "Code",
        )
    private val firstNames =
        listOf(
            "alex", "maria", "ivan", "olga", "chen", "sara", "omar", "lena",
            "pavel", "nina", "jun", "elsa", "karim", "tanya", "diego", "mila",
        )
    private val lastNames =
        listOf(
            "stone", "fox", "reed", "frost", "lake", "hill", "wood", "brook",
            "field", "grove", "marsh", "dale", "ridge", "vale", "glen", "moor",
        )
    private val profiles = listOf("Personal", "Work", "Family", "Shared", "Old", "Backup", "Business", "Kids")

    /** Deterministic category id for category index 0 until [CATEGORY_COUNT]. */
    fun categoryId(index: Int): String = UUID(0x5EED_0000_0000_0000L or index.toLong(), 0x1L).toString()

    /** Deterministic display name used when the on-device harness injects categories. */
    fun categoryName(index: Int): String = "Category $index"

    private fun siteName(index: Int): String {
        val base = prefixes[index % prefixes.size] + suffixes[(index / prefixes.size) % suffixes.size]
        val round = index / (prefixes.size * suffixes.size)
        return if (round == 0) base else base + (round + 1)
    }

    fun generate(count: Int, seed: Long = DEFAULT_SEED): List<EntrySummary> {
        require(count >= 0) { "count must be non-negative" }
        val rnd = Random(seed)
        // ~1.5 entries per site on average, and 30% of entries land on a small
        // "popular" slice of the sites so some sites carry several profiles.
        val siteCount = maxOf(64, count * 2 / 3)
        val popularSites = maxOf(8, siteCount / 20)

        val out = ArrayList<EntrySummary>(count)
        for (i in 0 until count) {
            val site = if (rnd.nextInt(100) < 30) rnd.nextInt(popularSites) else rnd.nextInt(siteCount)
            val name = siteName(site)
            val domain = name.lowercase() + ".example"

            val title = if (rnd.nextInt(100) < 85) name else "$name Account"

            // The site key is what `localvault-core`'s `site_key` yields for the
            // URL (the bridge supplies it in production). It is written out by
            // hand here -- no extra random draw -- so the dataset's other fields
            // and the pinned checksum are unchanged.
            val (url, siteKey) =
                when (rnd.nextInt(100)) {
                    in 0 until 10 -> "" to null
                    in 10 until 60 -> "https://www.$domain/login" to domain
                    in 60 until 90 -> "https://$domain" to domain
                    else -> "https://accounts.$domain/signin?next=%2Fhome" to "accounts.$domain"
                }

            val username =
                when (rnd.nextInt(100)) {
                    in 0 until 6 -> ""
                    in 6 until 56 -> {
                        val f = firstNames[rnd.nextInt(firstNames.size)]
                        val l = lastNames[rnd.nextInt(lastNames.size)]
                        "$f.$l${rnd.nextInt(100)}@inbox.example"
                    }
                    // Sequential handle: gives the benchmark a rare, selective token.
                    in 56 until 86 -> "user" + i.toString().padStart(6, '0')
                    else -> "me@$domain"
                }

            val profileName = if (rnd.nextInt(100) < 55) "" else profiles[rnd.nextInt(profiles.size)]

            val categoryId = if (rnd.nextInt(100) < 15) null else categoryId(rnd.nextInt(CATEGORY_COUNT))

            val id = UUID(rnd.nextLong(), rnd.nextLong()).toString()

            out.add(
                EntrySummary(
                    id = id,
                    title = title,
                    profileName = profileName,
                    url = url,
                    username = username,
                    categoryId = categoryId,
                    siteKey = siteKey,
                ),
            )
        }
        return out
    }

    /**
     * One benchmark scenario. [categoryIndex] null means "All". [query] is the
     * already-trimmed query string (the Android list trims before filtering).
     */
    data class Scenario(val name: String, val categoryIndex: Int?, val query: String)

    /** The identical scenario set used by the JVM data benchmark and the on-device harness. */
    val scenarios: List<Scenario> =
        listOf(
            Scenario("all / empty search", null, ""),
            Scenario("search many ('a')", null, "a"),
            Scenario("search mid ('mail')", null, "mail"),
            Scenario("search few ('user00001')", null, "user00001"),
            Scenario("search none", null, "zzqqxx-no-match"),
            Scenario("category only", 3, ""),
            Scenario("category + search ('mail')", 3, "mail"),
        )

    /** Dataset sizes the task calls for. */
    val defaultSizes: List<Int> = listOf(1_000, 5_000, 10_000, 50_000)
}
