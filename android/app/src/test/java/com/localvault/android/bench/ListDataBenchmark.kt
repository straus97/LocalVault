package com.localvault.android.bench

import com.localvault.android.CategoryFilter
import com.localvault.android.EntryListFilter
import java.io.File
import java.util.Locale
import org.junit.Assume.assumeTrue
import org.junit.Test
import uniffi.localvault_android_bridge.EntrySummary

/**
 * DATA-ONLY list benchmark (no Android, no Views): how expensive is the
 * category + search filter over [EntrySummary] data, and how expensive is the
 * pure-data part of building row content, at 1k / 5k / 10k / 50k entries.
 *
 * It calls the exact production helper [EntryListFilter.visible] that
 * `MainActivity.refreshListRows` calls (through `ListRows.build`). It is opt-in so the normal JVM suite stays
 * fast and quiet: it does nothing unless `LOCALVAULT_BENCH=1` is set. Run it
 * with `android/scripts/run-list-benchmark.ps1`.
 *
 * Numbers are from the host JVM (HotSpot, desktop CPU), NOT from a phone's
 * ART runtime. They are valid for comparing scenarios, sizes and
 * before/after changes on the same machine, and as a lower bound for a
 * phone; they are not phone timings.
 */
class ListDataBenchmark {

    private class Stats(samplesNs: LongArray) {
        private val sorted = samplesNs.sortedArray()
        val medianMs = ms(sorted[sorted.size / 2])
        val p95Ms = ms(sorted[minOf(sorted.size - 1, Math.ceil(sorted.size * 0.95).toInt() - 1)])
        val minMs = ms(sorted.first())
        val maxMs = ms(sorted.last())

        private fun ms(ns: Long) = ns / 1_000_000.0
    }

    // Keeps the JIT from eliminating the measured work.
    @Volatile private var sink: Long = 0

    private fun envInt(name: String, default: Int): Int = System.getenv(name)?.trim()?.toIntOrNull() ?: default

    /** A replica of the data-derivation in `MainActivity.newEntryRow` (subtitle string); no Views. */
    private fun rowModelWork(rows: List<EntrySummary>): Int {
        var acc = 0
        for (e in rows) {
            if (e.username.isNotBlank()) acc += e.username.length
            val site = listOf(e.url, e.profileName).filter { it.isNotBlank() }.joinToString(" · ")
            acc += site.length
        }
        return acc
    }

    /** Views one row creates in the current architecture: card + title + username? + subtitle?. */
    private fun viewsFor(rows: List<EntrySummary>): Long {
        var views = 0L
        for (e in rows) {
            views += 2 // card LinearLayout + title TextView
            if (e.username.isNotBlank()) views++
            if (e.url.isNotBlank() || e.profileName.isNotBlank()) views++
        }
        return views
    }

    private fun usedHeapBytes(): Long {
        val rt = Runtime.getRuntime()
        repeat(4) {
            System.gc()
            Thread.sleep(50)
        }
        return rt.totalMemory() - rt.freeMemory()
    }

    @Test
    fun run_list_data_benchmark() {
        assumeTrue("opt-in benchmark: set LOCALVAULT_BENCH=1 (see android/scripts/run-list-benchmark.ps1)", System.getenv("LOCALVAULT_BENCH") == "1")

        val sizes =
            System.getenv("LOCALVAULT_BENCH_SIZES")?.split(",")?.mapNotNull { it.trim().toIntOrNull() }?.takeIf { it.isNotEmpty() }
                ?: SyntheticEntries.defaultSizes
        val warmup = envInt("LOCALVAULT_BENCH_WARMUP", 30)
        val iterations = envInt("LOCALVAULT_BENCH_ITERATIONS", 60)

        val report = StringBuilder()
        fun line(s: String = "") {
            report.appendLine(s)
            println(s)
        }

        line("# Android list DATA-ONLY benchmark (host JVM)")
        line()
        line("- jvm: ${System.getProperty("java.vm.name")} ${System.getProperty("java.version")}")
        line("- os: ${System.getProperty("os.name")} ${System.getProperty("os.arch")}, cpus=${Runtime.getRuntime().availableProcessors()}, maxHeapMiB=${Runtime.getRuntime().maxMemory() / (1024 * 1024)}")
        line("- dataset: SyntheticEntries seed=${SyntheticEntries.DEFAULT_SEED}; sizes=$sizes; warmup=$warmup; measured iterations=$iterations")
        line("- timings are host-JVM milliseconds (median / p95 over measured iterations); NOT phone timings")
        line()

        for (size in sizes) {
            val heapBefore = usedHeapBytes()
            val entries = SyntheticEntries.generate(size)
            val heapAfter = usedHeapBytes()
            val dataMiB = (heapAfter - heapBefore) / (1024.0 * 1024.0)

            line("## $size entries (summary list heap ~${"%.1f".format(Locale.ROOT, dataMiB)} MiB on this JVM)")
            line()
            line("| scenario | matches | filter median ms | filter p95 ms | filter min | filter max | row-model median ms | est. Views if rebuilt |")
            line("|---|---:|---:|---:|---:|---:|---:|---:|")

            for (scenario in SyntheticEntries.scenarios) {
                val filter =
                    scenario.categoryIndex?.let { CategoryFilter.Category(SyntheticEntries.categoryId(it)) } ?: CategoryFilter.All

                var matches = 0
                repeat(warmup) {
                    val r = EntryListFilter.visible(entries, filter, scenario.query)
                    matches = r.size
                    sink += rowModelWork(r)
                }

                val filterSamples = LongArray(iterations)
                for (i in 0 until iterations) {
                    val t0 = System.nanoTime()
                    val r = EntryListFilter.visible(entries, filter, scenario.query)
                    filterSamples[i] = System.nanoTime() - t0
                    matches = r.size
                    sink += r.size
                }

                val visible = EntryListFilter.visible(entries, filter, scenario.query)
                val modelSamples = LongArray(iterations)
                for (i in 0 until iterations) {
                    val t0 = System.nanoTime()
                    sink += rowModelWork(visible)
                    modelSamples[i] = System.nanoTime() - t0
                }

                val f = Stats(filterSamples)
                val m = Stats(modelSamples)
                line(
                    "| ${scenario.name} | $matches | ${fmt(f.medianMs)} | ${fmt(f.p95Ms)} | ${fmt(f.minMs)} | ${fmt(f.maxMs)} | ${fmt(m.medianMs)} | ${viewsFor(visible)} |",
                )
            }
            line()
        }

        val outDir = File(System.getenv("LOCALVAULT_BENCH_OUT") ?: "build/benchmark")
        outDir.mkdirs()
        File(outDir, "list-data-benchmark.md").writeText(report.toString())
        println("[bench] sink=$sink; report written to ${File(outDir, "list-data-benchmark.md").absolutePath}")
    }

    private fun fmt(v: Double): String = "%.3f".format(Locale.ROOT, v)
}
