package com.localvault.android.bench

import android.app.Activity
import android.app.ActivityManager
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import android.view.FrameMetrics
import android.view.View
import android.view.ViewGroup
import android.view.Window
import android.widget.BaseAdapter
import android.widget.EditText
import android.widget.TextView
import java.lang.reflect.Field
import java.util.Locale
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import uniffi.localvault_android_bridge.CategorySummary

/**
 * ON-DEVICE list benchmark for the Android LIST screen. The committed
 * baseline measured the former architecture (ScrollView -> LinearLayout,
 * removeAllViews() + recreate every visible row); this harness now measures
 * the virtualized one (framework ListView + recycling BaseAdapter, header =
 * search/chips/count, footer = empty state). Scenario names, synthetic data
 * and seed are unchanged so before/after results compare directly.
 *
 * It drives the REAL, unmodified `MainActivity` -- no production telemetry,
 * no production hook. The only things it does to the Activity are:
 *   1. inject synthetic, non-secret list state (entries / categories / screen)
 *      into the private fields by reflection and call the private `render()`;
 *   2. then exercise the real UI the way a user would: type into the real
 *      search EditText (which fires the real TextWatcher -> `refreshListRows()`)
 *      and tap the real category chip TextViews.
 * No vault is opened, no real data is read, nothing is written.
 *
 * Per scenario it records, over measured iterations (median / p95):
 *   - action ms: synchronous main-thread time of the user action (filter +
 *     row-model build + adapter update + count/empty-state update);
 *   - layout/measure ms and draw ms of the very next frame (FrameMetrics),
 *     which is where ListView lays out and binds the visible rows;
 *   - total frame ms;
 *   - `rows` = LOGICAL adapter row count (virtualized: not a View count),
 *     `views` = every View currently in the Activity window hierarchy,
 *     `listChildren` = ListView's resident children (visible rows + header
 *     + footer). Nothing scrolls the list to inflate these.
 * It also records the Java-heap cost of the N-entry list state.
 *
 * It is a plain `android.app.Instrumentation` (no AndroidX test libraries).
 * See `android/scripts/run-list-benchmark-device.ps1` for the exact commands.
 * This harness has been COMPILED but must be run by the user on a device
 * (screen on, unlocked, ideally plugged in); it makes no network calls and
 * writes no files.
 */
class ListRebuildBenchmark : Instrumentation() {

    private val tag = "LVBench"
    private var args: Bundle = Bundle.EMPTY

    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        args = arguments ?: Bundle.EMPTY
        start()
    }

    override fun onStart() {
        super.onStart()
        val result = Bundle()
        var code = Activity.RESULT_OK
        try {
            runBenchmark()
        } catch (t: Throwable) {
            code = Activity.RESULT_CANCELED
            Log.e(tag, "benchmark failed: $t", t)
            result.putString("error", t.toString())
        }
        finish(code, result)
    }

    // ---------------------------------------------------------------- output

    private fun emit(line: String) {
        Log.i(tag, line)
        val b = Bundle()
        b.putString("stream", line + "\n")
        sendStatus(0, b)
    }

    // ---------------------------------------------------------------- reflection

    private lateinit var activity: Activity
    private val handlerThread = HandlerThread("lvbench-frames").also { it.start() }
    private val frameHandler = Handler(handlerThread.looper)
    private val frames = LinkedBlockingQueue<LongArray>()

    private fun field(name: String): Field = activity.javaClass.getDeclaredField(name).apply { isAccessible = true }

    private fun setField(name: String, value: Any?) = field(name).set(activity, value)

    private fun getField(name: String): Any? = field(name).get(activity)

    private fun callRender() {
        activity.javaClass.getDeclaredMethod("render").apply { isAccessible = true }.invoke(activity)
    }

    private fun listScreenConstant(): Any =
        Class.forName("com.localvault.android.MainActivity\$Screen").enumConstants!!.first { (it as Enum<*>).name == "LIST" }!!

    private fun onMain(block: () -> Unit) {
        var error: Throwable? = null
        runOnMainSync {
            try {
                block()
            } catch (t: Throwable) {
                error = t
            }
        }
        error?.let { throw it }
    }

    // ---------------------------------------------------------------- view helpers

    private fun decor(): View = activity.window.decorView

    private fun countViews(v: View): Int {
        var n = 1
        if (v is ViewGroup) for (i in 0 until v.childCount) n += countViews(v.getChildAt(i))
        return n
    }

    private fun findSearchField(v: View): EditText? {
        if (v is EditText) return v
        if (v is ViewGroup) {
            for (i in 0 until v.childCount) findSearchField(v.getChildAt(i))?.let { return it }
        }
        return null
    }

    private fun findTextView(v: View, text: String): TextView? {
        if (v is TextView && v !is EditText && v.text?.toString() == text) return v
        if (v is ViewGroup) {
            for (i in 0 until v.childCount) findTextView(v.getChildAt(i), text)?.let { return it }
        }
        return null
    }

    /** Logical rows held by the LIST adapter (header/footer excluded). -1 if the list is not built. */
    private fun adapterRowCount(): Int = (getField("entryAdapter") as? BaseAdapter)?.count ?: -1

    /** Views ListView currently keeps as children (visible rows + header + footer). -1 if not built. */
    private fun listChildCount(): Int = (getField("entryListView") as? ViewGroup)?.childCount ?: -1

    // ---------------------------------------------------------------- frame metrics

    private val frameListener =
        Window.OnFrameMetricsAvailableListener { _, metrics, _ ->
            frames.offer(
                longArrayOf(
                    metrics.getMetric(FrameMetrics.INTENDED_VSYNC_TIMESTAMP),
                    metrics.getMetric(FrameMetrics.LAYOUT_MEASURE_DURATION),
                    metrics.getMetric(FrameMetrics.DRAW_DURATION),
                    metrics.getMetric(FrameMetrics.TOTAL_DURATION),
                ),
            )
        }

    private class Sample(
        val actionMs: Double,
        val layoutMeasureMs: Double,
        val drawMs: Double,
        val frameTotalMs: Double,
        val gotFrame: Boolean,
        val rows: Int,
        val views: Int,
        val listChildren: Int,
    )

    /**
     * Runs [action] on the main thread (timed), then waits for the first frame
     * whose intended vsync is after the action started and reads its metrics.
     */
    private fun measure(action: () -> Unit): Sample {
        waitForIdleSync()
        frames.clear()
        var actionNs = 0L
        var startNs = 0L
        onMain {
            startNs = System.nanoTime()
            action()
            actionNs = System.nanoTime() - startNs
        }
        var layout = 0.0
        var draw = 0.0
        var total = 0.0
        var got = false
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
        while (System.nanoTime() < deadline) {
            val f = frames.poll(1, TimeUnit.SECONDS) ?: continue
            if (f[0] >= startNs) {
                layout = f[1] / 1e6
                draw = f[2] / 1e6
                total = f[3] / 1e6
                got = true
                break
            }
        }
        waitForIdleSync()
        var rows = -1
        var views = -1
        var listChildren = -1
        onMain {
            rows = adapterRowCount()
            views = countViews(decor())
            listChildren = listChildCount()
        }
        return Sample(actionNs / 1e6, layout, draw, total, got, rows, views, listChildren)
    }

    // ---------------------------------------------------------------- scenario driving

    private fun usedHeapBytes(): Long {
        val rt = Runtime.getRuntime()
        repeat(4) {
            System.gc()
            Thread.sleep(100)
        }
        return rt.totalMemory() - rt.freeMemory()
    }

    private fun inject(entriesSize: Int) {
        val entries = SyntheticEntries.generate(entriesSize)
        val categories =
            (0 until SyntheticEntries.CATEGORY_COUNT).map { i ->
                CategorySummary(
                    id = SyntheticEntries.categoryId(i),
                    name = SyntheticEntries.categoryName(i),
                    entryCount = entries.count { it.categoryId == SyntheticEntries.categoryId(i) }.toUInt(),
                )
            }
        onMain {
            setField("entries", entries)
            setField("categories", categories)
            setField("vaultName", "synthetic-benchmark.lvault")
            setField("screen", listScreenConstant())
            resetFilter(categoryIndex = null, query = "")
            callRender()
        }
    }

    /** Sets the Activity's own filter state, then rebuilds. Not a measured step. */
    private fun resetFilter(categoryIndex: Int?, query: String) {
        setField(
            "categoryFilter",
            categoryIndex?.let { com.localvault.android.CategoryFilter.Category(SyntheticEntries.categoryId(it)) }
                ?: com.localvault.android.CategoryFilter.All,
        )
        setField("searchQuery", query)
        callRender()
    }

    private fun typeQuery(query: String) {
        val field = findSearchField(decor()) ?: error("search field not found")
        field.setText(query) // fires the real TextWatcher -> refreshListRows()
    }

    private fun tapChip(categoryIndex: Int) {
        val chip = findTextView(decor(), SyntheticEntries.categoryName(categoryIndex)) ?: error("chip not found")
        chip.performClick() // real selectCategory -> renderChips() + refreshListRows()
    }

    private fun median(values: List<Double>): Double = values.sorted()[values.size / 2]

    private fun p95(values: List<Double>): Double {
        val s = values.sorted()
        return s[minOf(s.size - 1, Math.ceil(s.size * 0.95).toInt() - 1)]
    }

    private fun f(v: Double): String = String.format(Locale.ROOT, "%.2f", v)

    private fun report(size: Int, name: String, samples: List<Sample>) {
        val missing = samples.count { !it.gotFrame }
        emit(
            "CSV,$size,\"$name\",rows=${samples.last().rows},views=${samples.last().views}," +
                "action_med=${f(median(samples.map { it.actionMs }))},action_p95=${f(p95(samples.map { it.actionMs }))}," +
                "layout_med=${f(median(samples.map { it.layoutMeasureMs }))},layout_p95=${f(p95(samples.map { it.layoutMeasureMs }))}," +
                "draw_med=${f(median(samples.map { it.drawMs }))},draw_p95=${f(p95(samples.map { it.drawMs }))}," +
                "frame_med=${f(median(samples.map { it.frameTotalMs }))},frame_p95=${f(p95(samples.map { it.frameTotalMs }))}," +
                "n=${samples.size},missing_frames=$missing,listChildren=${samples.last().listChildren}",
        )
    }

    private fun runBenchmark() {
        val sizes =
            args.getString("sizes")?.split(",")?.mapNotNull { it.trim().toIntOrNull() }?.takeIf { it.isNotEmpty() }
                ?: SyntheticEntries.defaultSizes
        val warmup = args.getString("warmup")?.toIntOrNull() ?: 2
        val iterations = args.getString("iterations")?.toIntOrNull() ?: 7

        val am = targetContext.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        emit(
            "DEVICE,model=${Build.MANUFACTURER} ${Build.MODEL},sdk=${Build.VERSION.SDK_INT},memoryClassMiB=${am.memoryClass}," +
                "largeMemoryClassMiB=${am.largeMemoryClass},maxHeapMiB=${Runtime.getRuntime().maxMemory() / (1024 * 1024)}",
        )
        emit("PARAMS,sizes=$sizes,warmup=$warmup,iterations=$iterations,seed=${SyntheticEntries.DEFAULT_SEED}")

        val intent = Intent().setClassName(targetContext, "com.localvault.android.MainActivity").addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        activity = startActivitySync(intent)
        waitForIdleSync()
        activity.window.addOnFrameMetricsAvailableListener(frameListener, frameHandler)

        try {
            for (size in sizes) {
                try {
                    runSize(size, warmup, iterations)
                } catch (oom: OutOfMemoryError) {
                    emit("CSV,$size,\"OUT_OF_MEMORY\",error=${oom.message}")
                    onMain {
                        setField("entries", emptyList<Any>())
                        callRender()
                    }
                }
            }
        } finally {
            activity.window.removeOnFrameMetricsAvailableListener(frameListener)
            handlerThread.quitSafely()
            onMain { activity.finish() }
        }
        emit("DONE")
    }

    private fun runSize(size: Int, warmup: Int, iterations: Int) {
        // --- memory: heap with 0 resident rows vs N resident rows -------------
        inject(size)
        onMain { resetFilter(null, "zzqqxx-no-match") }
        val heapEmpty = usedHeapBytes()
        onMain { resetFilter(null, "") }
        waitForIdleSync()
        val heapFull = usedHeapBytes()
        var rows = -1
        var views = -1
        var listChildren = -1
        onMain {
            rows = adapterRowCount()
            views = countViews(decor())
            listChildren = listChildCount()
        }
        emit(
            "MEMORY,$size,rows=$rows,views=$views,heapEmptyMiB=${f(heapEmpty / 1048576.0)}," +
                "heapFullMiB=${f(heapFull / 1048576.0)},deltaMiB=${f((heapFull - heapEmpty) / 1048576.0)}," +
                "listChildren=$listChildren",
        )

        // --- initial screen build (unlock / back-from-detail) -----------------
        run {
            val s = ArrayList<Sample>()
            repeat(warmup + iterations) { i ->
                onMain {
                    setField("searchQuery", "zzqqxx-no-match")
                    callRender()
                    setField("searchQuery", "")
                }
                val sample = measure { callRender() }
                if (i >= warmup) s.add(sample)
            }
            report(size, "initial list build (all rows)", s)
        }

        // --- per-keystroke scenarios ------------------------------------------
        for (scenario in SyntheticEntries.scenarios) {
            val baselineCategory: Int? = if (scenario.categoryIndex != null && scenario.query.isNotEmpty()) scenario.categoryIndex else null
            val baselineQuery = if (scenario.query.isEmpty() && scenario.categoryIndex == null) "a" else ""
            val samples = ArrayList<Sample>()
            repeat(warmup + iterations) { i ->
                onMain { resetFilter(baselineCategory, baselineQuery) }
                val sample =
                    measure {
                        when {
                            scenario.categoryIndex != null && scenario.query.isEmpty() -> tapChip(scenario.categoryIndex)
                            else -> typeQuery(scenario.query)
                        }
                    }
                if (i >= warmup) samples.add(sample)
            }
            report(size, scenario.name, samples)
        }

        // --- typing sequence: each character is a full rebuild ----------------
        run {
            val word = "mail"
            val samples = ArrayList<Sample>()
            repeat(warmup + iterations) { i ->
                onMain { resetFilter(null, "") }
                var totalActionMs = 0.0
                var totalLayoutMs = 0.0
                var last: Sample? = null
                for (n in 1..word.length) {
                    val s = measure { typeQuery(word.substring(0, n)) }
                    totalActionMs += s.actionMs
                    totalLayoutMs += s.layoutMeasureMs
                    last = s
                }
                if (i >= warmup) {
                    samples.add(
                        Sample(totalActionMs, totalLayoutMs, last!!.drawMs, last.frameTotalMs, last.gotFrame, last.rows, last.views, last.listChildren),
                    )
                }
            }
            report(size, "type 'mail' (4 keystrokes, summed action+layout)", samples)
        }

        onMain { resetFilter(null, "zzqqxx-no-match") }
    }
}
