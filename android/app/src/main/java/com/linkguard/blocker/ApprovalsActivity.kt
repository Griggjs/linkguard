package com.linkguard.blocker

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.Gravity
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

/**
 * 网站白名单管理。
 *
 * 页面结构：
 *   - 顶部摘要（白名单条数 / 待处理记录条数）
 *   - 「待处理记录」可折叠，带搜索
 *   - 「白名单」常驻显示，带搜索；内置条目只读，手动添加的可移除
 *
 * 实现要点：页面骨架只在 onCreate 建一次，数据变化时**只重填列表容器**。
 * 如果每次搜索都整体重建界面，正在输入的搜索框会丢焦点、输入被打断。
 */
class ApprovalsActivity : Activity() {

    private lateinit var summary: TextView

    // 待处理记录
    private lateinit var pendingHeader: Button
    private lateinit var pendingBody: LinearLayout
    private lateinit var pendingList: LinearLayout
    private var pendingCount = 0
    private var pendingExpanded = false
    private var pendingQuery = ""

    // 白名单
    private lateinit var allowHeader: Button
    private lateinit var allowBody: LinearLayout
    private lateinit var allowList: LinearLayout
    private var allowQuery = ""
    /** 白名单整段默认展开（添加域名是最常用的操作），可点击标题收起。 */
    private var allowExpanded = true
    /** 内置条目默认折叠：130 条全展开会把手动添加的部分挤出屏幕。 */
    private var builtinExpanded = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = Ui.root(this)
        val scroll = ScrollView(this)
        scroll.addView(root)
        setContentView(scroll)

        root.addView(Ui.topBar(this, "网站白名单") { finish() })

        summary = Ui.text(this, "", 15f, Ui.MUTED)
        root.addView(summary)

        // ---------------- 待处理记录（可折叠 + 搜索）----------------
        pendingHeader = Button(this).apply {
            textSize = 15f
            isAllCaps = false
            gravity = Gravity.START or Gravity.CENTER_VERTICAL
            minimumWidth = 0
            setPadding(Ui.dp(this@ApprovalsActivity, 6), 0, Ui.dp(this@ApprovalsActivity, 6), 0)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this@ApprovalsActivity, 46)
            )
            setOnClickListener {
                pendingExpanded = !pendingExpanded
                pendingBody.visibility = visible(pendingExpanded)
                updatePendingHeader()
            }
        }
        root.addView(pendingHeader)

        pendingBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = visible(false)
        }
        pendingBody.addView(Ui.text(this,
            "这些域名最近被拦截过。若其中某个属于正常网站，点「加入白名单」。",
            13f, Ui.MUTED
        ).apply { setPadding(0, Ui.dp(this@ApprovalsActivity, 2), 0, Ui.dp(this@ApprovalsActivity, 6)) })

        pendingBody.addView(searchBox("搜索被拦截的域名") { pendingQuery = it; renderPending() })

        pendingList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        pendingBody.addView(pendingList)
        root.addView(pendingBody)

        // ---------------- 白名单（可折叠 + 搜索）----------------
        root.addView(Ui.divider(this))

        allowHeader = collapsibleHeader("白名单", allowExpanded) {
            allowExpanded = !allowExpanded
            allowBody.visibility = visible(allowExpanded)
            updateAllowHeader()
        }
        root.addView(allowHeader)

        allowBody = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = visible(allowExpanded)
        }
        allowBody.addView(Ui.text(this,
            "内置条目随应用发布，不可删除；手动添加的可以移除。\n" +
                "加入一个域名后，其所有子域名一并放行。",
            13f, Ui.MUTED
        ).apply { setPadding(0, Ui.dp(this@ApprovalsActivity, 2), 0, Ui.dp(this@ApprovalsActivity, 6)) })

        allowBody.addView(searchBox("搜索白名单") { allowQuery = it; renderAllow() })
        allowBody.addView(addDomainRow())

        allowList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        allowBody.addView(allowList)
        root.addView(allowBody)

        renderAll()
    }

    private fun updateAllowHeader() {
        val total = BuiltinRules.ALL.size + Prefs.extraAllow(this).size
        allowHeader.text = (if (allowExpanded) "▾ " else "▸ ") +
            "白名单（$total 条）" +
            if (allowExpanded) "（点击收起）" else "（点击展开）"
    }

    // ------------------------------------------------------------ 渲染

    private fun renderAll() {
        renderPending()
        renderAllow()
        updateSummary()
        updatePendingHeader()
        updateAllowHeader()
    }

    private fun updateSummary() {
        val builtin = BuiltinRules.ALL.size
        val manual = Prefs.extraAllow(this).size
        summary.text = "白名单 ${builtin + manual} 条（内置 $builtin · 手动 $manual）" +
            " · 待处理记录 $pendingCount 条"
        summary.setPadding(0, Ui.dp(this, 4), 0, Ui.dp(this, 6))
    }

    private fun updatePendingHeader() {
        pendingHeader.text = (if (pendingExpanded) "▾ " else "▸ ") +
            "待处理记录（$pendingCount 条）" +
            if (pendingExpanded) "（点击收起）" else "（点击展开）"
    }

    private fun renderPending() {
        val all = BlockLog.snapshot(this)
        pendingCount = all.size
        val shown = all.filter { matches(it.first, pendingQuery) }

        pendingList.removeAllViews()
        if (all.isEmpty()) {
            pendingList.addView(Ui.text(this, "（暂无记录）", 14f, Ui.MUTED))
            return
        }
        if (shown.isEmpty()) {
            pendingList.addView(Ui.text(this, "没有匹配「$pendingQuery」的记录", 14f, Ui.MUTED))
            return
        }
        for ((host, count) in shown.take(MAX_ROWS)) {
            pendingList.addView(pendingRow(host, count))
        }
        if (shown.size > MAX_ROWS) {
            pendingList.addView(Ui.text(this, "仅显示前 $MAX_ROWS 条，可用搜索缩小范围", 13f, Ui.MUTED))
        }
        pendingList.addView(Ui.secondaryButton(this, "清空记录") {
            BlockLog.clear(this)
            Ui.toast(this, "记录已清空")
            renderAll()
        })
    }

    private fun renderAllow() {
        val builtinAll = BuiltinRules.ALL
        val manual = Prefs.extraAllow(this).sorted().filter { matches(it, allowQuery) }
        val builtinHit = builtinAll.filter { matches(it, allowQuery) }
        val searching = allowQuery.isNotEmpty()

        allowList.removeAllViews()

        if (manual.isEmpty() && builtinHit.isEmpty()) {
            allowList.addView(Ui.text(this,
                if (searching) "没有匹配「$allowQuery」的域名" else "（暂无条目）",
                14f, Ui.MUTED))
            return
        }

        if (manual.isNotEmpty()) {
            allowList.addView(Ui.heading(this, "手动添加（${manual.size}）"))
            for (d in manual.take(MAX_ROWS)) allowList.addView(manualRow(d))
        }

        if (searching) {
            // 搜索时直接列出命中项，不再要求先展开
            allowList.addView(Ui.heading(this, "内置（匹配 ${builtinHit.size} 条）"))
            if (builtinHit.isEmpty()) {
                allowList.addView(Ui.text(this, "内置条目中没有匹配结果", 13f, Ui.MUTED))
            } else {
                for (d in builtinHit.take(MAX_ROWS)) allowList.addView(builtinRow(d))
                if (builtinHit.size > MAX_ROWS) {
                    allowList.addView(Ui.text(this, "仅显示前 $MAX_ROWS 条，可用搜索缩小范围", 13f, Ui.MUTED))
                }
            }
        } else {
            allowList.addView(collapsibleHeader(
                "内置（${builtinAll.size} 条）", builtinExpanded
            ) {
                builtinExpanded = !builtinExpanded
                renderAllow()
            })
            if (builtinExpanded) {
                for (d in builtinAll.take(MAX_ROWS)) allowList.addView(builtinRow(d))
                if (builtinAll.size > MAX_ROWS) {
                    allowList.addView(Ui.text(this, "仅显示前 $MAX_ROWS 条，可用搜索查找", 13f, Ui.MUTED))
                }
            }
        }

        // 只有在存在手动条目时才显示重置入口，避免空状态下多一个按钮
        val manualTotal = Prefs.extraAllow(this).size
        if (manualTotal > 0) {
            allowList.addView(Ui.secondaryButton(
                this, "重置白名单（清除手动添加的 $manualTotal 条）"
            ) { confirmResetWhitelist() })
        }
    }

    /** 可折叠分区标题：▸ 折叠 / ▾ 展开。 */
    private fun collapsibleHeader(title: String, expanded: Boolean, onClick: () -> Unit): Button =
        Button(this).apply {
            text = (if (expanded) "▾ " else "▸ ") + title +
                if (expanded) "（点击收起）" else "（点击展开）"
            textSize = 15f
            isAllCaps = false
            gravity = Gravity.START or Gravity.CENTER_VERTICAL
            minimumWidth = 0
            setPadding(Ui.dp(this@ApprovalsActivity, 6), 0, Ui.dp(this@ApprovalsActivity, 6), 0)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, Ui.dp(this@ApprovalsActivity, 44)
            )
            setOnClickListener { onClick() }
        }

    /** 重置白名单：只清手动添加的，内置条目随应用发布，运行时不动。 */
    private fun confirmResetWhitelist() {
        val manualTotal = Prefs.extraAllow(this).size
        AlertDialog.Builder(this)
            .setTitle("重置白名单")
            .setMessage(
                "将清除你手动添加的 $manualTotal 个域名，内置的 ${BuiltinRules.ALL.size} 条不受影响。\n\n" +
                    "清除后，这些网站需重新添加才能在严格模式下访问。"
            )
            .setPositiveButton("确认重置") { _, _ ->
                Prefs.clearExtraAllow(this)
                reloadRules()
                Ui.toast(this, "已清除手动添加的 $manualTotal 个域名")
                renderAll()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    // ------------------------------------------------------------ 行

    private fun pendingRow(host: String, count: Int): LinearLayout {
        val row = Ui.row(this)
        row.addView(Ui.text(this, host, 14f, Ui.TEXT),
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(Ui.text(this, "×$count", 13f, Ui.MUTED).apply {
            setPadding(Ui.dp(this@ApprovalsActivity, 6), 0, Ui.dp(this@ApprovalsActivity, 6), 0)
        })
        row.addView(smallButton("加入白名单") {
            Prefs.addAllow(this, host)
            BlockLog.remove(this, host)
            reloadRules()
            Ui.toast(this, "已加入白名单：$host")
            renderAll()
        })
        return row
    }

    private fun manualRow(domain: String): LinearLayout {
        val row = Ui.row(this)
        row.addView(Ui.text(this, domain, 14f, Ui.TEXT),
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(smallButton("移除") {
            Prefs.removeAllow(this, domain)
            reloadRules()
            Ui.toast(this, "已移除：$domain")
            renderAll()
        })
        return row
    }

    private fun builtinRow(domain: String): LinearLayout {
        val row = Ui.row(this)
        row.addView(Ui.text(this, domain, 14f, Ui.TEXT),
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        row.addView(Ui.text(this, "内置", 12f, Ui.MUTED))
        return row
    }

    private fun smallButton(label: String, onClick: () -> Unit): Button =
        Button(this).apply {
            text = label
            textSize = 13f
            isAllCaps = false
            minimumWidth = 0
            setPadding(Ui.dp(this@ApprovalsActivity, 10), 0, Ui.dp(this@ApprovalsActivity, 10), 0)
            setOnClickListener { onClick() }
        }

    /** 搜索框：内容变化时只重填对应列表，不重建整个页面。 */
    private fun searchBox(hint: String, onChanged: (String) -> Unit): EditText =
        EditText(this).apply {
            this.hint = hint
            textSize = 15f
            inputType = InputType.TYPE_CLASS_TEXT
            setSingleLine()
            setHintTextColor(0xFF9AA4B2.toInt())
            setPadding(0, Ui.dp(this@ApprovalsActivity, 4), 0, Ui.dp(this@ApprovalsActivity, 4))
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
                override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
                override fun afterTextChanged(s: Editable?) {
                    onChanged(s?.toString()?.trim().orEmpty())
                    updateSummary()
                }
            })
        }

    /** 手动输入域名的一行：输入框 + 添加按钮。 */
    private fun addDomainRow(): LinearLayout {
        val row = Ui.row(this)
        val input = EditText(this).apply {
            hint = "例如 example.com"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            textSize = 15f
            setSingleLine()
            setHintTextColor(0xFF9AA4B2.toInt())
        }
        row.addView(input, LinearLayout.LayoutParams(
            0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f
        ))
        row.addView(smallButton("添加") {
            val raw = input.text.toString()
            val domain = DomainName.fromUserInput(raw)
            if (!DomainName.isPlausibleDomain(domain)) {
                Ui.toast(this, "格式不正确，请输入有效域名：$raw")
                return@smallButton
            }
            Prefs.addAllow(this, domain)
            reloadRules()
            Ui.toast(this, "已加入白名单：$domain")
            input.setText("")
            renderAll()
        })
        return row
    }

    // ------------------------------------------------------------ 工具

    private fun matches(host: String, query: String): Boolean =
        query.isEmpty() || host.contains(query, ignoreCase = true)

    private fun visible(v: Boolean): Int = if (v) LinearLayout.VISIBLE else LinearLayout.GONE

    /** 名单变动后立刻让运行中的服务重新加载。 */
    private fun reloadRules() {
        GuardVpnService.reloadRules()
    }

    private companion object {
        /** 单次最多渲染多少行，避免内置 130 条 + 记录过多导致卡顿。 */
        const val MAX_ROWS = 80
    }
}
