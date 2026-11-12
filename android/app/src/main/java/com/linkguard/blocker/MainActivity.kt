package com.linkguard.blocker

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.UnknownHostException

/**
 * 主界面：开关 + 状态 + 入口。
 *
 * 这里的设计前提是"老人零操作"——所以只有一个主按钮，
 * 而且装上之后由子女点一次、授权一次，之后不再需要动。
 */
class MainActivity : Activity() {

    private lateinit var statusView: TextView
    private lateinit var detailView: TextView
    private lateinit var toggleButton: Button
    private lateinit var adBlockButton: Button
    private lateinit var learnButton: Button
    private lateinit var modeSpinner: Spinner
    private lateinit var selfTestView: TextView
    private lateinit var dnsCheckView: TextView
    private lateinit var statusCard: LinearLayout
    private lateinit var advancedContainer: LinearLayout
    private var autoCheckRunning = false

    private var pendingAfterPin: (() -> Unit)? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = Ui.root(this)
        val scroll = ScrollView(this)
        scroll.addView(root)
        setContentView(scroll)

        // 标题
        root.addView(TextView(this).apply {
            text = "护链"
            textSize = 24f
            setTextColor(Ui.TITLE)
            gravity = Gravity.CENTER
            setTypeface(typeface, android.graphics.Typeface.BOLD)
            setPadding(0, 0, 0, Ui.dp(this@MainActivity, 14))
        })

        // 状态大卡片：一眼看清"有没有在保护"
        statusCard = Ui.card(this)
        statusView = Ui.bigStatus(this, "检查中…", Ui.MUTED).apply {
            textSize = 26f
            gravity = Gravity.CENTER
        }
        statusCard.addView(statusView)

        detailView = Ui.text(this, "", 15f, Ui.MUTED).apply {
            gravity = Gravity.CENTER
            setPadding(0, Ui.dp(this@MainActivity, 6), 0, 0)
        }
        statusCard.addView(detailView)

        dnsCheckView = Ui.text(this, "", 15f, Ui.MUTED).apply {
            gravity = Gravity.CENTER
            setPadding(0, Ui.dp(this@MainActivity, 4), 0, 0)
        }
        statusCard.addView(dnsCheckView)
        root.addView(statusCard)

        // 主按钮
        toggleButton = Ui.primaryButton(this, "开启保护") { toggleProtection() }
        root.addView(toggleButton)

        // 工作模式：放在开关正下方，属于常用设置，不藏进高级选项
        val modeCard = Ui.card(this)
        modeCard.addView(Ui.heading(this, "工作模式"))
        modeSpinner = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@MainActivity,
                android.R.layout.simple_spinner_item,
                MODE_ORDER.map { modeTitle(it) }
            ).also { it.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item) }

            onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
                override fun onItemSelected(
                    parent: AdapterView<*>?, view: View?, position: Int, id: Long
                ) {
                    val target = MODE_ORDER[position]
                    val current = Prefs.mode(this@MainActivity)
                    // 与当前一致就什么都不做，避免 refresh() 里回填选项时递归触发
                    if (current == target) return

                    // 切换工作模式属于管理操作，必须过密码
                    requirePin { applyMode(target) }

                    // 下拉框先回填成当前模式：用户取消或密码错误时不留下"已经切了"的假象。
                    // 密码通过后 applyMode → refresh() 会把它改成新模式。
                    modeSpinner.setSelection(MODE_ORDER.indexOf(current).coerceAtLeast(0), false)
                }

                override fun onNothingSelected(parent: AdapterView<*>?) = Unit
            }
            setPadding(0, Ui.dp(this@MainActivity, 4), 0, 0)
        }
        modeCard.addView(modeSpinner)
        root.addView(modeCard)

        root.addView(Ui.secondaryButton(this, "检查网络与拦截状态") { runSelfTest() })

        // 检查结果
        val resultCard = Ui.card(this)
        resultCard.addView(Ui.heading(this, "检查结果"))
        selfTestView = Ui.text(this, "点击上方「检查网络与拦截状态」开始检测。", 14f, Ui.MUTED)
        selfTestView.setPadding(0, Ui.dp(this, 6), 0, 0)
        resultCard.addView(selfTestView)
        root.addView(resultCard)

        // 高级设置：只剩广告拦截与版本号，默认收起
        root.addView(Ui.secondaryButton(this, "高级设置") {
            advancedContainer.visibility =
                if (advancedContainer.visibility == View.VISIBLE) View.GONE else View.VISIBLE
        })

        advancedContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            visibility = View.GONE
        }

        // 网站管理（需密码）
        advancedContainer.addView(Ui.heading(this, "网站管理"))
        advancedContainer.addView(Ui.secondaryButton(this, "管理网站") {
            requirePin { startActivity(Intent(this, ApprovalsActivity::class.java)) }
        })
        learnButton = Ui.secondaryButton(this, "") { onLearnTapped() }
        advancedContainer.addView(learnButton)

        // 广告与追踪拦截
        advancedContainer.addView(Ui.heading(this, "拦截选项"))
        adBlockButton = Ui.secondaryButton(this, "") { toggleAdBlock() }
        advancedContainer.addView(adBlockButton)

        advancedContainer.addView(Ui.text(this, appVersionLabel(), 13f, Ui.MUTED).apply {
            gravity = Gravity.CENTER
            setPadding(0, Ui.dp(this@MainActivity, 10), 0, 0)
        })
        root.addView(advancedContainer)

        root.addView(Ui.text(this,
            "护链不联网、不上传任何数据，所有判断都在手机上完成。",
            13f, Ui.MUTED
        ).apply {
            gravity = Gravity.CENTER
            setPadding(0, Ui.dp(this@MainActivity, 10), 0, 0)
        })
        // 通知栏常驻需要通知权限（Android 13+）。拒绝也不影响拦截，只是看不到提示。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), REQ_NOTIF)
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQ_NOTIF) {
            // 无论允许还是拒绝都继续，拦截不依赖通知
            refresh()
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
        maybeFinishLearning()
    }

    private fun refresh() {
        val running = GuardVpnService.isRunning
        val learning = Prefs.isLearning(this)

        if (learning) {
            // 学习状态优先展示，避免用户以为在正常保护
            statusView.text = "正在学习"
            statusView.setTextColor(Ui.BLUE)
            Ui.tintCard(statusCard, 0xFFE3F2FD.toInt())
            toggleButton.text = "关闭保护"
        } else if (running) {
            statusView.text = "防护运行中"
            statusView.setTextColor(Ui.GREEN)
            toggleButton.text = "关闭保护"
            Ui.tintCard(statusCard, 0xFFE8F5E9.toInt())
        } else {
            statusView.text = "防护已关闭"
            statusView.setTextColor(Ui.RED)
            toggleButton.text = "开启保护"
            Ui.tintCard(statusCard, 0xFFFFEBEE.toInt())
        }

        val blocked = BlockLog.totalBlocked(this)
        detailView.text = if (learning) {
            "请打开那个软件正常用一分钟，然后回到这里"
        } else {
            "已拦截 $blocked 次可疑访问"
        }

        // 把下拉框回填成当前模式（onItemSelected 会因"与当前一致"直接返回）
        modeSpinner.setSelection(MODE_ORDER.indexOf(Prefs.mode(this)).coerceAtLeast(0), false)
        adBlockButton.text = when {
            Prefs.mode(this) != GuardMode.STRICT ->
                if (Prefs.isAdBlockEnabled(this))
                    "广告与追踪拦截：已开启（仅严格模式生效，当前不生效）"
                else "广告与追踪拦截：已关闭（仅严格模式生效）"
            Prefs.isAdBlockEnabled(this) -> "广告与追踪拦截：已开启"
            else -> "广告与追踪拦截：已关闭"
        }
        // 当前模式用不上的功能，按钮置灰，避免"以为它在工作"
        adBlockButton.alpha = if (Prefs.mode(this) == GuardMode.STRICT) 1f else 0.45f
        learnButton.text = if (learning) {
            "结束学习，把刚才的网站加入白名单"
        } else {
            "打不开某个软件？让它学习一下"
        }

        checkDnsAutomatically()
    }

    /** 版本号，显示在标题下面。 */
    private fun appVersionLabel(): String = try {
        val info = packageManager.getPackageInfo(packageName, 0)
        "v${info.versionName} (${info.versionCode})"
    } catch (t: Throwable) {
        "v?"
    }

    /**
     * 自动测一次 DNS：直接问护链自己的虚拟 DNS（和 App 走同一条路）。
     *
     * 打开界面就看到结果，不用点按钮、不用记数字。
     * 显示"正常 xxms"说明链路通；显示"失败"说明问题在护链这边。
     */
    private fun checkDnsAutomatically() {
        if (autoCheckRunning) return
        if (!GuardVpnService.isRunning) {
            dnsCheckView.text = "网络连通性：防护未开启，无法检测"
            dnsCheckView.setTextColor(Ui.MUTED)
            return
        }
        autoCheckRunning = true
        dnsCheckView.text = "网络连通性：检测中…"
        dnsCheckView.setTextColor(Ui.MUTED)

        Thread {
            val (ok, ms) = rawDnsLookup("www.baidu.com", 3000)
            runOnUiThread {
                autoCheckRunning = false
                if (ok) {
                    dnsCheckView.text = "网络连通性：正常（${ms}ms）"
                    dnsCheckView.setTextColor(Ui.GREEN)
                } else {
                    dnsCheckView.text = "网络连通性：异常，请将本页内容反馈给开发者"
                    dnsCheckView.setTextColor(Ui.RED)
                }
            }
        }.start()
    }

    /**
     * 下拉框里三个模式（智能排第一，因为它是推荐值）。
     *
     * 严格模式：只有名单里的网站能过。
     * 智能模式：默认放行，只拦诈骗高发后缀、同形字域名、冒充品牌的域名。
     * 排查模式：什么都不拦，只记录 —— 用来判断问题是不是护链造成的。
     */
    private fun modeTitle(m: GuardMode): String = when (m) {
        GuardMode.STRICT -> "严格模式：仅允许白名单内的网站（推荐）"
        GuardMode.SMART -> "智能模式：拦截高风险网站"
        GuardMode.OBSERVE -> "排查模式：仅记录，不拦截"
    }

    /** 下拉框选中后的处理：换引擎，不重建 VPN、不动系统缓存。 */
    private fun applyMode(m: GuardMode) {
        Prefs.setMode(this, m)
        GuardVpnService.reloadRules()
        Ui.toast(
            this,
            when (m) {
                GuardMode.SMART -> "已切换至智能模式：拦截高风险网站"
                GuardMode.STRICT -> "已切换至严格模式：仅允许白名单内的网站"
                GuardMode.OBSERVE -> "已切换至排查模式：仅记录，不拦截"
            }
        )
        refresh()
    }

    // ------------------------------------------------------------ 学习流程

    /**
     * 「学习」：把"某个软件在严格模式下打不开"这件事，压缩成一次点击。
     *
     * 流程：点一下 → 临时切到智能模式并开始记录被放行的域名 → 用户去用那个软件
     * → 回到本页 → 自动整理出需要加入白名单的域名，弹一次确认 → 恢复原模式。
     *
     * 用户全程只需要做一个决定（加入 / 丢弃），不需要挑选域名。
     */
    private fun onLearnTapped() {
        if (Prefs.isLearning(this)) {
            showLearnResult()
            return
        }
        if (!GuardVpnService.isRunning) {
            Ui.toast(this, "请先开启保护")
            return
        }
        Prefs.startLearning(this)
        LearnedLog.start()
        Prefs.setMode(this, GuardMode.SMART)
        GuardVpnService.reloadRules()
        Ui.toast(this, "已暂时放开限制：请打开那个软件用一分钟，然后回到护链")
        refresh()
    }

    /** 回到本页时检查学习是否该结束。太短（<15 秒）继续，太久（>30 分钟）作废。 */
    private fun maybeFinishLearning() {
        if (!Prefs.isLearning(this)) return
        val elapsed = System.currentTimeMillis() - Prefs.learningStartedAt(this)
        when {
            elapsed < LEARNING_MIN_MS -> Unit
            elapsed > LEARNING_TIMEOUT_MS -> {
                Prefs.stopLearning(this)
                LearnedLog.clear()
                restoreModeAfterLearning()
                Ui.toast(this, "学习已超时，未做任何修改")
                refresh()
            }
            else -> showLearnResult()
        }
    }

    private fun showLearnResult() {
        val hosts = LearnedLog.snapshot().map { it.first }
        val allowSet = BuiltinRules.buildAllowSet(Prefs.extraAllow(this))
        val denySet = BuiltinRules.buildDenySet(includeAds = true)
        val candidates = LearnedFilter.prepare(
            hosts,
            isAlreadyAllowed = { allowSet.match(it) != null },
            isDenied = { denySet.match(it) != null }
        )

        if (candidates.isEmpty()) {
            Prefs.stopLearning(this)
            LearnedLog.clear()
            restoreModeAfterLearning()
            Ui.toast(this, "这次没有记录到需要加入的网站")
            refresh()
            return
        }

        AlertDialog.Builder(this)
            .setTitle("学习完成")
            .setMessage(
                "记录了 ${candidates.size} 个网站。\n" +
                    "加入白名单后，严格模式下这个软件也能正常使用。"
            )
            .setPositiveButton("加入白名单") { _, _ ->
                candidates.forEach { Prefs.addAllow(this, it) }
                Prefs.stopLearning(this)
                LearnedLog.clear()
                restoreModeAfterLearning()
                GuardVpnService.reloadRules()
                Ui.toast(this, "已加入 ${candidates.size} 个网站")
                refresh()
            }
            .setNegativeButton("丢弃") { _, _ ->
                Prefs.stopLearning(this)
                LearnedLog.clear()
                restoreModeAfterLearning()
                refresh()
            }
            .setCancelable(false)
            .show()
    }

    /** 学习结束后恢复原来的工作模式。 */
    private fun restoreModeAfterLearning() {
        Prefs.setMode(this, Prefs.modeBeforeLearning(this))
        GuardVpnService.reloadRules()
    }

    /**
     * 广告拦截总开关。
     *
     * 只在严格模式下真正生效：智能模式要保证"App 都能用"，而 umeng / mob
     * 这类域名一拦，会出现收不到验证码、登录失败、推送不来。
     * 所以当前不是严格模式时，按钮置灰并在文案里写明"不生效"。
     */
    private fun toggleAdBlock() {
        val next = !Prefs.isAdBlockEnabled(this)
        Prefs.setAdBlockEnabled(this, next)
        GuardVpnService.reloadRules()
        Ui.toast(
            this,
            when {
                Prefs.mode(this) != GuardMode.STRICT && next ->
                    "已开启，但仅严格模式生效，当前模式不拦截广告"
                Prefs.mode(this) != GuardMode.STRICT ->
                    "已关闭"
                next -> "已开启广告与追踪拦截"
                else -> "已关闭广告与追踪拦截"
            }
        )
        refresh()
    }

    // ------------------------------------------------------------ 开关保护

    private fun toggleProtection() {
        if (GuardVpnService.isRunning) {
            GuardVpnService.stop(this)
            statusView.postDelayed({ refresh() }, 300)
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) {
            startActivityForResult(consent, REQ_VPN)
        } else {
            startProtection()
        }
    }

    private fun startProtection() {
        GuardVpnService.start(this)
        statusView.postDelayed({ refresh() }, 500)
    }

    // ---------------------------------------------------------------- PIN

    private fun requirePin(action: () -> Unit) {
        pendingAfterPin = action
        val mode = if (Prefs.hasPin(this)) PinActivity.MODE_VERIFY else PinActivity.MODE_SETUP
        startActivityForResult(
            Intent(this, PinActivity::class.java).putExtra(PinActivity.EXTRA_MODE, mode),
            REQ_PIN
        )
    }

    @Deprecated("Activity 结果回调，功能正常")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            REQ_VPN -> if (resultCode == RESULT_OK) startProtection()
            REQ_PIN -> {
                if (resultCode == RESULT_OK) pendingAfterPin?.invoke()
                pendingAfterPin = null
            }
        }
    }

    // -------------------------------------------------------------- 诊断

    /**
     * 一键诊断。它要回答的唯一问题是：
     * 「应用无法访问是否由护链的 DNS 转发导致？」
     *
     * 做法：
     *   1. 报告当前模式和开关状态；
     *   2. 规则自检（10 条）；
     *   3. **直连自己的 DNS 通道**（10.111.111.1:53）发真实查询测速——
     *      这走的就是 App 们走的那条路，包括上游转发，所以测出来的就是真相。
     *      InetAddress 有缓存会骗人，所以这里用手工报文 + 原始 UDP。
     */
    private fun runSelfTest() {
        selfTestView.text = "正在检查…"
        selfTestView.setTextColor(Ui.MUTED)

        Thread {
            val sb = StringBuilder()
            val running = GuardVpnService.isRunning

            sb.append(if (running) "防护状态：运行中\n" else "防护状态：未开启\n")

            // 1. 名单检查（只挑两种模式下结论都一样的用例，
            //    否则切到智能模式会误报"8/10 项正常"）
            val engine = Prefs.buildEngine(this)
            val cases = listOf(
                "mp.weixin.qq.com" to true,
                "www.icbc.com.cn" to true,
                "www.12306.cn" to true,
                "www.gov.cn" to true,
                "connectivitycheck.gstatic.com" to true,
                "www.douyin.com" to true,
                "icbc-login.top" to false,
                "xn--80ak6aa92e.com" to false
            )
            val ruleOk = cases.count { (h, want) -> engine.decide(h).allowed == want }
            sb.append("规则自检：$ruleOk/${cases.size} 项通过\n\n")

            // 2. 常用网站连通性（显示业务名称，不显示域名）
            var failures = 0
            if (!running) {
                sb.append("网络连通性：防护未开启，无法检测\n\n")
            } else {
                sb.append("常用网站连通性：\n")
                val targets = listOf(
                    "www.baidu.com" to "百度",
                    "img.alicdn.com" to "淘宝图片",
                    "360buyimg.com" to "京东图片",
                    "mp.weixin.qq.com" to "微信"
                )
                for ((host, label) in targets) {
                    val (ok, ms) = rawDnsLookup(host, 3000)
                    if (!ok) failures++
                    sb.append("  $label：").append(if (ok) "正常" else "不通").append("\n")
                }

                // 3. 陌生网站应该拦得住
                val probe = "selftest-${System.currentTimeMillis()}.example"
                val (blockedOk, _) = rawDnsLookup(probe, 3000)
                if (blockedOk) {
                    failures++
                    sb.append("  陌生网站：未拦截（防护可能未生效）\n")
                } else {
                    sb.append("  陌生网站：已拦截\n")
                }

                // 4. 上游 DNS 通不通（只做提示，不算故障 —— 备用上游挂了不影响使用）
                sb.append("\n上游 DNS 服务器：\n")
                val ups = GuardVpnService.lastUpstreams
                if (ups.isEmpty()) {
                    sb.append("  （没有记录到上游，说明护链没真正启动）\n")
                } else {
                    var firstOk = false
                    ups.forEachIndexed { index, ip ->
                        val ok = probeUpstream(ip, 2000)
                        if (index == 0 && ok) firstOk = true
                        sb.append("  $ip：").append(if (ok) "可达" else "不可达（备用，不影响）").append("\n")
                    }
                    if (!firstOk) {
                        failures++
                        sb.append("  ⚠ 首选上游不可达，将增加解析延迟\n")
                    }
                }

                // 5. 内部统计：卡在哪一步，一眼可见
                sb.append("\n内部统计：\n  ").append(Stats.summary()).append("\n")

                sb.append("\n")
            }

            sb.append(
                if (!running) "结论：请先点击上方「开启保护」，再重新检测。"
                else if (failures == 0) "结论：DNS 解析链路正常，未发现拦截异常。"
                else "结论：检测到 $failures 项异常，请将本页内容反馈给开发者。"
            )

            // 技术信息摘要（供维护者排查参考）
            val modeLabel = when (Prefs.mode(this)) {
                GuardMode.STRICT -> "仅白名单"
                GuardMode.SMART -> "拦截高风险"
                GuardMode.OBSERVE -> "仅记录"
            }
            sb.append("\n\n（模式：$modeLabel；广告拦截：")
                .append(if (Prefs.isAdBlockEnabled(this)) "开" else "关")
                .append("；").append(appVersionLabel()).append("）")

            runOnUiThread {
                selfTestView.text = sb.toString()
                selfTestView.setTextColor(if (failures == 0 && running) Ui.GREEN else Ui.RED)
                refresh()
            }
        }.start()
    }

    /**
     * 直接向某个上游 DNS 发一条查询（不经过护链的隧道，因为只有 10.111.111.1 被路由进隧道）。
     *
     * 用来区分两种完全不同的故障：
     *   - 上游不通 → 手机网络到不了这个 DNS，换上游
     *   - 上游通、但内部统计里"上游失败"在涨 → 转发环节存在缺陷
     */
    private fun probeUpstream(ip: String, timeoutMs: Int): Boolean {
        var socket: DatagramSocket? = null
        return try {
            val query = DnsMessage.buildQuery("www.baidu.com", DnsMessage.TYPE_A, 0x6262)
            socket = DatagramSocket()
            socket.soTimeout = timeoutMs
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(ip), 53))
            val buf = ByteArray(512)
            val p = DatagramPacket(buf, buf.size)
            socket.receive(p)
            p.length > 0
        } catch (t: Throwable) {
            false
        } finally {
            runCatching { socket?.close() }
        }
    }

    /**
     * 用手工构造的 DNS 报文直连护链的虚拟 DNS（10.111.111.1:53）测一条查询。
     *
     * 返回 (是否成功解析, 耗时毫秒)。成功 = 收到 rcode 0 的应答。
     * 不用 InetAddress 是因为它有缓存，测出来的是缓存不是真相。
     */
    private fun rawDnsLookup(name: String, timeoutMs: Int): Pair<Boolean, Long> {
        val started = System.currentTimeMillis()
        var socket: DatagramSocket? = null
        try {
            val query = DnsMessage.buildQuery(name, DnsMessage.TYPE_A, 0x5151)
            socket = DatagramSocket()
            socket.soTimeout = timeoutMs
            socket.send(DatagramPacket(
                query, query.size,
                InetAddress.getByName(GuardVpnService.DNS_ADDRESS), 53
            ))
            val buf = ByteArray(4096)
            val p = DatagramPacket(buf, buf.size)
            socket.receive(p)
            val resp = buf.copyOf(p.length)
            val elapsed = System.currentTimeMillis() - started
            val rcode = DnsMessage.rcodeOf(resp)
            val answers = DnsMessage.answerCountOf(resp)
            // 注意：诊断的"成功"要求 rcode=0 且有应答。
            // 被拦的查询会回 NXDOMAIN（rcode=3），正好用来测拦截。
            return ((rcode == 0 && answers > 0) to elapsed)
        } catch (t: Throwable) {
            return (false to (System.currentTimeMillis() - started))
        } finally {
            runCatching { socket?.close() }
        }
    }

    companion object {
        private const val REQ_VPN = 1001
        private const val REQ_PIN = 1002
        private const val REQ_NOTIF = 1003

        /** 下拉框的显示顺序；index 与 Spinner 的 position 一一对应。推荐项排第一。 */
        private val MODE_ORDER = listOf(GuardMode.STRICT, GuardMode.SMART, GuardMode.OBSERVE)

        /** 学习流程的时间边界：太短可能是误触，太长说明忘了结束。 */
        private const val LEARNING_MIN_MS = 15_000L
        private const val LEARNING_TIMEOUT_MS = 30 * 60 * 1000L
    }
}
