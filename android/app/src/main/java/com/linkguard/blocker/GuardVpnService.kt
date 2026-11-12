package com.linkguard.blocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * 白名单的强制点。
 *
 * 原理：
 *   VpnService 建立一张虚拟网卡，只把"发往 10.111.111.1:53 的 DNS 请求"
 *   路由进这张网卡（addRoute 只加一条 /32），所以：
 *     - 手机的所有 DNS 查询都会落到这里；
 *     - 其它流量完全不受影响（不走隧道，速度和耗电无感）。
 *
 *   收到查询后按白名单判定：
 *     - 允许 → 转发给上游公共 DNS，把应答拼回去；
 *     - 拒绝 → 直接合成 NXDOMAIN，客户端立刻得到"域名不存在"。
 *
 * ── v1.3 性能修正 ──────────────────────────────────────
 *   v1.2 是「单线程 + 串行 + 每个上游 4 秒超时」。一个网页要同时解析几十个域名，
 *   全部排队，前面卡一个后面全超时 —— 表现就是「页面能打开但图片全白、弹窗不出来」，
 *   而且被拦记录里看不到任何图片域名（因为它们根本没被拦，是超时了）。
 *
 *   现在的做法：
 *     1. 线程池并发处理（16 路）；
 *     2. 每个查询用独立的 protect() socket —— 共享 socket 会让并发线程收到彼此的应答；
 *     3. 应答缓存（含 NXDOMAIN），重复查询不再问上游；
 *     4. 上游超时收到 1.2 秒，失败立刻回 SERVFAIL，让客户端马上重试而不是干等。
 *
 * 已知局限（写在这里，免得以后当成 bug 查）：
 *   1. 只处理 IPv4 / UDP / 未分片的 DNS。IPv6 的 DNS 和 TCP 53 不处理。
 *   2. App 内置加密 DNS（DoH）会绕过这张网卡。
 *   3. 没调用 startForeground，被 MIUI 杀掉是可能的。
 */
class GuardVpnService : VpnService() {

    companion object {
        private const val TAG = "GuardVpn"

        const val ACTION_START = "com.linkguard.blocker.action.START"
        const val ACTION_STOP = "com.linkguard.blocker.action.STOP"

        const val VPN_ADDRESS = "10.111.111.2"
        const val DNS_ADDRESS = "10.111.111.1"
        private const val DNS_PORT = 53
        private const val MTU = 1500

        /**
         * 上游备用：公共 DNS，排在系统 DNS 之后。
         *
         * 实测 119.29.29.29（腾讯）在部分家用网络下不可达，每次查询都会白等一轮超时，
         * 已从默认列表移除，换成 114.114.114.114。
         */
        private val DEFAULT_UPSTREAMS = listOf("223.5.5.5", "114.114.114.114", "180.76.76.76")

        /** 单个上游等多久。短一点，失败就换下一个/立刻回 SERVFAIL。 */
        private const val UPSTREAM_TIMEOUT_MS = 1200

        /** 允许的应答缓存多久（毫秒）。 */
        private const val CACHE_TTL_MS = 120_000L

        /** 缓存的查询最多几个，超了整体清空（简单粗暴但不占内存）。 */
        private const val CACHE_MAX = 2000

        /** 并发处理的路数。手机上 16 路足够应付一个页面几十个域名。 */
        private const val WORKERS = 16

        /** 通知栏常驻。用前台服务的方式运行，降低被系统清理的概率。 */
        private const val CHANNEL_ID = "guard_status"
        private const val FGS_ID = 1001
        private const val NOTIF_INTERVAL_MS = 15_000L

        @Volatile
        var isRunning: Boolean = false
            private set

        /** 当前实际在用的上游 DNS（给诊断界面看）。 */
        @Volatile
        var lastUpstreams: List<String> = emptyList()
            private set

        @Volatile
        private var instance: GuardVpnService? = null

        fun reloadRules() {
            val svc = instance ?: return
            runCatching {
                svc.engine = Prefs.buildEngine(svc)
                // 模式/名单改了必须清缓存，否则最多 2 分钟内还在用旧判定
                svc.cache.clear()
            }
        }

        fun start(ctx: Context) {
            val i = Intent(ctx, GuardVpnService::class.java).setAction(ACTION_START)
            ctx.startService(i)
        }

        fun stop(ctx: Context) {
            val i = Intent(ctx, GuardVpnService::class.java).setAction(ACTION_STOP)
            ctx.startService(i)
        }
    }

    private class Cached(val payload: ByteArray, val expires: Long)

    private var tun: ParcelFileDescriptor? = null
    private var reader: Thread? = null
    private var workers: ExecutorService? = null

    @Volatile
    private var running = false

    private var engine: GuardEngine = GuardEngine(DomainSet())

    /** 实际使用的上游：优先使用当前网络的 DNS，公共 DNS 作为备用。 */
    @Volatile
    private var upstreams: List<String> = DEFAULT_UPSTREAMS

    private val cache = ConcurrentHashMap<String, Cached>()

    /** 多个工作线程会同时往 tun 写，必须串行化，否则包会互相穿插。 */
    private val writeLock = Any()

    private val dnsIp: ByteArray by lazy { InetAddress.getByName(DNS_ADDRESS).address }

    /** 定时刷新通知栏里的拦截计数。 */
    private val notificationTicker = object : Runnable {
        override fun run() {
            if (!running) return
            keepNotificationAlive()
            Handler(Looper.getMainLooper()).postDelayed(this, NOTIF_INTERVAL_MS)
        }
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        ensureNotificationChannel()
    }

    // ------------------------------------------------------------ 通知栏

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
        val channel = NotificationChannel(
            CHANNEL_ID, "防护状态", NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "显示护链是否正在保护手机"
            setShowBadge(false)
            enableVibration(false)
        }
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val modeText = when (Prefs.mode(this)) {
            GuardMode.STRICT -> "严格模式"
            GuardMode.SMART -> "智能模式"
            GuardMode.OBSERVE -> "排查模式"
        }
        val blocked = BlockLog.totalBlocked(this)
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("护链正在保护手机")
            .setContentText("$modeText · 已拦截 $blocked 次")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setContentIntent(open)
            .build()
    }

    private fun refreshNotification() {
        if (!running) return
        runCatching {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
            nm?.notify(FGS_ID, buildNotification())
        }
    }

    /**
     * 检查常驻通知是否还在，被用户划掉就重新挂上。
     *
     * 为什么需要：Android 11 起系统允许用户划掉前台服务通知，setOngoing(true)
     * 只是"默认不让划"，不是"禁止划掉"。通知消失会让用户误以为保护停了
     * （服务实际仍在运行），因此每 15 秒检查一次并自动恢复。
     */
    private fun keepNotificationAlive() {
        if (!running) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager
        if (nm == null) {
            refreshNotification()
            return
        }
        val stillThere = runCatching {
            nm.activeNotifications.any { it.id == FGS_ID }
        }.getOrDefault(true)

        if (stillThere) {
            refreshNotification()
        } else {
            // 通知被划掉了，重新进入前台状态把它挂回来
            runCatching { startForeground(FGS_ID, buildNotification()) }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            Prefs.setEnabled(this, false)
            stopVpn()
            return START_NOT_STICKY
        }
        if (!running) startVpn()
        return START_STICKY
    }

    // ------------------------------------------------------------ 建立/拆除

    private fun startVpn() {
        try {
            engine = Prefs.buildEngine(this)
            cache.clear()
            Stats.reset()
            upstreams = (currentNetworkDnsServers() + DEFAULT_UPSTREAMS).distinct()
            lastUpstreams = upstreams
            Log.i(TAG, "上游 DNS：$upstreams")

            // 注意：VpnService.Builder 在 SDK 里是**非静态内部类**，
            // 必须用隐式的外部实例（也就是本 Service）来构造，不能写 VpnService.Builder()。
            val builder = Builder()
                .setSession("护链")
                .setMtu(MTU)
                .addAddress(VPN_ADDRESS, 32)
                .addDnsServer(DNS_ADDRESS)
                .addRoute(DNS_ADDRESS, 32)
                .setBlocking(true)
            runCatching { builder.setMetered(false) }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.w(TAG, "establish() 返回 null：用户可能撤销了 VPN 授权")
                return
            }
            tun = pfd
            workers = Executors.newFixedThreadPool(WORKERS) { r ->
                Thread(r, "dns-worker").apply { isDaemon = true }
            }

            running = true
            isRunning = true
            Prefs.setEnabled(this, true)

            // 前台服务 + 常驻通知：系统不会轻易回收，用户也能一眼看到"正在保护"
            runCatching { startForeground(FGS_ID, buildNotification()) }
            Handler(Looper.getMainLooper()).removeCallbacks(notificationTicker)
            Handler(Looper.getMainLooper()).postDelayed(notificationTicker, NOTIF_INTERVAL_MS)

            reader = Thread({ readLoop() }, "dns-reader").also { it.start() }
            Log.i(TAG, "VPN 已建立，允许名单 ${engine.allowListSize()} 条，并发 $WORKERS")
        } catch (t: Throwable) {
            Log.e(TAG, "启动失败", t)
            stopVpn()
        }
    }

    private fun stopVpn() {
        running = false
        isRunning = false
        Handler(Looper.getMainLooper()).removeCallbacks(notificationTicker)
        runCatching { stopForeground(true) }
        reader?.interrupt()
        reader = null
        workers?.shutdownNow()
        workers = null
        cache.clear()
        runCatching { tun?.close() }
        tun = null
        runCatching { BlockLog.flush(this) }
    }

    override fun onRevoke() {
        Log.i(TAG, "用户或系统撤销了 VPN")
        stopVpn()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopVpn()
        instance = null
        super.onDestroy()
    }

    // ---------------------------------------------------------------- 主循环

    /**
     * 手机当前网络（WiFi/流量）下发的 DNS 服务器。
     *
     * 为什么用它们而不是写死公共 DNS：有的家用网络根本到不了 223.5.5.5
     * （被路由器或运营商拦了），那时候所有"放行"的查询都会失败，
     * 而路由器下发的 DNS 必然可达。公共 DNS 仅作为备用排在后面。
     */
    private fun currentNetworkDnsServers(): List<String> {
        return try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return emptyList()
            val lp = cm.getLinkProperties(cm.activeNetwork) ?: return emptyList()
            lp.dnsServers.mapNotNull { it.hostAddress }.distinct()
        } catch (t: Throwable) {
            Log.w(TAG, "取系统 DNS 失败", t)
            emptyList()
        }
    }

    private fun readLoop() {
        val pfd = tun ?: return
        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val buf = ByteArray(MTU + 64)
        val pool = workers
        try {
            while (running) {
                val n = try {
                    input.read(buf)
                } catch (e: IOException) {
                    break
                }
                if (n <= 0) continue
                // 必须拷贝：buf 会被下一次 read 覆盖，而处理是异步的
                val packet = buf.copyOf(n)
                try {
                    pool?.execute { handleOne(packet, output) }
                } catch (e: RejectedExecutionException) {
                    // 停机中，丢弃即可
                }
            }
        } finally {
            runCatching { input.close() }
            runCatching { output.close() }
            // 看门狗：读循环仅在 tun 被系统关闭或发生异常时退出，此处负责重建。
            // 如果用户没有主动关闭，就自动重建 VPN，避免"显示运行中但已经不回包"。
            if (running) {
                Stats.restarts.incrementAndGet()
                Log.w(TAG, "DNS 读循环意外退出，1 秒后自动重建 VPN")
                Handler(Looper.getMainLooper()).postDelayed({
                    if (running) {
                        stopVpn()
                        startVpn()
                    }
                }, 1000)
            }
        }
    }

    private fun handleOne(packet: ByteArray, out: FileOutputStream) {
        Stats.packets.incrementAndGet()
        try {
            val d = Ipv4.parseUdp(packet, packet.size)
            if (d == null || d.dstPort != DNS_PORT || !d.dstIp.contentEquals(dnsIp)) {
                // 非本服务的 UDP DNS 查询。统计其中 DNS over TCP 的数量，
                // 这是目前唯一不支持的协议；占比高意味着有域名会因此解析失败。
                Stats.notDns.incrementAndGet()
                if (packet.size >= 20 && (packet[0].toInt() and 0xF0) == 0x40 &&
                    (packet[9].toInt() and 0xFF) == 6
                ) {
                    Stats.tcpDns.incrementAndGet()
                }
                return
            }

            val query = packet.copyOfRange(d.payloadOffset, d.payloadOffset + d.payloadLength)
            val q = DnsMessage.parseQuestion(query)
            if (q == null) {
                Stats.unparsable.incrementAndGet()
                return
            }

            val verdict = engine.decide(q.name)
            val answer: ByteArray = if (verdict.allowed) {
                Stats.allowed.incrementAndGet()
                // 学习期间记录被放行的域名（非学习状态是空操作）
                LearnedLog.record(verdict.host)
                if (engine.currentMode() == GuardMode.OBSERVE) {
                    BlockLog.record(this, verdict.host)
                }
                resolve(query, q)
            } else {
                Stats.blocked.incrementAndGet()
                BlockLog.record(this, verdict.host)
                DnsMessage.buildNxdomain(query, q)
            }

            val response = DnsProxy.buildReply(d, dnsIp, answer)
            synchronized(writeLock) { out.write(response) }
        } catch (t: Throwable) {
            // 单个包出错不能影响别的包，但要留痕
            Stats.writeErr.incrementAndGet()
            Log.w(TAG, "包处理异常", t)
        }
    }

    /** 先查缓存，再问上游。命中缓存时要把事务 ID 改成当前查询的。 */
    private fun resolve(query: ByteArray, q: DnsQuestion): ByteArray {
        val key = q.name + "|" + q.qtype
        val now = System.currentTimeMillis()

        cache[key]?.let { hit ->
            if (hit.expires > now) {
                val copy = hit.payload.copyOf()
                copy[0] = query[0]
                copy[1] = query[1]
                return copy
            }
            cache.remove(key)
        }

        // 1. 先走 UDP。应答被截断（TC=1）或没应答，就改用 TCP 重查 —— 
        //    早期缺失的一步：客户端收到 TC 后会改用 TCP 连到本服务，
        //    而服务只处理 UDP，该连接必然超时，解析失败。
        //    表现就是"页面能打开、图片/接口加载不出来"。
        var upstream = forward(query)
        if (upstream == null || DnsMessage.isTruncated(upstream)) {
            Stats.tcpRetry.incrementAndGet()
            forwardTcp(query)?.let { upstream = it }
        }

        val result = upstream
        if (result == null) {
            Stats.forwardFail.incrementAndGet()
            return DnsMessage.buildServfail(query, q)
        }

        // 裁到能塞进 tun 的大小，否则整包会被内核丢弃。
        // 注意：这里**不改 TTL** —— 保持上游给的原始有效期，
        // 这样"已经放行过的网站"能按正常节奏留在系统缓存里，不被人为提前作废。
        val fitted = DnsMessage.fitUdp(result)

        if (cache.size >= CACHE_MAX) cache.clear()
        cache[key] = Cached(fitted, now + CACHE_TTL_MS)
        return fitted
    }

    /** 用 TCP 向同一个上游重查（UDP 应答被截断时用）。走 protect 过的 socket。 */
    private fun forwardTcp(queryIn: ByteArray): ByteArray? {
        val query = DnsMessage.clampEdnsUdpSize(queryIn)
        for (up in upstreams) {
            var s: Socket? = null
            try {
                s = Socket()
                if (!protect(s)) continue
                s.soTimeout = 2000
                s.connect(InetSocketAddress(up, DNS_PORT), 2000)
                val out = DataOutputStream(s.getOutputStream())
                out.writeShort(query.size)
                out.write(query)
                out.flush()
                val inp = DataInputStream(s.getInputStream())
                val len = inp.readUnsignedShort()
                if (len <= 0 || len > 4096) continue
                val buf = ByteArray(len)
                inp.readFully(buf)
                return buf
            } catch (t: Throwable) {
                // 换下一个上游
            } finally {
                runCatching { s?.close() }
            }
        }
        return null
    }

    /**
     * 转发给上游。
     *
     * - 每个查询开独立的 protect() socket：并发下共享 socket 会串应答。
     * - 转发前把 EDNS 载荷上限钳到 1232：防止上游回大包撑破隧道 MTU 被丢。
     */
    private fun forward(queryIn: ByteArray): ByteArray? {
        val query = DnsMessage.clampEdnsUdpSize(queryIn)
        for (up in upstreams) {
            var s: DatagramSocket? = null
            try {
                s = DatagramSocket()
                if (!protect(s)) {
                    // protect 失败说明该 socket 会回环至隧道，直接放弃
                    continue
                }
                s.soTimeout = UPSTREAM_TIMEOUT_MS
                s.send(DatagramPacket(query, query.size, InetAddress.getByName(up), DNS_PORT))
                val buf = ByteArray(4096)
                val p = DatagramPacket(buf, buf.size)
                s.receive(p)
                if (p.length > 0) return buf.copyOf(p.length)
            } catch (t: Throwable) {
                // 换下一个上游
            } finally {
                runCatching { s?.close() }
            }
        }
        return null
    }
}
