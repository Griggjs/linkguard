package com.linkguard.blocker

/**
 * 内置名单。
 *
 * ⚠️ 这些域名是**草稿**，不是权威数据。原因：
 *   - 一个网站实际会连接十几个域名（图片 CDN、登录、支付各有一套），无法仅凭文档穷举；
 *   - 各地社保、医院、学校用的是地方域名，不可能预先知道。
 *
 * 所以设计上必须接受"第一次装上会有网站打不开"，靠 App 里的拦截日志补。
 * 补的方式：子女在「被拦记录」里看到某个域名，点一下加入允许名单。
 */
object BuiltinRules {

    /**
     * 系统必需。这些不能删，删了手机会显示"已连接但无法访问互联网"，
     * 推送、应用商店、时间同步全废。
     *
     * 按厂商分组：严格模式下系统自身的联网、推送、应用商店、时间同步都会被拦，
     * 所以必须按品牌预置。覆盖国产手机使用量前五的品牌（不含苹果）。
     */
    val SYSTEM: List<String> = listOf(
        // ── 小米 / Redmi（HyperOS / MIUI）
        "miui.com", "xiaomi.com", "mi.com", "mipush.com", "miui.net",
        "miimg.com", "xiaomi.net", "mi-idc.com",

        // ── 华为 / 荣耀（HMS 推送、应用市场、云空间）
        "huawei.com", "huawei.com.cn", "hicloud.com",
        "honor.com", "hihonor.com",

        // ── OPPO / 一加 / realme（ColorOS、HeyTap 推送与应用商店）
        "oppo.com", "oppomobile.com", "heytap.com", "heytapmobi.com",
        "coloros.com", "oneplus.com", "oneplus.net", "realme.com",

        // ── vivo / iQOO
        "vivo.com", "vivo.com.cn", "iqoo.com",

        // ── Android 通用：联网检测与时间同步
        "connectivitycheck.gstatic.com",
        "connectivitycheck.android.com",
        "time.android.com",
        // 时间同步：拦了会让系统时间漂移，后果是 HTTPS 证书校验失败，
        // 表现成各种莫名其妙的"网络错误"。
        "ntp.org",
        "time.asia.apple.com",

        // ── 云服务 SDK（推送 / 短信验证码 / 对象存储常用）
        "aliyun.com",

        // ── 运营商（VoLTE 语音、短信、流量查询）
        "10086.cn", "chinamobile.com", "10010.com", "189.cn", "wo.cn"
    )

    /**
     * 生活必须。用户明确选择"A：只放生活必须那组"以外的 B（加了短视频），
     * 所以短视频那组在下面单独列。
     */
    val LIFE: List<String> = listOf(
        // 微信（含公众号、小程序、登录、支付）
        "qq.com", "weixin.com", "wechat.com",
        "qpic.cn", "gtimg.cn", "qlogo.cn", "servicewechat.com",

        // 支付（用户选择放行：能付款、扫码、转账）
        "tenpay.com", "alipay.com", "alipayobjects.com",

        // 银行
        "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankcomm.com",
        "cmbchina.com", "psbc.com", "spdb.com.cn", "cib.com.cn",
        "citicbank.com", "cebbank.com", "hxb.com.cn", "cmbc.com.cn",
        "pingan.com", "unionpay.com", "95588.com", "95533.com",

        // 出行 / 政务 / 医保 / 社保（gov.cn 是上级域，覆盖各地政务）
        "12306.cn", "gov.cn", "nhsa.gov.cn",

        // 地图导航
        "amap.com", "autonavi.com", "gaode.com",
        "baidu.com", "bdstatic.com", "bdimg.com", "bcebos.com",

        // 天气
        "weather.com.cn", "qweather.com",

        // 新闻资讯
        "toutiao.com", "163.com", "sina.com.cn", "weibo.com", "weibo.cn",
        "sohu.com", "ifeng.com",

        // 快递
        "sf-express.com", "kuaidi100.com", "yto.net.cn", "zto.com",
        "sto.cn", "ems.com.cn", "yundaex.com", "jtexpress.com",

        // ── v1.4 按实测被拦记录补的（都是"拦错了"的功能域名）─────────────
        // 微信支付通道（实测被拦 5 次/分钟，支付要能用）
        "wechatpay.cn",
        // 大众点评 / 美团的图片 CDN（实测被拦，图片白屏的元凶之一）
        "dpfile.com",
        // 肯德基 App 的登录域（和官网 kfc.com.cn 不是同一个）
        "kfcapp.cn",
        // 网易 CDN（126.net 已加，127.net 是另一套，网易云音乐/有道在用）
        "127.net",
        // QQ 音乐（ad.tencentmusic.com 继续由广告名单拦）
        "tencentmusic.com",
        // 极光推送。拦了通知和活动弹窗都不来 —— 对老人来说通知更重要
        "jpush.cn", "jpush.io",
        // 快手开放平台
        "kwaizt.com", "kuaishouzt.com",
        // 华为云直播拉流
        "livehwc3.cn",

        // ── v2.0 按第二轮实测被拦记录补的 ────────────────────────────────
        // 携程（之前整个漏了）
        "ctrip.com", "c-ctrip.com",
        // 途家（民宿）图片
        "tujia.com",
        // 微信直播 / 视频号的拉流 CDN（实测被拦了 12 个 pull-* 节点）
        "wxlivecdn.com",
        // 腾讯云 COS / 视频点播。**这一条会放行腾讯云的所有 bucket**，
        // 这确实扩大了放行范围，但微信视频与腾讯云视频依赖它，不放行会导致功能不可用。
        "myqcloud.com",
        // 视频点播 CDN（实测 img./vod.300hu.com）
        "300hu.com",
        // 小米小爱同学（语音助手、语音识别）
        "xiaomixiaoai.com",
        // 中国移动一键登录 / 号码认证
        "id6.me", "cmpassport.com"
    )

    /**
     * 短视频（用户选择 B：放行抖音/快手）。
     *
     * 这两个 App 依赖几十个域名，此处只保留最小可用集，
     * 大概率第一次装上会有部分内容加载不出来 —— 用拦截日志补。
     */
    val SHORT_VIDEO: List<String> = listOf(
        // 抖音 / 字节系
        "douyin.com", "douyinvod.com", "douyinpic.com", "douyincdn.com",
        "byteimg.com", "bytedance.com", "snssdk.com", "amemv.com",
        "ibytedtos.com", "pstatp.com", "ixigua.com",
        // 快手
        "kuaishou.com", "kwimgs.com", "gifshow.com", "kwaicdn.com",
        "yximgs.com"
    )

    /**
     * 电商 / 生活服务（v1.1 加入）。
     *
     * 起初按"只放生活必须"设计，但实测下来这些是老人真正在用的，被拦会直接影响日常使用。
     * 每个条目后面标了它大概是什么，方便以后删。
     */
    val SHOPPING: List<String> = listOf(
        // 淘宝 / 天猫（alicdn 为阿里共享图片 CDN，无法省略）
        "taobao.com", "tmall.com", "tbcdn.cn", "alicdn.com",
        // 拼多多
        "pinduoduo.com", "yangkeduo.com", "pddpic.com",
        // 京东
        "jd.com", "360buyimg.com", "jdpay.com", "jd.hk",
        // 美团 / 大众点评
        "meituan.com", "meituan.net", "sankuai.com", "dianping.com",
        // 去哪儿
        "qunar.com", "qunarzz.com",
        // 肯德基
        "kfc.com.cn", "yumchina.com",
        // 有道词典（126.net 是网易的 CDN）
        "youdao.com", "ydstatic.com", "126.net"
    )

    /**
     * 广告 / 推广 / 统计域名。**优先级高于允许名单**——即使父域被放行，这些也拦。
     *
     * 这是"区分 App 内部混进来的不明链接"的主要手段：
     * 外部落地页靠白名单本身就能挡，但广告素材和跳转常挂在已放行的大域名下
     * （比如 qq.com、taobao.com、baidu.com），只能按子域精确封。
     *
     * 取舍：只封"广告/统计"，**故意不封推送 SDK**（jpush / getui / igexin / bugly）——
     * 那些一封，应用可能启动卡死或收不到通知，且无法在手机上快速回滚。
     *
     * 还有个总开关（设置里可关）：万一某个 App 因为少了广告接口而打不开，
     * 关掉整个广告拦截就能恢复。
     */
    val AD_NETWORKS: List<String> = listOf(
        // 阿里妈妈 / 淘宝广告 / 阿里统计
        "tanx.com", "alimama.com", "mmstat.com", "simba.taobao.com",
        // 腾讯广点通 / 优量汇
        "e.qq.com", "gdt.qq.com", "ad.qq.com", "adsmind.gdt.qq.com",
        // 字节穿山甲
        "pangle.io", "pangolin-sdk-toutiao.com", "ad.toutiao.com",
        // 百度联盟
        "pos.baidu.com", "cpro.baidu.com",
        // 京东联盟
        "union.jd.com",
        // 国际通用广告/归因
        "doubleclick.net", "googlesyndication.com", "google-analytics.com",
        "app-measurement.com", "adjust.com", "appsflyer.com", "branch.io",
        // 国内统计类域名（不含推送服务，避免影响应用可用性）
        "cnzz.com", "umeng.com", "mob.com",
        // QQ 音乐的开屏广告（父域 tencentmusic.com 已放行，这里单独拦）
        "ad.tencentmusic.com"
    )

    /** 明确要拦的（即使被误加进允许名单也拦）。默认拒绝已经能挡住一切，这里只放极少数。 */
    val HARD_DENY: List<String> = emptyList()

    val ALL: List<String> = SYSTEM + LIFE + SHORT_VIDEO + SHOPPING

    fun buildAllowSet(extra: Collection<String> = emptyList()): DomainSet {
        val set = DomainSet(ALL)
        extra.forEach { set.add(it) }
        return set
    }

    /** 黑名单 = 强制拦截项 + 广告网络。广告拦截可在设置中关闭。 */
    fun buildDenySet(includeAds: Boolean = true): DomainSet {
        val set = DomainSet(HARD_DENY)
        if (includeAds) AD_NETWORKS.forEach { set.add(it) }
        return set
    }
}
