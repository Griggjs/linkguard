# -*- coding: utf-8 -*-
"""
静态规则数据层。

这里放的是"不联网也能判断"的知识：
- 哪些后缀名天生容易被批量注册来钓鱼
- 哪些品牌词不允许出现在别人的域名里
- 哪些文件扩展名一旦出现就基本可以直接拦（装上去就是木马）
- 诈骗话术里高频出现的词
- 家喻户晓的短链服务域名

数据来源说明见 docs/01-威胁模型.md，更新方式见 `python -m linkguard feeds --help`。
这个文件只放数据 + 极少量纯函数，不做网络访问，方便单元测试。
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# 1. 高风险顶级域 / 二级后缀
# ---------------------------------------------------------------------------
# 这些后缀注册便宜、批量注册门槛低，是钓鱼站的集中地。
# 注意：其中 tv/cc/top/vip/xin 等在国内也有正规站点在用，所以权重给得低，
# 只作为"加分项"，不单独构成拦截理由，避免误伤。
SUSPICIOUS_TLDS: dict[str, int] = {
    # 批量注册重灾区
    "top": 22, "xyz": 22, "icu": 22, "buzz": 20, "cyou": 24, "sbs": 24,
    "cfd": 24, "monster": 20, "quest": 20, "rest": 20, "lol": 20,
    "autos": 20, "bond": 20, "boats": 20, "hair": 20, "makeup": 20,
    "skin": 20, "beauty": 20, "cam": 22, "click": 20, "fit": 18,
    "gq": 26, "ml": 26, "cf": 26, "ga": 26, "tk": 26,
    # 常见但滥用率高的通用后缀
    "cc": 12, "tv": 10, "vip": 12, "xin": 12, "work": 14, "link": 12,
    "live": 10, "shop": 8, "site": 14, "online": 14, "store": 14,
    "space": 16, "website": 16, "host": 16, "press": 16, "fun": 14,
    "club": 14, "wang": 10, "men": 14, "loan": 20, "bid": 18, "win": 18,
    "date": 20, "racing": 20, "stream": 16, "download": 20, "review": 18,
    "trade": 16, "party": 16, "science": 16, "ink": 14, "tech": 6,
}

# ---------------------------------------------------------------------------
# 2. 可信站点白名单（对"该域及其所有子域"生效）
# ---------------------------------------------------------------------------
# 白名单的作用是"抵消"可疑特征，避免把银行官网自己判成危险。
# 但它不是免死金牌：命中白名单只给负分，不会让 .apk 直链直接放行。
ALLOWLIST_DOMAINS: set[str] = {
    # 政务 / 公共事业 / 教育
    "gov.cn", "12345.gov.cn", "12306.cn", "chinatax.gov.cn", "nmpa.gov.cn",
    "mps.gov.cn", "12377.cn", "cyberpolice.cn", "edu.cn", "ac.cn",
    # 银行 / 支付
    "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankcomm.com",
    "cmbchina.com", "psbc.com", "spdb.com.cn", "cib.com.cn", "citicbank.com",
    "cebbank.com", "hxb.com.cn", "cmbc.com.cn", "pingan.com", "unionpay.com",
    "alipay.com", "95588.com", "95533.com",
    # 运营商
    "10086.cn", "10010.com", "189.cn", "chinamobile.com", "chinatelecom.com.cn",
    "chinaunicom.com.cn", "wo.cn",
    # 大厂常用域
    "weixin.qq.com", "wechat.com", "weixin.com", "qq.com", "tencent.com",
    "alibaba.com", "aliyun.com", "taobao.com", "tmall.com", "tmall.hk",
    "jd.com", "jd.hk", "pinduoduo.com", "yangkeduo.com", "douyin.com",
    "kuaishou.com", "bilibili.com", "meituan.com", "dianping.com", "ele.me",
    "ctrip.com", "qunar.com", "didiglobal.com", "amap.com", "baidu.com",
    "sina.com.cn", "weibo.com", "weibo.cn", "sohu.com", "163.com", "126.com",
    "iqiyi.com", "youku.com", "mgtv.com", "xiaomi.com", "mi.com",
    "huawei.com", "honor.com", "oppo.com", "vivo.com", "oneplus.com",
    "apple.com", "icloud.com", "microsoft.com", "windowsupdate.com",
    "google.com", "youtube.com", "wikipedia.org",
    # 常用工具 / 开源
    "github.com", "githubusercontent.com", "python.org", "pypi.org",
    "adobe.com", "wps.cn", "kdocs.cn", "feishu.cn", "dingtalk.com",
    "sf-express.com", "yto.net.cn", "zto.com", "ems.com.cn", "sto.cn",
}

# ---------------------------------------------------------------------------
# 3. 品牌词 -> 官方注册域
# ---------------------------------------------------------------------------
# 判定逻辑：域名里出现了品牌词，但这个域名又不是该品牌的官方域（或其子域）
# -> 极可能是仿冒。这是钓鱼识别里性价比最高的一条规则。
BRANDS: dict[str, set[str]] = {
    "icbc": {"icbc.com.cn"},
    "ccb": {"ccb.com"},
    "abchina": {"abchina.com"},
    "bankofchina": {"boc.cn"},
    "boc": {"boc.cn"},
    "bankcomm": {"bankcomm.com"},
    "cmbchina": {"cmbchina.com"},
    "psbc": {"psbc.com"},
    "unionpay": {"unionpay.com"},
    "alipay": {"alipay.com"},
    "taobao": {"taobao.com"},
    "tmall": {"tmall.com"},
    "pinduoduo": {"pinduoduo.com"},
    "douyin": {"douyin.com"},
    "kuaishou": {"kuaishou.com"},
    "weixin": {"weixin.qq.com", "weixin.com"},
    "wechat": {"wechat.com", "weixin.qq.com"},
    "12306": {"12306.cn"},
    "10086": {"10086.cn"},
    "chinamobile": {"10086.cn"},
    "chinatelecom": {"189.cn", "chinatelecom.com.cn"},
    "chinaunicom": {"10010.com", "chinaunicom.com.cn"},
    "gov": {"gov.cn"},
    "jd": {"jd.com"},
}

# 品牌词太短会大量误伤（例如 "jd"、"boc" 出现在随机串里），
# 短于该长度的品牌词只做"标签完全相等"匹配，不做包含匹配。
BRAND_MIN_SUBSTRING_LEN = 4

# ---------------------------------------------------------------------------
# 4. 一出现就该拦的文件类型
# ---------------------------------------------------------------------------
# 手机上"点链接 -> 下载安装包 -> 装上木马"是最主流的入侵路径。
# 这些后缀不是"可能危险"，是"正常人不会从链接里装它"。
DANGEROUS_EXTENSIONS: dict[str, int] = {
    "apk": 70, "apks": 70, "xapk": 70, "apkm": 70,
    "exe": 70, "msi": 70, "scr": 70, "pif": 70, "com": 60,
    "bat": 70, "cmd": 70, "vbs": 70, "vbe": 70, "js": 55, "jse": 70,
    "jar": 70, "lnk": 70, "hta": 70, "reg": 60, "ps1": 60, "dll": 65,
    "ipa": 60,
    # iOS 描述文件：装上就可能被装上根证书 / 受远程管控
    "mobileconfig": 70, "mobileprovision": 60,
}

# ---------------------------------------------------------------------------
# 5. 诈骗话术关键词（出现在路径或查询串里）
# ---------------------------------------------------------------------------
# 仿冒页面的 URL 经常直接写着它想让你干什么。
# 权重低，只作加分项：正规站的登录页也会出现 login。
SCAM_KEYWORDS: dict[str, int] = {
    # 英文
    "login": 10, "signin": 10, "verify": 14, "verification": 14,
    "account": 8, "secure": 10, "security": 10, "confirm": 12,
    "unlock": 14, "activate": 14, "bonus": 16, "prize": 18, "gift": 14,
    "reward": 14, "refund": 16, "lottery": 20, "winner": 18, "free": 8,
    "auth": 10, "wallet": 12, "payment": 12, "bank": 12, "card": 8,
    "idcard": 20, "otp": 18, "reset": 12, "password": 14, "pwd": 12,
    "bind": 12, "realname": 18, "kyc": 16, "appeal": 16,
    # 中文（URL 里通常会被百分号编码，analyzer 会先解码）
    "实名": 18, "认证": 16, "验证": 14, "解封": 22, "激活": 16,
    "领取": 18, "中奖": 22, "退款": 18, "客服": 16, "安全中心": 18,
    "冻结": 20, "涉案": 24, "洗钱": 24, "升级": 10, "补贴": 18,
    "红包": 16, "提现": 18, "借贷": 16, "征信": 20, "医保": 18,
    "社保": 16, "快递": 12, "理赔": 20, "保障": 12, "通道": 10,
    "工本费": 24, "保证金": 24, "解冻": 22, "刷单": 24, "返利": 22,
}

# ---------------------------------------------------------------------------
# 6. 短链服务
# ---------------------------------------------------------------------------
# 短链本身不是恶意的，但它隐藏了真实去向，必须展开后再判断。
SHORTENER_DOMAINS: set[str] = {
    "t.cn", "dwz.cn", "url.cn", "w.url.cn", "suo.im", "sinaurl.cn",
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "s.id", "t.co", "tiny.cc", "shorturl.at",
    "6url.cn", "94c.cn", "rrd.me", "m.tb.cn", "u.nu", "kutt.it",
    "dlvr.it", "rb.gy", "shorte.st", "adf.ly", "zzb.bz", "y6.nz",
}

# ---------------------------------------------------------------------------
# 7. 各种表示"多段"的公共后缀，用于取"可注册域"
# ---------------------------------------------------------------------------
# 完整公共后缀列表有十几万条，这里只收国内最常见的多段后缀。
# 取可注册域的目的：判断"evil.com.cn" 到底注册在谁名下。
MULTI_PART_SUFFIXES: set[str] = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn", "mil.cn",
    "com.hk", "org.hk", "net.hk", "edu.hk", "gov.hk", "com.tw", "org.tw",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp",
    "co.kr", "or.kr", "com.au", "net.au", "org.au", "co.nz", "com.sg",
    "com.my", "co.th", "com.ph", "co.id", "com.vn", "com.br", "co.in",
    "com.ru", "com.tr", "com.mx", "com.ar", "co.za", "com.sa", "com.eg",
    "com.ua", "com.pl", "com.es", "com.it", "com.fr", "com.de",
}

# ---------------------------------------------------------------------------
# 8. 纯粹的常量
# ---------------------------------------------------------------------------
# 判定阈值（分数越高越危险）
VERDICT_BLOCK_AT = 55
VERDICT_WARN_AT = 30

# 允许出现的端口，其它端口视为可疑
COMMON_PORTS = {80, 443, 8443, 8080, 8000}

# 出现在 authority 里的伪协议（手机上是真实攻击面）
DANGEROUS_SCHEMES: dict[str, int] = {
    "javascript": 75,
    "data": 75,
    "vbscript": 75,
    "file": 65,
    "intent": 60,       # Android intent://，可直接拉起任意组件
    "content": 55,
    "blob": 40,
}

# 允许分析的非 http 协议（这些是"浏览器能打开"的，可以放行协议本身）
ANALYZABLE_SCHEMES = {"http", "https"}

# 常见端口 -> 名称，仅用于生成人话
PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3389: "远程桌面"}
