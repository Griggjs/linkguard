package com.linkguard.blocker

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * 开机自启。
 *
 * 只有在"上次是开着的"并且 VPN 授权仍然有效时才启动。
 * 启动失败不抛异常——开机广播里崩溃会让系统记一笔，没必要。
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!Prefs.wasEnabled(context)) return
        if (VpnService.prepare(context) != null) return

        runCatching { GuardVpnService.start(context) }
            .onFailure { Log.w("GuardVpn", "开机自启失败", it) }
    }
}
