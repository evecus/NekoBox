package io.nekohasekai.sagernet.bg

import android.annotation.SuppressLint
import android.app.Service
import android.content.Intent
import android.os.PowerManager
import android.util.Log
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore

class TransProxyService : Service(), BaseService.Interface {
    override val data = BaseService.Data(this)
    override val tag: String get() = "NekoBoxTransProxyService"
    override fun createNotification(profileName: String): ServiceNotification =
        ServiceNotification(this, profileName, "service-proxy", true)

    override var wakeLock: PowerManager.WakeLock? = null
    override var upstreamInterfaceName: String? = null

    @SuppressLint("WakelockTimeout")
    override fun acquireWakeLock() {
        wakeLock = SagerNet.power.newWakeLock(
            PowerManager.PARTIAL_WAKE_LOCK, "sagernet:transproxy"
        ).apply { acquire() }
    }

    override fun onBind(intent: Intent) = super.onBind(intent)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int =
        super<BaseService.Interface>.onStartCommand(intent, flags, startId)

    // iptables pre-clean: clear any leftover rules before sing-box starts (override preInit)
    override suspend fun preInit() {
        runIptables("stop")   // no-op if rules don't exist; cleans up if last stop was missed
        super.preInit()
    }

    // iptables start: after sing-box is up (override lateInit)
    override suspend fun lateInit() {
        super.lateInit()
        runIptables("start")
    }

    // iptables stop: before sing-box teardown (override stopRunner)
    override fun stopRunner(restart: Boolean, msg: String?) {
        runIptables("stop")
        super.stopRunner(restart, msg)
    }

    private fun runIptables(action: String) {
        val tproxyPort = DataStore.tproxyPort
        val dnsPort = 10336
        val appUid = applicationInfo.uid

        val script = when (DataStore.serviceMode) {
            Key.MODE_TPROXY -> IptablesRules.tproxy(action, tproxyPort, dnsPort, appUid)
            else            -> IptablesRules.redir(action, tproxyPort, dnsPort, appUid)
        }

        try {
            // Feed the script to `su` via stdin — single root grant, no temp file needed.
            val proc = Runtime.getRuntime().exec(arrayOf("su"))
            proc.outputStream.bufferedWriter().use { it.write(script) }
            val exitCode = proc.waitFor()
            val err = proc.errorStream.bufferedReader().readText()
            if (exitCode != 0) {
                Log.e(tag, "iptables $action failed (exit=$exitCode): $err")
            } else {
                Log.i(tag, "iptables $action ok")
            }
        } catch (e: Exception) {
            Log.e(tag, "runIptables $action failed: ${e.message}")
        }
    }
}
