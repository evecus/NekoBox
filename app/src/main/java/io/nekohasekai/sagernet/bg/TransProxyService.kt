package io.nekohasekai.sagernet.bg

import android.annotation.SuppressLint
import android.app.Service
import android.content.Intent
import android.os.PowerManager
import android.util.Log
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.database.DataStore
import java.io.File

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
        val isRedir = DataStore.serviceMode == Key.MODE_REDIR
        val scriptName = if (isRedir) "nekobox.redir" else "nekobox.tproxy"
        val scriptFile = File(filesDir, scriptName)

        try {
            assets.open("scripts/$scriptName").use { input ->
                scriptFile.outputStream().use { output -> input.copyTo(output) }
            }
            scriptFile.setExecutable(true)
        } catch (e: Exception) {
            Log.e(tag, "Failed to copy $scriptName: ${e.message}")
            return
        }

        val appUid = applicationInfo.uid
        val cmd = "APP_UID=$appUid TPROXY_PORT=${DataStore.tproxyPort} sh ${scriptFile.absolutePath} $action"
        try {
            val proc = Runtime.getRuntime().exec(arrayOf("su", "-c", cmd))
            val exitCode = proc.waitFor()
            val err = proc.errorStream.bufferedReader().readText()
            if (exitCode != 0) {
                Log.e(tag, "$scriptName $action failed (exit=$exitCode): $err")
            } else {
                Log.i(tag, "$scriptName $action ok")
            }
        } catch (e: Exception) {
            Log.e(tag, "exec su failed: ${e.message}")
        }
    }
}
