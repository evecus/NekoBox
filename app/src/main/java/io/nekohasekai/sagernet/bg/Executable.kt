package io.nekohasekai.sagernet.bg

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import io.nekohasekai.sagernet.ktx.Logs
import java.io.File
import java.io.IOException
import androidx.core.text.isDigitsOnly

object Executable {
    private val EXECUTABLES = setOf(
        "libtrojan.so", "libtrojan-go.so", "libnaive.so", "libtuic.so", "libhysteria.so",
        "libsingbox.so"
    )

    fun killAll(alsoKillBg: Boolean = false) {
        // kill bg may fail
        for (process in File("/proc").listFiles { _, name -> name.isDigitsOnly() } ?: return) {
            val exe = File(
                try {
                File(process, "cmdline").inputStream().bufferedReader().use {
                    it.readText()
                }
            } catch (_: IOException) {
                continue
            }.split(Character.MIN_VALUE, limit = 2).first())
            if (EXECUTABLES.contains(exe.name) || (alsoKillBg && exe.name.endsWith(":bg"))) try {
                Os.kill(process.name.toInt(), OsConstants.SIGKILL)
                Logs.w("SIGKILL ${exe.name} (${process.name}) succeed")
            } catch (e: ErrnoException) {
                if (e.errno == OsConstants.EPERM) {
                    // Process is owned by root (standalone redir/tproxy mode).
                    // Os.kill() is blocked by permission; fall back to `su -c kill`.
                    try {
                        Runtime.getRuntime()
                            .exec(arrayOf("su", "-c", "kill -KILL ${process.name}"))
                            .waitFor()
                        Logs.w("su SIGKILL ${exe.name} (${process.name}) sent")
                    } catch (ex: Exception) {
                        Logs.w("su SIGKILL ${exe.name} (${process.name}) failed: ${ex.message}")
                    }
                } else if (e.errno != OsConstants.ESRCH) {
                    Logs.w("SIGKILL ${exe.absolutePath} (${process.name}) failed")
                    Logs.w(e)
                }
            }
        }
    }
}
