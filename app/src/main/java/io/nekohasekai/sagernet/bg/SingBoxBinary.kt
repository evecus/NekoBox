package io.nekohasekai.sagernet.bg

import android.content.Context
import android.os.Build
import android.util.Log
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.database.DataStore
import java.io.File

/**
 * Extracts and provides the standalone sing-box binary (libsingbox.so)
 * for root redir/tproxy mode. Built from aazz77/singbox-slim and bundled
 * under assets/singbox/{abi}/libsingbox.so.
 */
object SingBoxBinary {
    private const val TAG = "SingBoxBinary"
    private const val ASSET_NAME = "libsingbox.so"
    private const val BIN_NAME = "libsingbox.so"

    fun isStandaloneMode(): Boolean {
        val mode = DataStore.serviceMode
        return mode == Key.MODE_REDIR || mode == Key.MODE_TPROXY
    }

    /** Resolve preferred ABI for packaged assets. */
    fun preferredAbi(): String {
        val supported = Build.SUPPORTED_ABIS
        val order = listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        for (abi in order) {
            if (supported.contains(abi)) return abi
        }
        return supported.firstOrNull() ?: "arm64-v8a"
    }

    /**
     * Ensure binary exists under filesDir/bin and is executable.
     * Returns absolute path.
     */
    fun ensureBinary(context: Context): File {
        val abi = preferredAbi()
        val outDir = File(context.filesDir, "bin").apply { mkdirs() }
        val out = File(outDir, BIN_NAME)
        val assetPath = "singbox/$abi/$ASSET_NAME"
        // Re-extract if missing or empty
        if (!out.exists() || out.length() == 0L) {
            try {
                context.assets.open(assetPath).use { input ->
                    out.outputStream().use { output -> input.copyTo(output) }
                }
                out.setReadable(true, true)
                out.setExecutable(true, false)
                Log.i(TAG, "Extracted $assetPath -> ${out.absolutePath} (${out.length()} bytes)")
            } catch (e: Exception) {
                throw IllegalStateException(
                    "Missing standalone sing-box binary for ABI $abi ($assetPath). " +
                        "Rebuild core.yml and app.yml so assets include libsingbox.so.",
                    e
                )
            }
        } else {
            out.setExecutable(true, false)
        }
        return out
    }
}
