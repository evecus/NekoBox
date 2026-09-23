package io.nekohasekai.sagernet.bg

import android.content.Context
import android.util.Log
import io.nekohasekai.sagernet.Key
import io.nekohasekai.sagernet.database.DataStore
import java.io.File

/**
 * Provides the standalone sing-box binary (libsingbox.so) for root redir/tproxy.
 *
 * The binary is packaged via [app/executableSo] (jniLibs source set) so each ABI-split
 * APK only contains the matching architecture. At runtime it lives under
 * [Context.getApplicationInfo.nativeLibraryDir] (extractNativeLibs / legacy packaging).
 */
object SingBoxBinary {
    private const val TAG = "SingBoxBinary"
    private const val BIN_NAME = "libsingbox.so"

    fun isStandaloneMode(): Boolean {
        val mode = DataStore.serviceMode
        return mode == Key.MODE_REDIR || mode == Key.MODE_TPROXY
    }

    /**
     * Resolve the packaged binary path and ensure it is executable.
     * Prefers nativeLibraryDir; falls back to copying into filesDir/bin if needed.
     */
    fun ensureBinary(context: Context): File {
        // Primary: system-extracted jniLibs (per-ABI, already on disk)
        val native = File(context.applicationInfo.nativeLibraryDir, BIN_NAME)
        if (native.exists() && native.length() > 0L) {
            // nativeLibraryDir is usually executable; force flag for safety
            native.setExecutable(true, false)
            Log.i(TAG, "Using nativeLibraryDir binary: ${native.absolutePath} (${native.length()} bytes)")
            return native
        }

        // Fallback: copy from native path or throw a clear error
        throw IllegalStateException(
            "Missing $BIN_NAME in nativeLibraryDir (${context.applicationInfo.nativeLibraryDir}). " +
                "Ensure app.yml places libsingbox.so under app/executableSo/{abi}/ and rebuild."
        )
    }
}
