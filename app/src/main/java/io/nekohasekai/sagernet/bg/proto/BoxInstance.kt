package io.nekohasekai.sagernet.bg.proto

import android.os.SystemClock
import io.nekohasekai.sagernet.SagerNet
import io.nekohasekai.sagernet.bg.AbstractInstance
import io.nekohasekai.sagernet.bg.GuardedProcessPool
import io.nekohasekai.sagernet.bg.SingBoxBinary
import io.nekohasekai.sagernet.database.DataStore
import io.nekohasekai.sagernet.database.ProxyEntity
import io.nekohasekai.sagernet.fmt.ConfigBuildResult
import io.nekohasekai.sagernet.fmt.buildConfig
import io.nekohasekai.sagernet.fmt.hysteria.HysteriaBean
import io.nekohasekai.sagernet.fmt.hysteria.buildHysteria1Config
import io.nekohasekai.sagernet.fmt.mieru.MieruBean
import io.nekohasekai.sagernet.fmt.mieru.buildMieruConfig
import io.nekohasekai.sagernet.fmt.naive.NaiveBean
import io.nekohasekai.sagernet.fmt.naive.buildNaiveConfig
import io.nekohasekai.sagernet.fmt.trojan_go.TrojanGoBean
import io.nekohasekai.sagernet.fmt.trojan_go.buildTrojanGoConfig
import io.nekohasekai.sagernet.ktx.*
import io.nekohasekai.sagernet.plugin.PluginManager
import kotlinx.coroutines.*
import libcore.BoxInstance
import libcore.Libcore
import moe.matsuri.nb4a.net.LocalResolverImpl
import java.io.File
import org.json.JSONArray
import org.json.JSONObject

abstract class BoxInstance(
    val profile: ProxyEntity
) : AbstractInstance {

    lateinit var config: ConfigBuildResult
    lateinit var box: BoxInstance

    val pluginPath = hashMapOf<String, PluginManager.InitResult>()
    val pluginConfigs = hashMapOf<Int, Pair<Int, String>>()
    val externalInstances = hashMapOf<Int, AbstractInstance>()
    open lateinit var processes: GuardedProcessPool
    private var cacheFiles = ArrayList<File>()
    fun isInitialized(): Boolean {
        if (!::config.isInitialized) return false
        if (SingBoxBinary.isStandaloneMode()) return true
        return ::box.isInitialized
    }

    protected fun initPlugin(name: String): PluginManager.InitResult {
        return pluginPath.getOrPut(name) { PluginManager.init(name)!! }
    }

    protected open fun buildConfig() {
        config = buildConfig(profile)
    }

    protected open suspend fun loadConfig() {
        if (SingBoxBinary.isStandaloneMode()) {
            return
        }
        box = Libcore.newSingBoxInstance(config.config, LocalResolverImpl)
    }

    open suspend fun init() {
        buildConfig()
        for ((chain) in config.externalIndex) {
            chain.entries.forEachIndexed { index, (port, profile) ->
                when (val bean = profile.requireBean()) {
                    is TrojanGoBean -> {
                        initPlugin("trojan-go-plugin")
                        pluginConfigs[port] = profile.type to bean.buildTrojanGoConfig(port)
                    }
                    is MieruBean -> {
                        initPlugin("mieru-plugin")
                        pluginConfigs[port] = profile.type to bean.buildMieruConfig(port)
                    }
                    is NaiveBean -> {
                        initPlugin("naive-plugin")
                        pluginConfigs[port] = profile.type to bean.buildNaiveConfig(port)
                    }
                    is HysteriaBean -> {
                        initPlugin("hysteria-plugin")
                        pluginConfigs[port] = profile.type to bean.buildHysteria1Config(port) {
                            File(
                                app.cacheDir, "hysteria_" + SystemClock.elapsedRealtime() + ".ca"
                            ).apply {
                                parentFile?.mkdirs()
                                cacheFiles.add(this)
                            }
                        }
                    }
                }
            }
        }
        loadConfig()
    }

    override fun launch() {
        val cacheDir = File(SagerNet.application.cacheDir, "tmpcfg")
        cacheDir.mkdirs()

        for ((chain) in config.externalIndex) {
            chain.entries.forEachIndexed { index, (port, profile) ->
                val bean = profile.requireBean()
                val (profileType, config) = pluginConfigs[port] ?: (0 to "")

                when {
                    externalInstances.containsKey(port) -> {
                        externalInstances[port]!!.launch()
                    }
                    bean is TrojanGoBean -> {
                        val configFile = File(
                            cacheDir, "trojan_go_" + SystemClock.elapsedRealtime() + ".json"
                        )
                        configFile.parentFile?.mkdirs()
                        configFile.writeText(config)
                        cacheFiles.add(configFile)
                        processes.start(
                            mutableListOf(
                                initPlugin("trojan-go-plugin").path, "-config", configFile.absolutePath
                            )
                        )
                    }
                    bean is MieruBean -> {
                        val configFile = File(
                            cacheDir, "mieru_" + SystemClock.elapsedRealtime() + ".json"
                        )
                        configFile.parentFile?.mkdirs()
                        configFile.writeText(config)
                        cacheFiles.add(configFile)
                        val envMap = mutableMapOf<
                            String, String
                        >()
                        envMap["MIERU_CONFIG_JSON_FILE"] = configFile.absolutePath
                        envMap["MIERU_PROTECT_PATH"] = "protect_path"
                        processes.start(
                            mutableListOf(initPlugin("mieru-plugin").path, "run"), envMap
                        )
                    }
                    bean is NaiveBean -> {
                        val configFile = File(
                            cacheDir, "naive_" + SystemClock.elapsedRealtime() + ".json"
                        )
                        configFile.parentFile?.mkdirs()
                        configFile.writeText(config)
                        cacheFiles.add(configFile)
                        val envMap = mutableMapOf<String, String>()
                        if (bean.certificates.isNotBlank()) {
                            val certFile = File(
                                cacheDir, "naive_" + SystemClock.elapsedRealtime() + ".crt"
                            )
                            certFile.parentFile?.mkdirs()
                            certFile.writeText(bean.certificates)
                            cacheFiles.add(certFile)
                            envMap["SSL_CERT_FILE"] = certFile.absolutePath
                        }
                        processes.start(
                            mutableListOf(initPlugin("naive-plugin").path, configFile.absolutePath),
                            envMap
                        )
                    }
                    bean is HysteriaBean -> {
                        val configFile = File(
                            cacheDir, "hysteria_" + SystemClock.elapsedRealtime() + ".json"
                        )
                        configFile.parentFile?.mkdirs()
                        configFile.writeText(config)
                        cacheFiles.add(configFile)
                        val commands = mutableListOf(
                            initPlugin("hysteria-plugin").path,
                            "--no-check",
                            "--config",
                            configFile.absolutePath,
                            "--log-level",
                            if (DataStore.logLevel > 0) "trace" else "warn",
                            "client"
                        )
                        if (bean.protocol == HysteriaBean.PROTOCOL_FAKETCP) {
                            commands.addAll(0, listOf("su", "-c"))
                        }
                        processes.start(commands)
                    }
                }
            }
        }

        if (SingBoxBinary.isStandaloneMode()) {
            launchStandalone()
        } else {
            box.start()
        }
    }

    private fun launchStandalone() {
        val app = SagerNet.application
        val bin = SingBoxBinary.ensureBinary(app)
        val cfgDir = File(app.filesDir, "singbox_standalone").apply { mkdirs() }
        val cfgFile = File(cfgDir, "config.json")
        val logFile = File(cfgDir, "sing-box.log")
        cfgFile.writeText(sanitizeConfigForStandalone(config.config))
        logFile.writeText("")
        cacheFiles.add(cfgFile)

        val workDir = app.getExternalFilesDir(null) ?: app.filesDir
        val cmd = "cd '${workDir.absolutePath}' && " +
            "exec '${bin.absolutePath}' run -c '${cfgFile.absolutePath}' " +
            ">>'${logFile.absolutePath}' 2>&1"
        Logs.i("standalone sing-box: $cmd")
        processes.start(listOf("su", "-c", cmd))
    }

    private fun sanitizeConfigForStandalone(raw: String): String {
        val root = JSONObject(raw)

        val legacyInboundKeys = listOf(
            "sniff", "sniff_override_destination", "sniff_timeout", "domain_strategy"
        )
        var hadSniff = false
        val inbounds = root.optJSONArray("inbounds")
        if (inbounds != null) {
            for (i in 0 until inbounds.length()) {
                val ib = inbounds.optJSONObject(i) ?: continue
                if (ib.optBoolean("sniff", false)) hadSniff = true
                for (k in legacyInboundKeys) ib.remove(k)
            }
        }
        if (hadSniff) {
            val route = root.optJSONObject("route") ?: JSONObject().also { root.put("route", it) }
            val rules = route.optJSONArray("rules") ?: JSONArray().also { route.put("rules", it) }
            val newRules = JSONArray()
            newRules.put(JSONObject().put("action", "sniff"))
            for (i in 0 until rules.length()) newRules.put(rules.get(i))
            route.put("rules", newRules)
        }

        val dns = root.optJSONObject("dns")
        if (dns != null) {
            dns.remove("independent_cache")
            val fakeipObj = dns.optJSONObject("fakeip")
            val servers = dns.optJSONArray("servers")
            if (servers != null) {
                val migrated = JSONArray()
                var firstStrategy: String? = null
                for (i in 0 until servers.length()) {
                    val s = servers.optJSONObject(i) ?: continue
                    val st = s.optString("strategy", "")
                    if (st.isNotEmpty() && firstStrategy == null) firstStrategy = st
                    s.remove("strategy")
                    migrated.put(migrateDnsServer(s, fakeipObj))
                }
                dns.put("servers", migrated)
                if (!dns.has("strategy") && firstStrategy != null) {
                    dns.put("strategy", firstStrategy)
                }
            }
            dns.remove("fakeip")
            val dnsRules = dns.optJSONArray("rules")
            if (dnsRules != null) {
                for (i in 0 until dnsRules.length()) {
                    val r = dnsRules.optJSONObject(i) ?: continue
                    if (!r.has("action") && r.has("server")) r.put("action", "route")
                }
            }
        }
        return root.toString()
    }

    private fun migrateDnsServer(s: JSONObject, fakeipObj: JSONObject?): JSONObject {
        if (s.has("type") && s.optString("type").isNotEmpty()) {
            if (s.has("address_resolver") && !s.has("domain_resolver")) {
                s.put("domain_resolver", s.remove("address_resolver"))
            }
            s.remove("strategy")
            return s
        }
        val address = s.optString("address", "")
        val out = JSONObject()
        if (s.has("tag")) out.put("tag", s.get("tag"))
        if (s.has("detour")) out.put("detour", s.get("detour"))
        val resolver = when {
            s.has("domain_resolver") -> s.get("domain_resolver")
            s.has("address_resolver") -> s.get("address_resolver")
            else -> null
        }
        if (resolver != null) out.put("domain_resolver", resolver)

        when {
            address == "local" || address.startsWith("local://") -> out.put("type", "local")
            address == "fakeip" || address.startsWith("fakeip") -> {
                out.put("type", "fakeip")
                if (fakeipObj != null) {
                    if (fakeipObj.has("inet4_range")) out.put("inet4_range", fakeipObj.get("inet4_range"))
                    if (fakeipObj.has("inet6_range")) out.put("inet6_range", fakeipObj.get("inet6_range"))
                } else {
                    out.put("inet4_range", "198.18.0.0/15")
                    out.put("inet6_range", "fc00::/18")
                }
            }
            address.startsWith("rcode://") -> out.put("type", "local")
            address.startsWith("dhcp://") -> {
                out.put("type", "dhcp")
                val iface = address.removePrefix("dhcp://")
                if (iface.isNotEmpty() && iface != "auto") out.put("interface", iface)
            }
            address.startsWith("tcp://") -> {
                out.put("type", "tcp"); out.put("server", stripDnsHost(address.removePrefix("tcp://")))
            }
            address.startsWith("udp://") -> {
                out.put("type", "udp"); out.put("server", stripDnsHost(address.removePrefix("udp://")))
            }
            address.startsWith("tls://") -> {
                out.put("type", "tls"); out.put("server", stripDnsHost(address.removePrefix("tls://")))
            }
            address.startsWith("quic://") -> {
                out.put("type", "quic"); out.put("server", stripDnsHost(address.removePrefix("quic://")))
            }
            address.startsWith("https://") -> {
                out.put("type", "https"); putHttpsDnsServer(out, address.removePrefix("https://"))
            }
            address.startsWith("h3://") -> {
                out.put("type", "h3"); putHttpsDnsServer(out, address.removePrefix("h3://"))
            }
            address.contains("://") -> {
                out.put("type", "udp"); out.put("server", stripDnsHost(address.substringAfter("://")))
            }
            else -> {
                out.put("type", "udp"); out.put("server", stripDnsHost(address))
            }
        }
        return out
    }

    private fun stripDnsHost(raw: String): String {
        var h = raw.trim()
        if (h.contains("/")) h = h.substringBefore("/")
        if (h.startsWith("[")) return h.substringAfter("[").substringBefore("]")
        if (h.count { it == ':' } == 1) {
            if (h.substringAfter(":").toIntOrNull() != null) return h.substringBefore(":")
        }
        return h
    }

    private fun putHttpsDnsServer(out: JSONObject, rest: String) {
        val pathPart = if (rest.contains("/")) "/" + rest.substringAfter("/") else ""
        out.put("server", stripDnsHost(rest.substringBefore("/")))
        if (pathPart.isNotEmpty() && pathPart != "/dns-query") out.put("path", pathPart)
    }

    @Suppress("EXPERIMENTAL_API_USAGE")
    override fun close() {
        for (instance in externalInstances.values) {
            runCatching { instance.close() }
        }
        cacheFiles.removeAll { it.delete(); true }
        if (::processes.isInitialized) processes.close(GlobalScope + Dispatchers.IO)
        if (::box.isInitialized) box.close()
    }

}
