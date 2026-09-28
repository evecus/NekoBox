package io.nekohasekai.sagernet.bg

object IptablesRules {

    // mark 100 (0x64): set on sing-box outbound packets via route.default_mark
    // must match the value in ConfigBuilder (0x64) and the RETURN rules below
    private const val SING_MARK = 100
    private const val MARK_VALUE = 200
    private const val TABLE_ID = 200

    // Shared chain names across v4/v6 and across modes, so the unified cleanup()
    // can remove any residue regardless of which mode (or mode switch) created it.
    private const val CHAIN_TP = "NEKOBOX_TP"    // tproxy: mangle PREROUTING
    private const val CHAIN_RD = "NEKOBOX_RD"    // redir: nat PREROUTING
    private const val CHAIN_DNS = "NEKOBOX_DNS"  // both: nat OUTPUT DNS hijack

    fun tproxy(action: String, tproxyPort: Int, dnsPort: Int, appUid: Int): String =
        if (action == "start") tproxyStart(tproxyPort, dnsPort, appUid) else cleanup(dnsPort)

    fun redir(action: String, tproxyPort: Int, dnsPort: Int, appUid: Int): String =
        if (action == "start") redirStart(tproxyPort, dnsPort, appUid) else cleanup(dnsPort)

    // ─────────────────────────── tproxy start ───────────────────────────

    private fun tproxyStart(tproxyPort: Int, dnsPort: Int, appUid: Int): String = """
        TPROXY_PORT=$tproxyPort
        DNS_PORT=$dnsPort
        APP_UID=$appUid
        MARK_VALUE=$MARK_VALUE
        TABLE_ID=$TABLE_ID
        SING_MARK=$SING_MARK
        CHAIN=$CHAIN_TP
        CHAIN_DNS=$CHAIN_DNS

        # ---- IPv4 ----
        ip rule add fwmark ${'$'}MARK_VALUE table ${'$'}TABLE_ID pref ${'$'}TABLE_ID 2>/dev/null || true
        ip route add local 0.0.0.0/0 dev lo table ${'$'}TABLE_ID 2>/dev/null || true
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

        iptables -t nat -N ${'$'}CHAIN_DNS 2>/dev/null
        iptables -t nat -F ${'$'}CHAIN_DNS
        iptables -t nat -A ${'$'}CHAIN_DNS -m mark --mark ${'$'}SING_MARK -j RETURN
        [ "${'$'}APP_UID" != "0" ] && iptables -t nat -A ${'$'}CHAIN_DNS -m owner --uid-owner ${'$'}APP_UID -j RETURN
        iptables -t nat -A ${'$'}CHAIN_DNS -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
        iptables -t nat -A ${'$'}CHAIN_DNS -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
        iptables -t nat -I OUTPUT -j ${'$'}CHAIN_DNS
        iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
        iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT

        iptables -t mangle -N ${'$'}CHAIN 2>/dev/null
        iptables -t mangle -F ${'$'}CHAIN
        iptables -t mangle -A ${'$'}CHAIN -m mark --mark ${'$'}SING_MARK -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 127.0.0.0/8    -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 10.0.0.0/8     -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 172.16.0.0/12  -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 192.168.0.0/16 -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 169.254.0.0/16 -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 224.0.0.0/4    -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -d 240.0.0.0/4    -j RETURN
        iptables -t mangle -A ${'$'}CHAIN -p tcp -j TPROXY --on-ip 127.0.0.1 --on-port ${'$'}TPROXY_PORT --tproxy-mark ${'$'}MARK_VALUE
        iptables -t mangle -A ${'$'}CHAIN -p udp -j TPROXY --on-ip 127.0.0.1 --on-port ${'$'}TPROXY_PORT --tproxy-mark ${'$'}MARK_VALUE
        iptables -t mangle -I PREROUTING -p tcp -j ${'$'}CHAIN
        iptables -t mangle -I PREROUTING -p udp -j ${'$'}CHAIN

        iptables -t mangle -N ${'$'}{CHAIN}_OUT 2>/dev/null
        iptables -t mangle -F ${'$'}{CHAIN}_OUT
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -m mark --mark ${'$'}SING_MARK -j RETURN
        [ "${'$'}APP_UID" != "0" ] && iptables -t mangle -A ${'$'}{CHAIN}_OUT -m owner --uid-owner ${'$'}APP_UID -j RETURN
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -d 127.0.0.0/8    -j RETURN
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -d 10.0.0.0/8     -j RETURN
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -d 172.16.0.0/12  -j RETURN
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -d 192.168.0.0/16 -j RETURN
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -p tcp -j MARK --set-mark ${'$'}MARK_VALUE
        iptables -t mangle -A ${'$'}{CHAIN}_OUT -p udp -j MARK --set-mark ${'$'}MARK_VALUE
        iptables -t mangle -I OUTPUT -p tcp -j ${'$'}{CHAIN}_OUT
        iptables -t mangle -I OUTPUT -p udp -j ${'$'}{CHAIN}_OUT

        # ---- IPv6 ----
        # TPROXY/MARK are broadly supported; NAT66 (REDIRECT) is not on every kernel,
        # so all ip6tables rules are best-effort — unsupported ones are silently skipped.
        ip -6 rule add fwmark ${'$'}MARK_VALUE table ${'$'}TABLE_ID pref ${'$'}TABLE_ID 2>/dev/null || true
        ip -6 route add local ::/0 dev lo table ${'$'}TABLE_ID 2>/dev/null || true

        ip6tables -t nat -N ${'$'}CHAIN_DNS 2>/dev/null
        ip6tables -t nat -F ${'$'}CHAIN_DNS
        ip6tables -t nat -A ${'$'}CHAIN_DNS -m mark --mark ${'$'}SING_MARK -j RETURN 2>/dev/null || true
        [ "${'$'}APP_UID" != "0" ] && ip6tables -t nat -A ${'$'}CHAIN_DNS -m owner --uid-owner ${'$'}APP_UID -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN_DNS -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN_DNS -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -I OUTPUT -j ${'$'}CHAIN_DNS 2>/dev/null || true
        ip6tables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true

        ip6tables -t mangle -N ${'$'}CHAIN 2>/dev/null
        ip6tables -t mangle -F ${'$'}CHAIN
        ip6tables -t mangle -A ${'$'}CHAIN -m mark --mark ${'$'}SING_MARK -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}CHAIN -d ::1/128    -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}CHAIN -d fc00::/7   -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}CHAIN -d fe80::/10  -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}CHAIN -d ff00::/8   -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}CHAIN -p tcp -j TPROXY --on-ip :: --on-port ${'$'}TPROXY_PORT --tproxy-mark ${'$'}MARK_VALUE 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}CHAIN -p udp -j TPROXY --on-ip :: --on-port ${'$'}TPROXY_PORT --tproxy-mark ${'$'}MARK_VALUE 2>/dev/null || true
        ip6tables -t mangle -I PREROUTING -p tcp -j ${'$'}CHAIN 2>/dev/null || true
        ip6tables -t mangle -I PREROUTING -p udp -j ${'$'}CHAIN 2>/dev/null || true

        ip6tables -t mangle -N ${'$'}{CHAIN}_OUT 2>/dev/null
        ip6tables -t mangle -F ${'$'}{CHAIN}_OUT
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -m mark --mark ${'$'}SING_MARK -j RETURN 2>/dev/null || true
        [ "${'$'}APP_UID" != "0" ] && ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -m owner --uid-owner ${'$'}APP_UID -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -d ::1/128    -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -d fc00::/7   -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -d fe80::/10  -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -d ff00::/8   -j RETURN 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -p tcp -j MARK --set-mark ${'$'}MARK_VALUE 2>/dev/null || true
        ip6tables -t mangle -A ${'$'}{CHAIN}_OUT -p udp -j MARK --set-mark ${'$'}MARK_VALUE 2>/dev/null || true
        ip6tables -t mangle -I OUTPUT -p tcp -j ${'$'}{CHAIN}_OUT 2>/dev/null || true
        ip6tables -t mangle -I OUTPUT -p udp -j ${'$'}{CHAIN}_OUT 2>/dev/null || true
    """.trimIndent()

    // ─────────────────────────── redir start ────────────────────────────

    private fun redirStart(tproxyPort: Int, dnsPort: Int, appUid: Int): String = """
        TPROXY_PORT=$tproxyPort
        DNS_PORT=$dnsPort
        APP_UID=$appUid
        SING_MARK=$SING_MARK
        CHAIN=$CHAIN_RD
        CHAIN_DNS=$CHAIN_DNS

        # ---- IPv4 ----
        # Order matters: all jumps/rules are inserted with -I (top of chain), so the
        # DNS block is written LAST to end up FIRST in PREROUTING/OUTPUT. This routes
        # TCP DNS into dns-in instead of the generic redir chain.
        iptables -t nat -N ${'$'}CHAIN 2>/dev/null
        iptables -t nat -F ${'$'}CHAIN
        iptables -t nat -A ${'$'}CHAIN -m mark --mark ${'$'}SING_MARK -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 127.0.0.0/8    -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 10.0.0.0/8     -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 172.16.0.0/12  -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 192.168.0.0/16 -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 169.254.0.0/16 -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 224.0.0.0/4    -j RETURN
        iptables -t nat -A ${'$'}CHAIN -d 240.0.0.0/4    -j RETURN
        iptables -t nat -A ${'$'}CHAIN -p tcp -j REDIRECT --to-ports ${'$'}TPROXY_PORT
        iptables -t nat -I PREROUTING -p tcp -j ${'$'}CHAIN

        iptables -t nat -N ${'$'}{CHAIN}_OUT 2>/dev/null
        iptables -t nat -F ${'$'}{CHAIN}_OUT
        iptables -t nat -A ${'$'}{CHAIN}_OUT -m mark --mark ${'$'}SING_MARK -j RETURN
        [ "${'$'}APP_UID" != "0" ] && iptables -t nat -A ${'$'}{CHAIN}_OUT -m owner --uid-owner ${'$'}APP_UID -j RETURN
        iptables -t nat -A ${'$'}{CHAIN}_OUT -d 127.0.0.0/8    -j RETURN
        iptables -t nat -A ${'$'}{CHAIN}_OUT -d 10.0.0.0/8     -j RETURN
        iptables -t nat -A ${'$'}{CHAIN}_OUT -d 172.16.0.0/12  -j RETURN
        iptables -t nat -A ${'$'}{CHAIN}_OUT -d 192.168.0.0/16 -j RETURN
        iptables -t nat -A ${'$'}{CHAIN}_OUT -p tcp -j REDIRECT --to-ports ${'$'}TPROXY_PORT
        iptables -t nat -I OUTPUT -p tcp -j ${'$'}{CHAIN}_OUT

        iptables -t nat -N ${'$'}CHAIN_DNS 2>/dev/null
        iptables -t nat -F ${'$'}CHAIN_DNS
        iptables -t nat -A ${'$'}CHAIN_DNS -m mark --mark ${'$'}SING_MARK -j RETURN
        [ "${'$'}APP_UID" != "0" ] && iptables -t nat -A ${'$'}CHAIN_DNS -m owner --uid-owner ${'$'}APP_UID -j RETURN
        iptables -t nat -A ${'$'}CHAIN_DNS -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
        iptables -t nat -A ${'$'}CHAIN_DNS -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
        iptables -t nat -I OUTPUT    -j ${'$'}CHAIN_DNS
        iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
        iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT

        # ---- IPv6 (best-effort: NAT66 REDIRECT unsupported on some kernels) ----
        # redirect cannot carry UDP, so only TCP and DNS are hijacked for v6;
        # non-DNS UDP over IPv6 leaks direct in redir mode (same as v4).
        # Same ordering as v4: DNS block last, so it lands first.
        ip6tables -t nat -N ${'$'}CHAIN 2>/dev/null
        ip6tables -t nat -F ${'$'}CHAIN
        ip6tables -t nat -A ${'$'}CHAIN -m mark --mark ${'$'}SING_MARK -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN -d ::1/128    -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN -d fc00::/7   -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN -d fe80::/10  -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN -d ff00::/8   -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN -p tcp -j REDIRECT --to-ports ${'$'}TPROXY_PORT 2>/dev/null || true
        ip6tables -t nat -I PREROUTING -p tcp -j ${'$'}CHAIN 2>/dev/null || true

        ip6tables -t nat -N ${'$'}{CHAIN}_OUT 2>/dev/null
        ip6tables -t nat -F ${'$'}{CHAIN}_OUT
        ip6tables -t nat -A ${'$'}{CHAIN}_OUT -m mark --mark ${'$'}SING_MARK -j RETURN 2>/dev/null || true
        [ "${'$'}APP_UID" != "0" ] && ip6tables -t nat -A ${'$'}{CHAIN}_OUT -m owner --uid-owner ${'$'}APP_UID -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}{CHAIN}_OUT -d ::1/128    -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}{CHAIN}_OUT -d fc00::/7   -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}{CHAIN}_OUT -d fe80::/10  -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}{CHAIN}_OUT -d ff00::/8   -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}{CHAIN}_OUT -p tcp -j REDIRECT --to-ports ${'$'}TPROXY_PORT 2>/dev/null || true
        ip6tables -t nat -I OUTPUT -p tcp -j ${'$'}{CHAIN}_OUT 2>/dev/null || true

        ip6tables -t nat -N ${'$'}CHAIN_DNS 2>/dev/null
        ip6tables -t nat -F ${'$'}CHAIN_DNS
        ip6tables -t nat -A ${'$'}CHAIN_DNS -m mark --mark ${'$'}SING_MARK -j RETURN 2>/dev/null || true
        [ "${'$'}APP_UID" != "0" ] && ip6tables -t nat -A ${'$'}CHAIN_DNS -m owner --uid-owner ${'$'}APP_UID -j RETURN 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN_DNS -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -A ${'$'}CHAIN_DNS -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -I OUTPUT -j ${'$'}CHAIN_DNS 2>/dev/null || true
        ip6tables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
    """.trimIndent()

    // ────────────────────────── unified cleanup ─────────────────────────
    // Mode-agnostic: removes every chain family (tproxy + redir + dns) for both
    // v4 and v6. Safe to run repeatedly and after any mode switch.

    private fun cleanup(dnsPort: Int): String = """
        DNS_PORT=$dnsPort
        MARK_VALUE=$MARK_VALUE
        TABLE_ID=$TABLE_ID
        CHAIN_TP=$CHAIN_TP
        CHAIN_RD=$CHAIN_RD
        CHAIN_DNS=$CHAIN_DNS

        # ---- IPv4 ----
        iptables -t nat -D OUTPUT -j ${'$'}CHAIN_DNS 2>/dev/null || true
        iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        iptables -t nat -F ${'$'}CHAIN_DNS 2>/dev/null || true
        iptables -t nat -X ${'$'}CHAIN_DNS 2>/dev/null || true

        iptables -t mangle -D PREROUTING -p tcp -j ${'$'}CHAIN_TP 2>/dev/null || true
        iptables -t mangle -D PREROUTING -p udp -j ${'$'}CHAIN_TP 2>/dev/null || true
        iptables -t mangle -F ${'$'}CHAIN_TP 2>/dev/null || true
        iptables -t mangle -X ${'$'}CHAIN_TP 2>/dev/null || true
        iptables -t mangle -D OUTPUT -p tcp -j ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true
        iptables -t mangle -D OUTPUT -p udp -j ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true
        iptables -t mangle -F ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true
        iptables -t mangle -X ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true

        iptables -t nat -D PREROUTING -p tcp -j ${'$'}CHAIN_RD 2>/dev/null || true
        iptables -t nat -F ${'$'}CHAIN_RD 2>/dev/null || true
        iptables -t nat -X ${'$'}CHAIN_RD 2>/dev/null || true
        iptables -t nat -D OUTPUT -p tcp -j ${'$'}{CHAIN_RD}_OUT 2>/dev/null || true
        iptables -t nat -F ${'$'}{CHAIN_RD}_OUT 2>/dev/null || true
        iptables -t nat -X ${'$'}{CHAIN_RD}_OUT 2>/dev/null || true

        ip rule del fwmark ${'$'}MARK_VALUE table ${'$'}TABLE_ID 2>/dev/null || true
        ip route flush table ${'$'}TABLE_ID 2>/dev/null || true

        # ---- IPv6 ----
        ip6tables -t nat -D OUTPUT -j ${'$'}CHAIN_DNS 2>/dev/null || true
        ip6tables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
        ip6tables -t nat -F ${'$'}CHAIN_DNS 2>/dev/null || true
        ip6tables -t nat -X ${'$'}CHAIN_DNS 2>/dev/null || true

        ip6tables -t mangle -D PREROUTING -p tcp -j ${'$'}CHAIN_TP 2>/dev/null || true
        ip6tables -t mangle -D PREROUTING -p udp -j ${'$'}CHAIN_TP 2>/dev/null || true
        ip6tables -t mangle -F ${'$'}CHAIN_TP 2>/dev/null || true
        ip6tables -t mangle -X ${'$'}CHAIN_TP 2>/dev/null || true
        ip6tables -t mangle -D OUTPUT -p tcp -j ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true
        ip6tables -t mangle -D OUTPUT -p udp -j ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true
        ip6tables -t mangle -F ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true
        ip6tables -t mangle -X ${'$'}{CHAIN_TP}_OUT 2>/dev/null || true

        ip6tables -t nat -D PREROUTING -p tcp -j ${'$'}CHAIN_RD 2>/dev/null || true
        ip6tables -t nat -F ${'$'}CHAIN_RD 2>/dev/null || true
        ip6tables -t nat -X ${'$'}CHAIN_RD 2>/dev/null || true
        ip6tables -t nat -D OUTPUT -p tcp -j ${'$'}{CHAIN_RD}_OUT 2>/dev/null || true
        ip6tables -t nat -F ${'$'}{CHAIN_RD}_OUT 2>/dev/null || true
        ip6tables -t nat -X ${'$'}{CHAIN_RD}_OUT 2>/dev/null || true

        ip -6 rule del fwmark ${'$'}MARK_VALUE table ${'$'}TABLE_ID 2>/dev/null || true
        ip -6 route flush table ${'$'}TABLE_ID 2>/dev/null || true
    """.trimIndent()
}
