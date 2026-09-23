package io.nekohasekai.sagernet.bg

object IptablesRules {

    // mark 100 (0x64): set on sing-box outbound packets via route.default_mark
    // must match the value in ConfigBuilder (0x64) and iptables RETURN rules below
    private const val SING_MARK = 100
    private const val MARK_VALUE = 200
    private const val TABLE_ID = 200

    fun tproxy(action: String, tproxyPort: Int, dnsPort: Int, appUid: Int): String = when (action) {
        "start" -> """
            TPROXY_PORT=$tproxyPort
            DNS_PORT=$dnsPort
            APP_UID=$appUid
            MARK_VALUE=$MARK_VALUE
            TABLE_ID=$TABLE_ID
            SING_MARK=$SING_MARK
            CHAIN=NEKOBOX_TP
            CHAIN_DNS=NEKOBOX_DNS

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
        """.trimIndent()

        "stop" -> """
            MARK_VALUE=$MARK_VALUE
            TABLE_ID=$TABLE_ID
            DNS_PORT=$dnsPort
            CHAIN=NEKOBOX_TP
            CHAIN_DNS=NEKOBOX_DNS

            iptables -t nat -D OUTPUT -j ${'$'}CHAIN_DNS 2>/dev/null || true
            iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
            iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
            iptables -t nat -F ${'$'}CHAIN_DNS 2>/dev/null || true
            iptables -t nat -X ${'$'}CHAIN_DNS 2>/dev/null || true

            iptables -t mangle -D PREROUTING -p tcp -j ${'$'}CHAIN 2>/dev/null || true
            iptables -t mangle -D PREROUTING -p udp -j ${'$'}CHAIN 2>/dev/null || true
            iptables -t mangle -F ${'$'}CHAIN 2>/dev/null || true
            iptables -t mangle -X ${'$'}CHAIN 2>/dev/null || true

            iptables -t mangle -D OUTPUT -p tcp -j ${'$'}{CHAIN}_OUT 2>/dev/null || true
            iptables -t mangle -D OUTPUT -p udp -j ${'$'}{CHAIN}_OUT 2>/dev/null || true
            iptables -t mangle -F ${'$'}{CHAIN}_OUT 2>/dev/null || true
            iptables -t mangle -X ${'$'}{CHAIN}_OUT 2>/dev/null || true

            ip rule del fwmark ${'$'}MARK_VALUE table ${'$'}TABLE_ID pref ${'$'}TABLE_ID 2>/dev/null || true
            ip route del local 0.0.0.0/0 dev lo table ${'$'}TABLE_ID 2>/dev/null || true
        """.trimIndent()

        else -> error("unknown action: $action")
    }

    fun redir(action: String, tproxyPort: Int, dnsPort: Int, appUid: Int): String = when (action) {
        "start" -> """
            TPROXY_PORT=$tproxyPort
            DNS_PORT=$dnsPort
            APP_UID=$appUid
            SING_MARK=$SING_MARK
            CHAIN=NEKOBOX_RD
            CHAIN_DNS=NEKOBOX_DNS

            iptables -t nat -N ${'$'}CHAIN_DNS 2>/dev/null
            iptables -t nat -F ${'$'}CHAIN_DNS
            iptables -t nat -A ${'$'}CHAIN_DNS -m mark --mark ${'$'}SING_MARK -j RETURN
            [ "${'$'}APP_UID" != "0" ] && iptables -t nat -A ${'$'}CHAIN_DNS -m owner --uid-owner ${'$'}APP_UID -j RETURN
            iptables -t nat -A ${'$'}CHAIN_DNS -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
            iptables -t nat -A ${'$'}CHAIN_DNS -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
            iptables -t nat -I OUTPUT    -j ${'$'}CHAIN_DNS
            iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT
            iptables -t nat -I PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT

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
        """.trimIndent()

        "stop" -> """
            DNS_PORT=$dnsPort
            CHAIN=NEKOBOX_RD
            CHAIN_DNS=NEKOBOX_DNS

            iptables -t nat -D OUTPUT    -j ${'$'}CHAIN_DNS 2>/dev/null || true
            iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
            iptables -t nat -D PREROUTING -p tcp --dport 53 -j REDIRECT --to-ports ${'$'}DNS_PORT 2>/dev/null || true
            iptables -t nat -F ${'$'}CHAIN_DNS 2>/dev/null || true
            iptables -t nat -X ${'$'}CHAIN_DNS 2>/dev/null || true

            iptables -t nat -D PREROUTING -p tcp -j ${'$'}CHAIN 2>/dev/null || true
            iptables -t nat -F ${'$'}CHAIN 2>/dev/null || true
            iptables -t nat -X ${'$'}CHAIN 2>/dev/null || true

            iptables -t nat -D OUTPUT -p tcp -j ${'$'}{CHAIN}_OUT 2>/dev/null || true
            iptables -t nat -F ${'$'}{CHAIN}_OUT 2>/dev/null || true
            iptables -t nat -X ${'$'}{CHAIN}_OUT 2>/dev/null || true
        """.trimIndent()

        else -> error("unknown action: $action")
    }
}
