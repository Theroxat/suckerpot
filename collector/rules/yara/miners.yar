// SuckerPot rule, MIT licence. Written from public descriptions of the family, no sample was copied.
rule crypto_miner_xmrig
{
    meta:
        author = "SuckerPot"
        description = "XMRig-style Monero miner: stratum URLs, config keys and algorithm names"
        reference = "https://xmrig.com/docs"
        family = "xmrig"
        severity = "warning"
    strings:
        $s1 = "stratum+tcp://" ascii nocase
        $s2 = "stratum+ssl://" ascii nocase
        $s3 = "stratum2+tcp://" ascii nocase
        $x1 = "xmrig" ascii nocase
        $x2 = "donate-level" ascii nocase
        $x3 = "randomx" ascii nocase
        $x4 = "cryptonight" ascii nocase
        $x5 = "\"rig-id\"" ascii
        $x6 = "monero" ascii nocase
    condition:
        filesize < 16MB and
        ((1 of ($s*) and 1 of ($x*)) or 3 of ($x*))
}
