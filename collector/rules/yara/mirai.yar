// SuckerPot rule, MIT licence. Written from public descriptions of the family, no sample was copied.
rule mirai_elf
{
    meta:
        author = "SuckerPot"
        description = "Mirai-style IoT bot (ELF): scanner markers, watchdog handling, Valve query flood"
        reference = "https://en.wikipedia.org/wiki/Mirai_(malware)"
        family = "mirai"
        severity = "severe"
    strings:
        $ecchi = "ECCHI" ascii
        $busybox = "/bin/busybox" ascii
        $wd1 = "/dev/watchdog" ascii
        $wd2 = "/dev/misc/watchdog" ascii
        $tsource = "TSource Engine Query" ascii
        $net = "/proc/net/tcp" ascii
        $ncorrect = "ncorrect" ascii
        $dvr = "dvrHelper" ascii
        $report = "REPORT %s:%s" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and
        (
            ($ecchi and $busybox) or
            ($tsource and 1 of ($wd*)) or
            $dvr or
            4 of ($busybox, $wd1, $wd2, $tsource, $net, $ncorrect, $report)
        )
}
