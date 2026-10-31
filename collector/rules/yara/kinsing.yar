// SuckerPot rule, MIT licence. Written from public descriptions of the family, no sample was copied.
rule kinsing_loader
{
    meta:
        author = "SuckerPot"
        description = "Kinsing / kdevtmpfsi cryptojacking malware: process and file names, ld.so.preload persistence"
        reference = "https://www.aquasec.com/blog/threat-alert-kinsing-malware-container-vulnerability/"
        family = "kinsing"
        severity = "severe"
    strings:
        $n1 = "kinsing" ascii nocase
        $n2 = "kdevtmpfsi" ascii
        $n3 = "kerberods" ascii
        $n4 = "libsystem.so" ascii
        $preload = "/etc/ld.so.preload" ascii
        $cron = "crontab" ascii
    condition:
        filesize < 32MB and (2 of ($n*) or (1 of ($n1, $n2, $n3) and ($preload or $cron)))
}
