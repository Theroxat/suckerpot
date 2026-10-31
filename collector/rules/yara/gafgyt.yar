// SuckerPot rule, MIT licence. Written from public descriptions of the family, no sample was copied.
rule gafgyt_elf
{
    meta:
        author = "SuckerPot"
        description = "Gafgyt / Bashlite IoT bot (ELF): command keywords of its IRC-like protocol"
        reference = "https://en.wikipedia.org/wiki/Mirai_(malware)#Related_malware"
        family = "gafgyt"
        severity = "severe"
    strings:
        $botkill = "BOTKILL" ascii
        $killattk = "KILLATTK" ascii
        $lolno = "LOLNOGTFO" ascii
        $scanner = "SCANNER ON" ascii
        $localip = "GETLOCALIP" ascii
        $junk = "JUNK" ascii
        $hold = "HOLD" ascii
        $std = "STD" ascii
        $pong = "PONG!" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 4MB and
        ($lolno or $killattk or 3 of ($botkill, $scanner, $localip, $junk, $hold, $std, $pong))
}
