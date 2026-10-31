// SuckerPot rule, MIT licence. Written from public descriptions of the family, no sample was copied.
rule shell_dropper_multiarch
{
    meta:
        author = "SuckerPot"
        description = "Shell script that downloads one binary per CPU architecture, makes it executable and runs it"
        reference = "https://en.wikipedia.org/wiki/Mirai_(malware)#Infection"
        family = "shell-dropper"
        severity = "severe"
    strings:
        $dl = /(wget|curl|tftp|ftpget)[^\n]{1,200}[\/ -](mips|mpsl|mipsel|arm[0-9a-z]*|x86|x86_64|i[3-6]86|ppc|sh4|spc|m68k)\b/
        $chmod = /chmod[ \t]+(\+x|[0-7]?[0-7][0-7][0-7])/
        $rm = /rm[ \t]+(-[a-z]+[ \t]+)?[^\n;]{0,80}(\.sh|\$0|\.\/)/
    condition:
        filesize < 64KB and not (uint32(0) == 0x464c457f) and
        ((#dl >= 2 and $chmod) or ($dl and $chmod and $rm))
}
