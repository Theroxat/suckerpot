// SuckerPot rule, MIT licence. Written from public descriptions of the family, no sample was copied.
rule redis_rogue_module
{
    meta:
        author = "SuckerPot"
        description = "Redis module (ELF) exposing command execution, as loaded by rogue-master attacks"
        reference = "https://redis.io/docs/latest/develop/reference/modules/"
        family = "redis-rogue-module"
        severity = "severe"
    strings:
        $onload = "RedisModule_OnLoad" ascii
        $create = "RedisModule_CreateCommand" ascii
        $cmd1 = "system.exec" ascii
        $cmd2 = "system.rev" ascii
        $cmd3 = "system.bind" ascii
        $popen = "popen" ascii
        $exec = "execve" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 2MB and $onload and
        (1 of ($cmd*) or ($create and ($popen or $exec)))
}
