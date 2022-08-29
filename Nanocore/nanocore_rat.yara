rule nanocore_rat : rat
{
    meta:
        description = "Nanocore rat"
        threat_level = 3
        in_the_wild = true
    strings:
        $nanocore_name = "NanoCore"
        $get_StartupPath = "get_StartupPath"
        $ConnectDone = "ConnectDone"
    condition:
        $nanocore_name and $get_StartupPath and $ConnectDone
}
