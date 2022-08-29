rule quasar_rat : rat
{
    meta:
        description = "Quasar rat"
        threat_level = 3
        in_the_wild = true
    strings:
        $quasar_name = "Quasar"
        $add_DownloadFileCompleted = "add_DownloadFileCompleted"
        $reverse_proxy_data = "ReverseProxyData"
    condition:
        $quasar_name and $add_DownloadFileCompleted and $reverse_proxy_data
}
