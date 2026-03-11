rule Andr_Adware_EvilCleaner_a {
    strings:
    $dex = { 64 65 78 0A 30 33 ?? 00 }

    $p1 = "/cleaner/activity/" ascii
    $p2 = "/clean/activity/" ascii
    $p3 = "Lcom/clean/" ascii
    $p4 = "/clean/main/" ascii
    $p5 = "/JunkScanActivity" ascii
    $p6 = "Lcom/cleaner/" ascii
    $p7 = "com/mirror/clearup/" ascii
    $p8 = "Lcom/nimbly/nimblyclean/" ascii
    $p9 = "Lcom/cleanmax/" ascii
    $p10 = "/cleanes/R$id" ascii
    $p11 = "/junkclean/presentation/" ascii
    $p12 = "NewJunkCleanerPageActivity$" ascii
    $p13 = "/cleaner/view/" ascii

    $a1 = "com/bytedance/sdk/openadsdk/" ascii
    $a2 = "Lcom/bytedance/adsdk/" ascii
    $a3 = "Lcom/vungle/ads/" ascii
    $a4 = "Lcom/thinkup/core/" ascii
    $a5 = "Lcom/iab/omid/library/" ascii
    condition:
    $dex at 0 and (
        (any of ($p*)) and
        (2   of ($a*))
    )
}

rule Andr_Adware_EvilCleaner_b {
    strings:
    $dex = { 64 65 78 0A 30 33 ?? 00 }

    $p1 = "com.cleanmaster.mguard" ascii
    $p2 = "com.noxgroup.app.cleaner" ascii
    $p3 = "com.ushareit.cleanit" ascii

    condition:
    $dex at 0 and (
        (any of ($p*))
    )
}

rule Andr_Adware_EvilCleaner_c {
    strings:
    $dex = { 64 65 78 0A 30 33 ?? 00 }

    $p1 = "$cleanUps" ascii
    $p2 = "last_cleanup_time" ascii

    condition:
    $dex at 0 and (
        (all of ($p*))
    )
}
