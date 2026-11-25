import "pe"
import "hash"

rule Win32_Trojan_Gh0st_360Masking {
    meta:
        description = "Detects Gh0st RAT variants masking as 360 Safe Browser containing specific Windows service manipulation strings and C2 domain artifacts."
        author = "Serhii Kocherhan"
        date = "2026-11-25"
        yarahub_twitter = "@skocherhan"
        yarahub_uuid = "3f2fbe1c-569f-492c-9e0b-3891008548ec"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e5a8df35182b193af1542093d8ebc5e7"

    strings:
        // Domains / Network Indicators
        $d_conf360   = "conf.f.360.cn" ascii wide nocase
        $d_zhourunfa = "zhourunfa80.gicp.net" ascii wide nocase
        $d_360cn     = "360.cn" ascii wide nocase
        $d_baidu     = "www.baidu.com" ascii wide nocase

        $s_product_utf8 = { 33 36 30 e5 ae 89 e5 85 a8 e6 b5 8f e8 a7 88 e5 99 a8 }

        // Mutex / Schema String
        $m_esent_v85 = "ESENT Performance Data Schema Version 85" ascii wide nocase

        // Selected Windows Services Targeted or Enumerated
        $svc1  = "fastuserswitchingcompatibility" ascii wide nocase
        $svc2  = "helpsvc" ascii wide nocase
        $svc3  = "ias" ascii wide nocase
        $svc4  = "irmon" ascii wide nocase
        $svc5  = "logonhours" ascii wide nocase
        $svc6  = "nla" ascii wide nocase
        $svc7  = "ntmssvc" ascii wide nocase
        $svc8  = "nwcworkstation" ascii wide nocase
        $svc9  = "pcaudit" ascii wide nocase
        $svc10 = "srservice" ascii wide nocase
        $svc11 = "uploadmgr" ascii wide nocase
        $svc12 = "wmdmpmsp" ascii wide nocase
        $svc13 = "wmi" ascii wide nocase
        $svc14 = "xcvs" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        (
            hash.md5(0, filesize) == "e5a8df35182b193af1542093d8ebc5e7" or
            $m_esent_v85 or
            $d_zhourunfa or
            ($d_conf360 and ($s_product_utf8 or $d_360cn or 3 of ($svc*))) or
            ($s_product_utf8 and $d_baidu and 2 of ($svc*)) or
            (5 of ($svc*))
        )
}