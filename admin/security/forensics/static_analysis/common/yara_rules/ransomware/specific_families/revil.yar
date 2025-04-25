rule Ransomware_REvil_Core {
    meta:
        description = "Detects REvil/Sodinokibi ransomware core components"
        author = "Security Team"
        date = "2024-07-18"
        version = "1.0"
        hash = "4356ccd266c8b7eeaf89f64213f29c7a906b2c643bd48c8b29d57c4b48c314f2"
        reference = "https://www.cisa.gov/uscert/ncas/alerts/aa21-131a"
        severity = "critical"
        family = "REvil/Sodinokibi"
        mitre_att = "T1486" // Data Encrypted for Impact

    strings:
        // Core encryption process markers
        $crypto1 = { 48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B F2 48 8B F9 8B 0D }
        $crypto2 = { 41 B8 61 D0 15 53 4C 8D 0D ?? ?? ?? ?? 41 8B D1 48 8B CB FF 15 }
        $crypto3 = { 41 8D 4D AF E8 ?? ?? ?? ?? 44 0F B6 5D ?? 45 84 DB 74 }

        // Specific strings known to be in REvil
        $str1 = "expand 32-byte k" ascii wide
        $str2 = ".onion" ascii wide
        $str3 = "DECRYPT-FILES.txt" ascii wide

        // Configuration strings
        $config1 = "pk_key" ascii wide
        $config2 = "sub_key" ascii wide
        $config3 = "ext_key" ascii wide

        // Extension pattern or markers
        $ext_pattern = /\.[\w]{4,8}$/ ascii wide

        // Ransom note markers
        $ransom1 = "All your files are encrypted" ascii wide
        $ransom2 = "would like to recover all your files?" ascii wide
        $ransom3 = "your files in this directory" ascii wide
        $ransom4 = "tor browser" ascii nocase wide

        // URL patterns in ransom notes
        $url1 = "http://aplebzu" ascii wide
        $url2 = ".onion" ascii wide

        // Command execution artifacts
        $cmd1 = "cmd.exe /c" ascii wide
        $cmd2 = "vssadmin delete shadows" ascii wide nocase
        $cmd3 = "bcdedit" ascii wide
        $cmd4 = "recoveryenabled no" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and // MZ header for PE files
        filesize < 5MB and
        (
            // Different detection combinations
            (2 of ($crypto*) and 1 of ($str*)) or
            (1 of ($crypto*) and 2 of ($str*) and 1 of ($config*)) or
            (2 of ($ransom*) and 1 of ($url*)) or
            (1 of ($config*) and 2 of ($cmd*)) or
            (3 of ($cmd*) and 1 of ($str*))
        )
}

rule Ransomware_REvil_RansomNote {
    meta:
        description = "Detects REvil/Sodinokibi ransomware ransom notes"
        author = "Security Team"
        date = "2024-07-18"
        version = "1.0"
        hash = "79aa26d4c59c17e92bd9f5b153530a1af1daca1b01d3c9628474a12d8cde5f89"
        reference = "https://www.cisa.gov/uscert/ncas/alerts/aa21-131a"
        severity = "high"
        family = "REvil/Sodinokibi"
        mitre_att = "T1486" // Data Encrypted for Impact

    strings:
        // Ransom note content patterns
        $header1 = "All of your files are encrypted!" ascii wide
        $header2 = "---=== Welcome ===---" ascii wide
        $header3 = "!!! All of your files are encrypted !!!" ascii wide

        // Specific phrases common in REvil ransom notes
        $phrase1 = "All your files have been encrypted due to a security problem" ascii wide
        $phrase2 = "If you want to restore them, write us to the e-mail" ascii wide
        $phrase3 = "You have to pay for decryption in Bitcoin" ascii wide
        $phrase4 = "After payment we will send you the decryption tool" ascii wide
        $phrase5 = "To get all your files back you need to pay" ascii wide

        // Typical REvil ransom note file names
        $filename1 = "[random].onion.readme.txt" ascii wide
        $filename2 = "readme.txt" ascii wide
        $filename3 = "readme.html" ascii wide
        $filename4 = "DECRYPT-FILES.txt" ascii wide

        // Contact instructions
        $contact1 = "contact us at" ascii wide
        $contact2 = "tor browser" ascii wide nocase
        $contact3 = "https://torproject.org" ascii wide

        // URLs and onion addresses (partial patterns)
        $url1 = ".onion/" ascii wide
        $url2 = "http://decoder" ascii wide

    condition:
        filesize < 100KB and
        (
            2 of ($header*) or
            3 of ($phrase*) or
            (1 of ($header*) and 2 of ($phrase*)) or
            (1 of ($filename*) and 2 of ($contact*)) or
            (2 of ($contact*) and 1 of ($url*))
        )
}

rule Ransomware_REvil_PostInfection {
    meta:
        description = "Detects REvil/Sodinokibi post-infection indicators"
        author = "Security Team"
        date = "2024-07-18"
        version = "1.0"
        reference = "https://www.cisa.gov/uscert/ncas/alerts/aa21-131a"
        severity = "high"
        family = "REvil/Sodinokibi"
        mitre_att = "T1486" // Data Encrypted for Impact

    strings:
        // Random extension appended to encrypted files
        $extension1 = /\.[a-zA-Z0-9]{4,10}$/ ascii wide

        // Renamed files with extension
        $renamed = /[a-zA-Z0-9]{8}\.[a-zA-Z0-9]{4,10}$/ ascii wide

        // Registry modifications
        $reg1 = "HKEY_CURRENT_USER\\Software\\REvil" ascii wide
        $reg2 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\REvil" ascii wide

        // Wallpaper changes
        $wallpaper1 = "Your files are encrypted" ascii wide
        $wallpaper2 = "background.bmp" ascii wide
        $wallpaper3 = "wallpaper.jpg" ascii wide

        // System modifications
        $sysmod1 = "vssadmin Delete Shadows /All /Quiet" ascii wide nocase
        $sysmod2 = "bcdedit /set {default} recoveryenabled No" ascii wide nocase
        $sysmod3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $sysmod4 = "wmic shadowcopy delete" ascii wide nocase

    condition:
        (
            1 of ($extension*) or
            $renamed or
            1 of ($reg*) or
            (1 of ($wallpaper*) and 1 of ($sysmod*))
        )
}
