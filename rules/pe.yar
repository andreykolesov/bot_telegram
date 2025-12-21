import "pe"

rule Code_Injection_API {
    meta:
        description = "Detects injection APIs"
        severity = "Critical"
    condition:
        pe.is_pe and (
            pe.imports("kernel32.dll", "VirtualAllocEx") or
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("kernel32.dll", "WriteProcessMemory")
        )
}

rule Suspicious_Dropper {
    meta:
        description = "Detects dropper behavior"
        severity = "High"
    condition:
        pe.is_pe and (
            (pe.imports("shell32.dll", "ShellExecuteA") or pe.imports("shell32.dll", "ShellExecuteW") or pe.imports("kernel32.dll", "WinExec")) and
            (pe.imports("kernel32.dll", "WriteFile") or pe.imports("kernel32.dll", "GetTempPathA"))
        )
}

rule Suspicious_Sections {
    meta:
        description = "Detects bad section names"
        severity = "High"
    strings:
        $s1 = ".freetp" nocase
        $s2 = ".hack" nocase
        $s3 = ".crack" nocase
        $s4 = ".inj" nocase
    condition:
        any of them
}

rule Internet_Downloader {
    meta:
        description = "Detects URLDownloadToFile"
        severity = "High"
    condition:
        pe.is_pe and (
            pe.imports("urlmon.dll", "URLDownloadToFileA") or
            pe.imports("urlmon.dll", "URLDownloadToFileW") or
            pe.imports("wininet.dll", "InternetOpenA")
        )
}

rule Dynamic_Loading {
    meta:
        description = "Hides imports via GetProcAddress"
        severity = "Medium"
    condition:
        pe.is_pe and 
        pe.imports("kernel32.dll", "LoadLibraryA") and 
        pe.imports("kernel32.dll", "GetProcAddress")
}