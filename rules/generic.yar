// 1. PowerShell (Скрипты могут быть в текстовых файлах или внутри документов)
rule Suspicious_PowerShell {
    meta:
        description = "Detects malicious PowerShell commands"
        severity = "High"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "FromBase64String" nocase
        $web  = "System.Net.WebClient" nocase
        $down = ".DownloadString" nocase
        $iex  = "Invoke-Expression" nocase
    condition:
        any of them
}

// 2. WebShells (PHP/ASP/JSP)
rule Webshell_Indicators {
    meta:
        description = "Detects webshells"
        severity = "High"
    strings:
        $php_eval = "eval(base64_decode("
        $php_sys  = "system($_GET"
        $php_exec = "shell_exec("
        $asp_eval = "eval(Request.Item"
    condition:
        filesize < 5MB and any of them
}

// 3. Ransomware (Текстовые команды)
rule Ransomware_Strings {
    meta:
        description = "Detects ransomware commands strings"
        severity = "Critical"
    strings:
        $vss = "vssadmin.exe Delete Shadows" nocase
        $wb  = "wbadmin DELETE SYSTEMSTATEBACKUP" nocase
        $bcd = "bcdedit /set {default} recoveryenabled No" nocase
    condition:
        any of them
}

// 4. HackTools (Текстовые сигнатуры)
rule HackTools_Strings {
    meta:
        description = "Detects hacking tools strings"
        severity = "Critical"
    strings:
        $mimi1 = "sekurlsa::logonpasswords" wide ascii
        $mimi2 = "lsadump::lsa" wide ascii
        $meta1 = "meterpreter" nocase
        $meta2 = "reverse_tcp" nocase
    condition:
        any of them
}

// 5. Опасные скрипты в PDF/Office (Базовый поиск)
rule Malicious_Script_Tags {
    meta:
        description = "Detects embedded scripts"
        severity = "Medium"
    strings:
        $js  = "/JavaScript"
        $js2 = "/JS"
        $vba = "VBA Project"
        $auto = "AutoOpen"
    condition:
        any of them
}