rule DetectSuspicious {
    meta:
        description = "Generic suspicious keywords"
        author = "AntivirusBot"
        date = "2023-12-14"
    strings:
        $cmd = "cmd.exe" nocase
        $ps = "powershell" nocase
        $eval = "eval("
        $net = "System.Net.WebClient"
    condition:
        any of them
}