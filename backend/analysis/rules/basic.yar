rule Crypto_APIs
{
    meta:
        description = "Detects the use of cryptographic APIs often used by Ransomware"
        author = "Silent Scan"
        severity = "Medium"

    strings:
        $c1 = "CryptAcquireContext" ascii wide nocase
        $c2 = "CryptEncrypt" ascii wide nocase
        $c3 = "CryptExportKey" ascii wide nocase

    condition:
        any of ($c*)
}

rule Suspicious_Network_Activity
{
    meta:
        description = "Detects APIs indicating HTTP/HTTPS downloads"
        author = "Silent Scan"
        severity = "Medium"

    strings:
        $d1 = "URLDownloadToFile" ascii wide nocase
        $d2 = "InternetOpenUrl" ascii wide nocase
        $d3 = "WinHttpOpen" ascii wide nocase

    condition:
        any of ($d*)
}

rule Process_Injection
{
    meta:
        description = "Detects classic Process Injection API sequence"
        author = "Silent Scan"
        severity = "High"

    strings:
        $p1 = "OpenProcess" ascii wide nocase
        $p2 = "VirtualAllocEx" ascii wide nocase
        $p3 = "WriteProcessMemory" ascii wide nocase
        $p4 = "CreateRemoteThread" ascii wide nocase

    condition:
        3 of them
}