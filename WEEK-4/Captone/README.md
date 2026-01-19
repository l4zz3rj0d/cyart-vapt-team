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
