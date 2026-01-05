# Vulnerability Assessment and Penetration Testing (VAPT) 

## Overview
This repository documents a structured Vulnerability Assessment and Penetration
Testing (VAPT) workflow carried out in an authorized and controlled lab
environment. The objective is to demonstrate practical security testing skills,
methodology, and proper technical documentation.

The workflow covers network-level assessment, manual exploitation, post-
exploitation validation, web application testing, and automated vulnerability
scanning.

---

## Scope and Authorization
- Target Type: Deliberately vulnerable systems
- Testing Type: Educational / Authorized lab assessment
- Scope: Network services, system-level vulnerabilities, and web application
  vulnerabilities
- All activities were performed strictly for learning and demonstration purposes

---

## VAPT Workflow Summary

1. Network Scanning and Enumeration  
2. Vulnerability Identification  
3. Exploitation  
4. Post-Exploitation  
5. Web Application VAPT (DVWA)  
6. Automated Vulnerability Scanning 

---

## Phase 1: Network Scanning and Enumeration

**Tool Used:** Nmap  

### Activities
- Full TCP port scanning
- Service and version detection
- Identification of exposed and potentially vulnerable services

###  Command Used
```
nmap -sV  192.168.56.5 -oN nmap_scan.txt
# Nmap 7.98 scan initiated Mon Jan  5 04:25:28 2026 as: /usr/lib/nmap/nmap --privileged -sV -oN nmap_scan.txt 192.168.56.5
Nmap scan report for 192.168.56.5
Host is up (0.0033s latency).
Not shown: 977 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet      Linux telnetd
25/tcp   open  smtp        Postfix smtpd
53/tcp   open  domain      ISC BIND 9.4.2
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp  open  rpcbind     2 (RPC #100000)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp  open  exec        netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  shell       Netkit rshd
1099/tcp open  java-rmi    GNU Classpath grmiregistry
1524/tcp open  bindshell   Metasploitable root shell
2049/tcp open  nfs         2-4 (RPC #100003)
2121/tcp open  ftp         ProFTPD 1.3.1
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp open  vnc         VNC (protocol 3.3)
6000/tcp open  X11         (access denied)
6667/tcp open  irc         UnrealIRCd
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Jan  5 04:25:44 2026 -- 1 IP address (1 host up) scanned in 16.46 seconds
```
### Outcome
Multiple network services were identified running outdated or insecure versions,
indicating a broad attack surface for further assessment.

### Evidence Location

Week 2/Scanning/

## Phase 2: Vulnerability Identification
Based on enumeration results, identified services were analyzed for known
weaknesses and misconfigurations.

### Key Observations
Insecure and legacy services exposed to the network

### Weak authentication mechanisms

Services commonly associated with publicly known exploits

A vulnerability mapping table was created to correlate services with risk level
and potential impact.

### Documentation

| Port | Service | Version | Risk | Reason |
|------|--------|---------|------|--------|
| 21 | FTP | vsftpd 2.3.4 | High | Known backdoor vulnerability |
| 23 | Telnet | Linux telnetd | High | Cleartext authentication |
| 139/445 | SMB | Samba 3.x | Critical | Multiple RCE vulnerabilities |
| 1524 | bindshell | Metasploitable root shell | Critical | Unauthenticated root access |
| 8180 | HTTP | Apache Tomcat | High | Weak credentials / RCE |



## Phase 3: Exploitation

Tool Used: Metasploit Framework

### Activities
Selection of exploit modules based on identified services
```
selection command prompt needed
```

Successful exploitation of vulnerable service
```
command prommpt text needed
```
Shell access obtained on the target system
```
full working bash shell needed 
```
### Result
The target system was successfully compromised, and root-level access was
achieved due to critical security misconfigurations. This confirms a high to
critical severity impact.

### Evidence Location

Week 2/Exploitation/

## Phase 4: Post-Exploitation
### Activities
Verification of privilege level
```
priv check needed
```

### Outcome
Post-exploitation confirmed complete system control, validating the severity of
the identified vulnerabilities.

### Evidence Location

Week 2/Post-Exploitation/

## Phase 5: Web Application VAPT (DVWA)
### Application Tested: Damn Vulnerable Web Application (DVWA)

### Vulnerability Identified
SQL Injection due to improper input validation

### Exploitation Method
Authenticated SQL Injection testing was performed using automated tooling.

```
sqlmap -u "http://<target-ip>/vulnerabilities/sqli/?id=1&Submit=Submit#" \
--cookie="security=low; PHPSESSID=<session-id>" \
-D dvwa -T users --dump
```
### Results
```
result here
```
Backend DBMS identified as MySQL

Databases and tables enumerated successfully

Sensitive user information extracted from the users table

Multiple SQL Injection techniques confirmed:

Boolean-based

Error-based

Time-based

UNION-based

### Evidence Location

Week 2/Capstone/

## Phase 6: Automated Vulnerability Scanning (OpenVAS)
Tool: OpenVAS / Greenbone Vulnerability Manager
```
needs to be configured
```
Week 2/scanning/
### Repository Structure

Week 2/
├──Theory
├── Scanning/
├── Exploitation/
├── Post-Exploitation/
├── Capstone/
└── README.md
### Key Takeaways
Manual enumeration is essential for accurate vulnerability discovery

Exploitation validates real-world impact beyond automated scan results

Authenticated web application testing exposes critical vulnerabilities

Automated tools support, but do not replace, structured methodology


