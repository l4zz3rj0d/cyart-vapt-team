# Vulnerability Scanning – Metasploitable2

## Objective
The objective of this phase was to identify exposed network services and
potential security weaknesses on the target system as part of the
vulnerability assessment process.

## Target Information
- Target Machine: Metasploitable2  
- Target IP: 192.168.56.5  
- Environment: Isolated lab network  

## Tools Used
- Nmap – Network and service enumeration  
- OWASP ZAP – Web application vulnerability assessment  
- Nikto – Web server vulnerability scanning  

## Scanning Methodology
An initial network scan was performed using Nmap to enumerate all open ports
and identify running services. Service version detection was enabled to
identify potentially vulnerable software and legacy services.

Based on the discovered web services, OWASP ZAP was used to perform an
automated web application scan to identify security misconfigurations such as
missing security headers, weak session handling, and information disclosure.

Additionally, Nikto was used to conduct a focused web server scan against the
Apache Tomcat service to identify default configurations, exposed management
interfaces, and insecure HTTP methods.

## Key Findings
The scanning phase revealed multiple insecure and legacy services exposed on
the target system, including:

- FTP service running vsftpd 2.3.4  
- Telnet service allowing cleartext communication  
- SMB services exposed on ports 139 and 445  
- Web services running on Apache HTTP and Apache Tomcat  
- Exposed Tomcat management interfaces  
- Multiple database services accessible remotely  

Web application scanning further identified missing security headers,
information disclosure issues, and weak security hardening, confirming a
high-risk security posture.

## Evidence
- Nmap scan screenshots showing open ports and service versions  
- OWASP ZAP scan screenshots highlighting web application misconfigurations  
- Nikto scan output identifying default Tomcat components and exposed
  interfaces  

### Nmap Scan Result
```
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

## Outcome
The vulnerability scanning phase successfully identified critical network and
web application weaknesses. These findings directly supported the exploitation
strategy and provided a clear attack path for the exploitation and
post-exploitation phases of the VAPT workflow.
