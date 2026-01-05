# Capstone Project – Web Application VAPT (DVWA)

## Objective
To perform a complete web application vulnerability assessment and penetration
test against a deliberately vulnerable application in a controlled lab
environment.

## Target Environment
- Platform: TryHackMe
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

## Tools Used
- sqlmap
- Web Browser
- TryHackMe AttackBox

## Remediation
- Use prepared statements (parameterized queries)
- Validate and sanitize all user input
- Implement least-privilege database access
- Avoid exposing detailed database errors
