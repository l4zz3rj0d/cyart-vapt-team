# API Security Testing (OWASP crAPI)

## Overview
This section documents an API security assessment performed against the
**OWASP crAPI (Completely Ridiculous API)** application in a controlled lab
environment. The objective was to demonstrate practical API pentesting skills
such as request interception, parameter manipulation, logic testing, and impact
validation aligned with the **OWASP API Top 10**.

---

## Scope and Environment
- Target Application: OWASP crAPI
- Testing Platform: Kali Linux
- Intercepting Proxy: Caido
- Testing Methodology:
  - Manual request interception
  - Endpoint analysis
  - Parameter tampering
  - Authentication logic testing

---

## Tools Used
- Caido (Intercepting proxy)
- Browser
- Kali Linux
- Docker (crAPI environment)

---
## API Security Testing Summary

Test ID | Vulnerability                 | Severity | Target Endpoint
------- |-------------------------------|----------|-------------------------------
008     | BOLA / IDOR                   | Critical | /api/posts, /api/vehicle/*
009     | Excessive Data Exposure       | High     | /api/posts
010     | OTP Bypass → Account Takeover | Critical | /api/auth/forgot-password

---

## Initial Interaction

A user was created for testing.

Example user:
```
{"name":"lazzer","email":"lazzer@hackcorp.com","number":"1234567890","password":"SuperStrong@123"}
```

## Vulnerability 1: Content Discovery & Sensitive Data Exposure
### Observation

While browsing the community posts feature, the frontend did not reveal much
information. However, inspection of backend API responses using Caido revealed
that the API exposes sensitive user information.

![project post](Evidence/post_section.png)
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

![project cd](Evidence/Content_discovery.png)

### Impact

This represents Excessive Data Exposure, allowing attackers to collect user
information for further targeted attacks.


## Vulnerability 2: IDOR / BOLA (Broken Object Level Authorization)
### Observation

Using the Contact Mechanic feature, backend requests containing ID parameters
were observed.

![project mech](Evidence/contact_mechanic.png)

The request included a user-specific identifier.

![project id](Evidence/id_request.png)

By modifying the ID value to another user's ID, data belonging to other users
became accessible.

![project IDOR](Evidence/IDOR.png)

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

![project veh](Evidence/IDOR_vehicle.png)

### Impact

This confirms a BOLA (Broken Object Level Authorization) vulnerability.
Any authenticated user can access other users’ sensitive data by modifying
request parameters.


## Vulnerability 3: OTP Bypass → Account Takeover
### Observation

The password reset functionality required OTP verification.

![project otp](Evidence/invalid_otp.png)

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

![project by](Evidence/success_otp.png)

Successful request:
```
{"email":"robot001@example.com","otp":"4872","password":"Password@123"}

```

The password reset succeeded, resulting in full account takeover.

![project take](Evidence/account_takeover.png)

### Impact

This vulnerability allows:

- OTP brute-force attacks

- Password reset abuse

- Full account takeover

- Abuse of legacy API versions

This maps to Broken Authentication and Improper API Versioning Controls
within the OWASP API Top 10.
