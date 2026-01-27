# Web Application Penetration Testing

This section documents the web application testing phase of the Week 3 task.
The focus of this stage was on manual reconnaissance, vulnerability discovery,
version identification, and safe confirmation of a Server-Side Template
Injection (SSTI) vulnerability without immediately moving into exploitation.

---

## Phase 1: Application Reconnaissance

Instead of relying on automated scanners, the application was explored manually
through normal user interaction.

During navigation, the following workflow was identified:

Forms → Views → Add Group

A user-controlled input field was discovered:
- Group Name

Client-side behavior was inspected and it was observed that user input was being
directly processed and sent to backend logic.

![project d](/WEEK-3/Evidence/unvalidated_user_input_ajax.png)

This suggested the presence of a potential server-side injection surface.

---

## Phase 2: Version Identification & Vulnerability Research

The application version was identified as:

Form Tools 3.1.1

![project d](/WEEK-3/Evidence/version_identification.png)

Public vulnerability research revealed the presence of a known vulnerability:

- CVE-2024-22722
- Vulnerability Type: Server-Side Template Injection (SSTI)
- Affected Parameter: Group Name field
- Impact: Remote Command Execution

![project d](/WEEK-3/Evidence/cve_reference.png)

The CVE documentation confirmed that the observed behavior matched a real-world
public vulnerability affecting this application version.

---

## Phase 3: Vulnerability Confirmation (SSTI)

To safely confirm whether template evaluation was occurring, a non-malicious
test payload was used.

Payload tested:

![project d](/WEEK-3/Evidence/SSTI_identification.png)

Expected secure behavior:
- The application should display the payload as literal text.

Actual behavior:
- The application evaluated the expression instead of displaying it.

![project d](/WEEK-3/Evidence/SSTI_confirmation.png)

This confirmed that:
- User input was being evaluated server-side by a template engine.
- The input was not properly sanitized.
- The application was vulnerable to SSTI.
