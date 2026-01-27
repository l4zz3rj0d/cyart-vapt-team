# Reporting Practice

This section demonstrates structured security reporting based on the findings
from the Week 3 engagement. The objective is to show the ability to communicate
technical issues clearly, structure findings professionally, and tailor content
for both technical and non-technical audiences.

---

## Report Structure

The report structure used for this task follows a simplified professional
pentesting format:

- Executive Summary  
- Technical Findings  
- Risk and Impact  
- Recommendations  
- Evidence References  

This structure was applied across the Week 3 documentation to ensure clarity,
traceability, and professionalism.

---

## Executive Summary (Technical Engagement Summary)

During testing, a critical Server-Side Template Injection (SSTI) vulnerability
was identified in the target web application (Form Tools 3.1.1). The issue was
confirmed through manual testing, mapped to CVE-2024-22722, and demonstrated to
lead to Remote Code Execution (RCE) and shell access.

The vulnerability allowed attacker-controlled input to be evaluated on the
server, ultimately resulting in system-level command execution under the
www-data context. This represents a complete compromise of application
confidentiality and integrity.

---

## Technical Findings

| Finding ID | Vulnerability | Severity | Evidence |
|------------|----------------|----------|----------|
| F-001 | Server-Side Template Injection (SSTI) | Critical | Web-Application-Testing/Evidence |
| F-002 | Remote Code Execution via SSTI | Critical | Advanced-Exploitation/Evidence |
| F-003 | Unauthorized System Access | High | Post-Exploitation/Evidence |

All findings were validated manually and supported by captured evidence within
their respective subdirectories.

---

## Risk and Impact

The identified vulnerability chain allows:

- Execution of arbitrary system commands  
- Remote shell access to the target server  
- Exposure of system-level data  
- Potential pivoting or lateral movement in real-world environments  

This demonstrates a complete failure of input handling and server-side trust
boundaries.

---

## Recommendations

The following remediation measures are recommended based on the findings:

- Strict server-side input validation  
- Disable dangerous template engine functions  
- Apply security patches for Form Tools (upgrade beyond 3.1.1)  
- Apply template sandboxing where supported  
- Implement application security testing into the SDLC  

---

## Stakeholder-Friendly Summary (Non-Technical)

A critical weakness was found in the application that allows attackers to take
control of the server by simply submitting specially crafted input into a form.
This could allow unauthorized access to data and full compromise of the system.

Fixing this issue requires proper input validation, disabling unsafe template
features, and updating the vulnerable software to a secure version.

---

## Outcome

This reporting exercise demonstrates:

- Ability to structure findings clearly  
- Translation of technical impact into business risk  
- Evidence-based reporting  
- Professional documentation style  
- Alignment with real-world pentesting deliverables  
