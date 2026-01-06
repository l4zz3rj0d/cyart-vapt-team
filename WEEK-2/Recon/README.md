# Reconnaissance – Metasploitable2

## Objective
To gather information about exposed services and interfaces in order to
identify potential attack vectors prior to exploitation.

---

## Target Information
- Target Machine: Metasploitable2
- Target IP: 192.168.56.5

---

## Reconnaissance Activities
Reconnaissance was conducted using a combination of network enumeration and
web-based inspection techniques.

The following activities were performed:
- Identification of exposed services through network scanning
- Manual inspection of web-accessible services
- Information gathering from service interfaces to identify misconfigurations

---

## Web-Based Reconnaissance
During reconnaissance, the Apache Tomcat web interface was accessed through a
browser to gather information related to service configuration and access
controls.

The Tomcat landing and manager-related pages were reviewed to identify:
- Service version and deployment details
- Exposed management interfaces
- Indicators of weak or default credential usage

This step helped confirm that the Tomcat Manager interface was accessible and
represented a viable attack surface.

---

## Findings
Reconnaissance revealed that the Apache Tomcat Manager service was exposed and
reachable over the network. The presence of a management interface increased
the likelihood of weak or default credentials being in use.

These findings indicated a high-risk entry point suitable for further
credential validation and exploitation.

---

## Outcome
The reconnaissance phase successfully identified Apache Tomcat Manager as the
primary attack vector. Information gathered during this phase directly guided
the exploitation strategy, which focused on credential discovery using the auxillary for credential identification 


