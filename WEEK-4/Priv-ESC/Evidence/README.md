# Evidence – Privilege Escalation

This directory contains supporting artifacts collected during the privilege
escalation exercise performed on the Pluck CMS 4.7.16 lab environment.

## Contents
The evidence includes:
- Output of SUID enumeration (`find / -perm -4000`)
- Screenshots of privilege escalation execution
- Terminal proof showing escalation to root (`whoami`)
- Access to restricted directories (`/root`)

## Purpose
These artifacts demonstrate successful escalation from a low-privileged user to
root-level access in a controlled lab environment.
