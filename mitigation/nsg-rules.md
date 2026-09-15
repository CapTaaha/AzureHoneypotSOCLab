# Mitigation: Securing the VM in a Real Environment

This lab intentionally exposed the VM to the entire internet in order to collect attack data. **None of the configuration below should ever be used in production.** This document describes what would be done differently to secure a real internet-facing VM.

## 1. Restrict NSG Rules

Instead of an `Allow Any/Any/Any` rule, restrict inbound access to only the ports and source IPs that are actually needed:

| Priority | Name | Port | Protocol | Source | Destination | Action |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 100 | Allow-RDP-Trusted | 3389 | TCP | `<office/home IP>/32` | Any | Allow |
| 200 | Deny-All-Inbound | Any | Any | Any | Any | Deny |

## 2. Just-In-Time (JIT) VM Access

Enable JIT access through Microsoft Defender for Cloud so that management ports (RDP/SSH) are closed by default and only opened for a limited time window when explicitly requested and approved.

## 3. Multi-Factor Authentication (MFA)

Require MFA for any account with administrative access to the VM, ideally enforced through Azure AD Conditional Access policies rather than local account MFA alone.

## 4. Azure Bastion

Deploy Azure Bastion so RDP/SSH sessions are proxied through the Azure portal over TLS, removing the need to expose port 3389/22 to the public internet at all.

## 5. Microsoft Defender for Cloud

Enable Defender for Servers to get:
- Vulnerability assessment
- Just-in-time access recommendations
- Adaptive network hardening
- Threat detection and alerting

## 6. Strong Password & Account Lockout Policy

- Enforce complex passwords (length, character variety).
- Enable account lockout after a small number of failed attempts to blunt brute-force attacks.
- Rename or disable the default `Administrator` account, since it was the most frequently targeted username in this lab.

## 7. Sentinel Analytics Rules

Create scheduled analytics rules in Sentinel that:
- Alert on a threshold of failed logons (Event ID 4625) from a single IP within a short time window.
- Trigger a Logic App playbook to automatically block the offending IP at the NSG level.
