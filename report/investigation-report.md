# Investigation Report: Mailbox Verification Phishing

Case ID: PH-2026-001
Analyst: Daniel
Report date: 2026-10-02
Status: Closed (simulated exercise)
Classification: Credential phishing

Note: This is a simulated case. The email, domains, and IPs are fictional. Enrichment results in section 6 are illustrative and are marked as simulated.

## 1. Executive summary

On 2026-10-01 at 14:22 EDT, an employee at Brightline Corp received an email claiming their mailbox was 98% full and that they must verify their account within 24 hours. The email came from a lookalike domain and the verify link pointed to a fake login page, not the company portal. The email was assessed as credential phishing. No evidence of a click or credential entry was found in this exercise. Recommended actions were to block the domain and IP, purge the message from all mailboxes, and reset the recipient password as a precaution.

## 2. Scope and evidence

| Evidence | Detail |
|---|---|
| File | evidence/sample.eml |
| SHA256 | 8075ea6522df1018bae1c2edc21c21b20a6507731abe4169ccf470f3bc07a753 |
| Recipient | j.alvarez at brightline.example |
| Received | 2026-10-01 14:22:05 to 14:22:09 -0400 |

## 3. Timeline

| Time (EDT) | Event |
|---|---|
| 2026-10-01 14:21:58 | Email created (Date header) |
| 2026-10-01 14:22:05 | Accepted by company mail gateway from 203[.]0[.]113[.]45 |
| 2026-10-01 14:22:09 | Delivered to recipient mailbox |
| 2026-10-01 (later) | User reports the email to the SOC (assumed for this exercise) |
| 2026-10-02 | Analysis, containment, and report |

## 4. Email header analysis

| Field | Value | Assessment |
|---|---|---|
| From | "Brightline IT Helpdesk" no-reply at brlghtline-it[.]example | Display name claims to be internal IT. Domain swaps the letter i for l in "brightline" and adds "-it". |
| Return-Path | bounce at brlghtline-it[.]example | Matches From domain, so no spoofing of the envelope sender. |
| Reply-To | helpdesk-recovery at freemail[.]example | Different from From. Replies would go to a free mail account, which no real IT team would use. |
| X-Mailer | PHPMailer 6.5.0 | Scripted sending library, not a normal mail client. |
| Origin IP | 203[.]0[.]113[.]45 | First external hop in the Received chain. |
| SPF | pass | Attacker controls the lookalike domain DNS and set up SPF. |
| DKIM | pass | Attacker signed with their own domain key. |
| DMARC | pass | Passes for the lookalike domain, not for the real company domain. |

Key point: authentication passing does not mean an email is safe. SPF, DKIM, and DMARC only prove the sender controls the domain in the From address. They do not prove it is the domain you think it is.

## 5. Body and link analysis

Social engineering traits found:
- Fear: mail will be blocked and messages permanently deleted
- Urgency: verify within 24 hours
- Authority: signed as IT Helpdesk
- Generic greeting with no name
- Subject uses a bracketed tag to look like an official notice

Link analysis:

| | Value |
|---|---|
| Text shown to the user | hxxps://portal[.]brightline[.]example/mailbox/verify |
| Real destination (href) | hxxps://brlghtline-it[.]example/login/verify?uid=j[.]alvarez&t=8f3a1c |

The visible link looks like the real company portal, but the underlying link goes to the attacker domain. The plain text version of the email shows the real portal URL as a decoy. The URL contains the victim username and a tracking token, which suggests the page is prefilled to look more convincing and to track who clicks.

## 6. Infrastructure enrichment (simulated)

These values are illustrative for the exercise. For a real case, run these lookups on the live indicators.

| Check | Tool | Simulated result |
|---|---|---|
| Domain registration | WHOIS | Registered 3 days before the email, privacy protected |
| IP reputation | VirusTotal, AbuseIPDB | Hosted on a low cost VPS provider, flagged by several vendors |
| Page analysis | urlscan.io | Login form posting credentials to the same domain, copies company logo |
| Certificate | crt.sh | Free certificate issued the same day as registration |

Why these matter: a very new domain, privacy protected registration, and a fresh free certificate are common for short lived phishing infrastructure.

## 7. Indicators of compromise

All values are defanged. Full list in iocs/iocs.csv.

| Type | Value |
|---|---|
| Domain | brlghtline-it[.]example |
| Domain | freemail[.]example (Reply-To, context only, do not block a shared provider blindly) |
| IP | 203[.]0[.]113[.]45 |
| URL | hxxps://brlghtline-it[.]example/login/verify |
| Sender | no-reply at brlghtline-it[.]example |
| Subject keyword | Mailbox storage 98% full |
| File hash | 8075ea6522df1018bae1c2edc21c21b20a6507731abe4169ccf470f3bc07a753 (the .eml) |

## 8. MITRE ATT&CK mapping

| Tactic | Technique | Evidence |
|---|---|---|
| Reconnaissance | T1598.003 Phishing for Information: Spearphishing Link | Fake login page to collect credentials |
| Initial Access | T1566.002 Phishing: Spearphishing Link | Malicious link in email body |
| Execution | T1204.001 User Execution: Malicious Link | Relies on the user clicking |
| Resource Development | T1583.001 Acquire Infrastructure: Domains | Lookalike domain registered for the campaign |

## 9. Verdict

Malicious. Confidence: high.

Reasons: lookalike domain, mismatch between visible and real link, Reply-To to a free mail account, threat and urgency language, scripted mailer, and a recently registered domain.

## 10. Impact assessment

- Click activity: no proxy evidence of a visit to the domain (simulated)
- Credential entry: none observed
- Other recipients: search of the mail gateway for the sender domain and subject returned one message (simulated)
- Risk if the user had entered credentials: mailbox access, internal phishing from a trusted account, and possible access to other systems that use the same login

## 11. Response actions

Containment:
1. Block brlghtline-it[.]example at the DNS filter, web proxy, and mail gateway
2. Block 203[.]0[.]113[.]45 at the firewall
3. Search and purge the message from all mailboxes
4. Reset the recipient password and revoke active sessions as a precaution
5. Confirm MFA is enabled on the account

Recovery and communication:
6. Send a short notice to staff describing the lure and how to report it
7. Thank the user who reported it

## 12. Detection and prevention

- Sigma rule for the lookalike domain and link mismatch: detection/sigma-lookalike-domain.yml
- Example SIEM queries: detection/splunk-queries.md
- Add the company name and common typos to a lookalike domain watch list
- Alert on newly registered domains in email links
- Enable external sender banners
- Run regular phishing awareness training that includes the "authentication passed but still phishing" lesson

## 13. Lessons learned

1. Passing SPF, DKIM, and DMARC is not a safety signal by itself.
2. Hover over links and compare the real destination to the visible text.
3. A Reply-To that differs from the From address is worth a closer look.
4. Fast user reporting limits the time an attacker has to use stolen credentials.

## 14. References

- MITRE ATT&CK: https://attack.mitre.org
- RFC 5737 (documentation IP ranges): https://www.rfc-editor.org/rfc/rfc5737
- RFC 2606 (reserved example domains): https://www.rfc-editor.org/rfc/rfc2606
