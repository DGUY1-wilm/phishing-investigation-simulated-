# Phishing Investigation: Fake IT Mailbox Verification (Simulated)

See GETTING_STARTED for beginner friendly simulation setup and execution. 
A SOC style investigation of a simulated credential harvesting email. The email, domains, and IP addresses are fictional and use reserved example ranges (.example domains, RFC 5737 IPs). Nothing here is a live threat.

## Summary

| Item | Detail |
|---|---|
| Verdict | Malicious, credential phishing |
| Attack type | Spoofed IT helpdesk, fake mailbox full notice |
| Target | Single employee mailbox |
| Technique | Lookalike domain, link text mismatch, urgency |
| ATT&CK | T1566.002, T1598.003, T1204.001 |
| Key lesson | SPF, DKIM, and DMARC all passed, because the attacker owned the lookalike domain |

## What is in this repo

- report/investigation-report.md: full write up with timeline, analysis, verdict, and response
- evidence/sample.eml: the simulated email (defanged links where possible)
- scripts/extract_iocs.py: parses the email, flags suspicious traits, outputs defanged IOCs
- iocs/iocs.csv: indicator table produced by the script
- detection/: a Sigma rule and example Splunk queries
- screenshots/: add your own screenshots of the script output and any tools you use

## How to run

```
python3 scripts/extract_iocs.py evidence/sample.eml --legit-domain brightline.example --csv iocs/iocs.csv
```

Requires Python 3.8 or newer. No third party packages.

## Skills shown

Email header analysis, authentication result interpretation, lookalike domain detection, IOC extraction and defanging, MITRE ATT&CK mapping, incident response steps, detection engineering, and clear reporting.

## Disclaimer

For education and defensive security practice only.
