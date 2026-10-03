#!/usr/bin/env python3
"""
extract_iocs.py
Parse a .eml file and pull out phishing indicators.
All indicators in the output are defanged.

Usage:
  python3 scripts/extract_iocs.py evidence/sample.eml --legit-domain brightline.example --csv iocs/iocs.csv
"""
import argparse
import csv
import difflib
import hashlib
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
URGENCY = ["urgent", "immediately", "within 24 hours", "action required",
           "verify", "suspend", "permanently", "blocked", "expire"]


def defang(value):
    return value.replace("http", "hxxp").replace(".", "[.]")


def domain_of(address):
    if not address:
        return ""
    return address.rsplit("@", 1)[-1].strip("<> ").lower()


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def lookalike_score(candidate, legit):
    full = difflib.SequenceMatcher(None, candidate, legit).ratio()
    label = difflib.SequenceMatcher(
        None, candidate.split(".")[0].split("-")[0], legit.split(".")[0]
    ).ratio()
    return max(full, label)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("eml")
    ap.add_argument("--legit-domain", required=True,
                    help="the real domain being impersonated")
    ap.add_argument("--csv", help="write IOC table to this path")
    args = ap.parse_args()

    raw = open(args.eml, "rb").read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    rows = [("file_sha256", hashlib.sha256(raw).hexdigest(), "evidence file")]
    findings = []

    from_dom = domain_of(msg["From"].addresses[0].addr_spec if msg["From"] else "")
    rp_dom = domain_of(msg.get("Return-Path", ""))
    rt_dom = domain_of(msg["Reply-To"].addresses[0].addr_spec) if msg["Reply-To"] else ""

    print("== Header summary ==")
    for h in ("From", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID", "X-Mailer"):
        print(f"{h}: {msg.get(h)}")

    print("\n== Authentication ==")
    auth = msg.get("Authentication-Results", "")
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"{mech}=(\w+)", auth)
        print(f"{mech}: {m.group(1) if m else 'not present'}")

    received = msg.get_all("Received", [])
    first_hop_ips = IP_RE.findall(received[-1]) if received else []
    print("\n== Origin ==")
    print("First external hop IP(s):", ", ".join(defang(i) for i in first_hop_ips) or "none")
    for ip in first_hop_ips:
        rows.append(("ip", defang(ip), "first external hop in Received chain"))

    for dom, label in ((from_dom, "From domain"), (rp_dom, "Return-Path domain"),
                       (rt_dom, "Reply-To domain")):
        if dom:
            rows.append(("domain", defang(dom), label))

    if from_dom and from_dom != args.legit_domain:
        score = lookalike_score(from_dom, args.legit_domain)
        if score >= 0.8:
            findings.append(f"From domain {defang(from_dom)} looks like {defang(args.legit_domain)} (similarity {score:.2f})")
    if rt_dom and rt_dom != from_dom:
        findings.append(f"Reply-To domain ({defang(rt_dom)}) differs from From domain ({defang(from_dom)})")
    if msg["From"] and "helpdesk" in msg["From"].addresses[0].display_name.lower() and from_dom != args.legit_domain:
        findings.append("Display name claims to be internal IT but domain is not the company domain")
    if "mailer" in msg.get("X-Mailer", "").lower():
        findings.append(f"Bulk mailer library in X-Mailer: {msg.get('X-Mailer')}")

    html_body, text_body = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "text/html":
            html_body += part.get_content()
        elif ctype == "text/plain":
            text_body += part.get_content()

    parser = LinkParser()
    parser.feed(html_body)
    seen = set()
    print("\n== Links ==")
    for href, text in parser.links:
        host = urlparse(href).hostname or ""
        print(f"href: {defang(href)}\n  text: {defang(text)}")
        seen.add(href)
        rows.append(("url", defang(href), "HTML anchor href"))
        rows.append(("domain", defang(host), "host of href"))
        if text.lower().startswith("http"):
            shown = urlparse(text).hostname or ""
            if shown != host:
                findings.append(f"Link text shows {defang(shown)} but href goes to {defang(host)}")
    for url in URL_RE.findall(text_body):
        if url not in seen:
            rows.append(("url", defang(url), "plain text body (decoy)"))

    body_all = (text_body + html_body + msg.get("Subject", "")).lower()
    hits = [w for w in URGENCY if w in body_all]
    if hits:
        findings.append("Urgency or threat language: " + ", ".join(hits))

    print("\n== Findings ==")
    for f in findings:
        print("-", f)

    if args.csv:
        with open(args.csv, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["type", "value", "context"])
            done = set()
            for r in rows:
                if r[:2] not in done:
                    done.add(r[:2])
                    w.writerow(r)
        print(f"\nIOC table written to {args.csv}")


if __name__ == "__main__":
    main()
