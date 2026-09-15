"""Safe, local static triage for untrusted URLs and uploaded files.

This module deliberately does not fetch URLs, execute files, unpack archives,
or make a malware claim without evidence.  It provides an explainable first
pass before a reputation or antivirus service is configured.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit


MAX_FILE_BYTES = 10 * 1024 * 1024
SUSPICIOUS_URL_TERMS = {"crack", "keygen", "torrent", "repack", "warez", "download"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".js", ".jse", ".ps1", ".vbs", ".vbe", ".wsf"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".msi", ".scr", ".com", ".jar", ".apk"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}


def _verdict(score: int) -> str:
    if score >= 70:
        return "Suspicious"
    if score >= 35:
        return "Caution"
    return "Low risk"


def scan_url(value: str) -> dict:
    """Analyze URL structure only, without contacting the destination."""
    candidate = value.strip()
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Enter a complete http:// or https:// URL.")

    host = parsed.hostname.lower().rstrip(".")
    signals: list[str] = []
    score = 0
    if parsed.scheme == "http":
        signals.append("Uses unencrypted HTTP instead of HTTPS.")
        score += 15
    if host.startswith("xn--") or ".xn--" in host:
        signals.append("Internationalized (punycode) domain; verify the spelling carefully.")
        score += 25
    try:
        address = ipaddress.ip_address(host)
        if address.is_private or address.is_loopback or address.is_link_local:
            signals.append("Targets a private, loopback, or link-local address; no request was made.")
            score += 70
        else:
            signals.append("Uses a numeric IP address instead of a domain name.")
            score += 20
    except ValueError:
        pass
    if len(candidate) > 250:
        signals.append("Unusually long URL.")
        score += 10
    terms = sorted(term for term in SUSPICIOUS_URL_TERMS if term in candidate.lower())
    if terms:
        signals.append(f"Contains high-risk download terms: {', '.join(terms)}.")
        score += min(30, 10 * len(terms))
    if not signals:
        signals.append("No local structural risk signals were found.")

    return {
        "kind": "url",
        "target": candidate,
        "risk_score": min(score, 100),
        "verdict": _verdict(score) if score >= 35 else ("Review recommended" if score else "Low risk"),
        "signals": signals,
        "sha256": None,
        "note": "Static URL triage only: the link was not opened or downloaded.",
    }


def scan_file(filename: str, content: bytes) -> dict:
    """Inspect uploaded bytes without executing or retaining them."""
    if not filename:
        raise ValueError("A filename is required.")
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("File is larger than the 10 MB scan limit.")

    suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
    extension = suffixes[-1] if suffixes else ""
    signals: list[str] = []
    score = 0
    if b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" in content:
        signals.append("EICAR antivirus test signature detected.")
        score = 100
    elif content.startswith(b"MZ") or content.startswith(b"\x7fELF") or content[:4] in {b"\xfe\xed\xfa\xce", b"\xcf\xfa\xed\xfe"}:
        signals.append("Executable binary signature detected.")
        score += 45
    if extension in EXECUTABLE_EXTENSIONS:
        signals.append(f"Executable installer type ({extension}).")
        score += 30
    if extension in SCRIPT_EXTENSIONS:
        signals.append(f"Script type ({extension}) can run commands on a device.")
        score += 40
    if extension in MACRO_EXTENSIONS:
        signals.append(f"Macro-enabled Office document ({extension}).")
        score += 25
    if extension in ARCHIVE_EXTENSIONS:
        signals.append(f"Archive or disk image ({extension}); contents were not unpacked.")
        score += 10
    if len(suffixes) >= 2 and suffixes[-1] in EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS:
        signals.append("Double-extension filename may disguise an executable or script.")
        score += 30
    if not signals:
        signals.append("No local static risk signals were found.")

    return {
        "kind": "file",
        "target": filename,
        "risk_score": min(score, 100),
        "verdict": _verdict(score) if score >= 35 else ("Review recommended" if score else "Low risk"),
        "signals": signals,
        "sha256": hashlib.sha256(content).hexdigest(),
        "note": "Static file triage only: the file was not executed, opened, or retained.",
    }
