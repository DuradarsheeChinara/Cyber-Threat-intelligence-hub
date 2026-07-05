"""Mock threat feed data for local AI service development."""

from __future__ import annotations

from typing import Any

sample_threats: list[dict[str, Any]] = [
    {
        "id": "CVE-2026-0001",
        "title": "Remote code execution in Acme Web Gateway",
        "vendor": "Acme Security",
        "product": "Web Gateway",
        "description": (
            "A deserialization flaw in the administrative API allows an "
            "unauthenticated remote attacker to execute arbitrary commands "
            "on vulnerable gateway appliances."
        ),
        "cvss": 9.8,
        "kev": True,
        "published": "2026-06-30",
    },
    {
        "id": "CVE-2026-0002",
        "title": "Stored cross-site scripting in HelpDesk Pro",
        "vendor": "Northstar Apps",
        "product": "HelpDesk Pro",
        "description": (
            "Improper input sanitization in ticket comments allows attackers "
            "with a standard user account to store malicious JavaScript that "
            "executes in an administrator browser session."
        ),
        "cvss": 6.1,
        "kev": False,
        "published": "2026-06-28",
    },
    {
        "id": "CVE-2026-0003",
        "title": "Authentication bypass in cloud identity connector",
        "vendor": "Contoso Cloud",
        "product": "Identity Connector",
        "description": (
            "A logic error in token validation may allow attackers to bypass "
            "authentication and access restricted tenant synchronization APIs."
        ),
        "cvss": 8.6,
        "kev": True,
        "published": "2026-06-25",
    },
]
