sample_threats = [
    {
        "id": "CVE-2026-0001",
        "title": "Apache HTTP Server Remote Code Execution",
        "vendor": "Apache",
        "product": "HTTP Server",
        "description": """
A vulnerability in Apache HTTP Server allows remote attackers
to execute arbitrary code by sending specially crafted HTTP
requests. Successful exploitation may lead to complete system
compromise.
""",
        "cvss": 9.8,
        "kev": True,
        "published": "2026-06-30"
    },

    {
        "id": "CVE-2026-0002",
        "title": "Linux Kernel Denial of Service",
        "vendor": "Linux",
        "product": "Kernel",
        "description": """
Improper handling of malformed network packets can cause the
Linux kernel to crash, allowing attackers to trigger a denial
of service remotely.
""",
        "cvss": 7.5,
        "kev": False,
        "published": "2026-06-28"
    },

    {
        "id": "CVE-2026-0003",
        "title": "Microsoft Windows Privilege Escalation",
        "vendor": "Microsoft",
        "product": "Windows",
        "description": """
A flaw in Windows allows a local attacker to gain SYSTEM
privileges by exploiting improper access control within a
kernel component.
""",
        "cvss": 8.8,
        "kev": True,
        "published": "2026-06-26"
    },

    {
        "id": "CVE-2026-0004",
        "title": "MySQL Information Disclosure",
        "vendor": "Oracle",
        "product": "MySQL",
        "description": """
An authenticated user may obtain sensitive information from
the database because of insufficient authorization checks.
""",
        "cvss": 5.6,
        "kev": False,
        "published": "2026-06-25"
    },

    {
        "id": "CVE-2026-0005",
        "title": "OpenSSH Authentication Bypass",
        "vendor": "OpenSSH",
        "product": "OpenSSH",
        "description": """
Improper authentication logic may allow attackers to bypass
authentication under specific conditions and gain unauthorized
access to SSH services.
""",
        "cvss": 9.1,
        "kev": True,
        "published": "2026-06-24"
    }
]