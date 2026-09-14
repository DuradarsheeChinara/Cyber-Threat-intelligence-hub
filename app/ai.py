def analyze_threat(threat: dict) -> dict:
    description = threat.get("description", "").lower()
    cvss = threat.get("cvss", 0)

    if "remote code execution" in description or "rce" in description:
        category = "Remote Code Execution"
    elif "denial of service" in description:
        category = "Denial of Service"
    elif "privilege escalation" in description:
        category = "Privilege Escalation"
    elif "sql injection" in description:
        category = "SQL Injection"
    else:
        category = "Other"

    summary = (
        f"This vulnerability affects {threat.get('product', 'the product')} "
        f"by {threat.get('vendor', 'the vendor')}. It is classified as {category}, "
        f"has a CVSS score of {cvss}, and "
        f"{'is actively exploited in the wild (KEV listed).' if threat.get('kev') else 'is not currently listed as actively exploited.'}"
    )

    risk_score = cvss
    if threat.get("kev"):
        risk_score = min(10, risk_score + 1.5)

    return {
        "ai_summary": summary,
        "threat_category": category,
        "risk_score": round(risk_score, 2),
    }