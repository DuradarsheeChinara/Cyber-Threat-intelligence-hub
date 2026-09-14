from scripts.build_dataset import classify_category

def test_cwe_is_supporting_evidence_not_a_blind_lookup():
    assert classify_category("Input validation issue with no injection behavior", ["CWE-89"]) == "Other"
    assert classify_category("SQL query injection allows data extraction", ["CWE-89"]) == "SQL Injection"
    assert classify_category("A remote attacker can execute arbitrary commands", ["CWE-78"]) == "Remote Code Execution"
