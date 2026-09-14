from scripts.evaluate_dataset import evaluate

def test_evaluation_hides_labels_and_reports_metrics():
    observed = []
    rows = [
        {"title": "RCE", "description": "remote code execution", "cwe": "CWE-78", "true_category": "Remote Code Execution", "cvss": "9.8", "kev": "True", "true_risk_score": "10"},
        {"title": "SQL", "description": "SQL injection", "cwe": "CWE-89", "true_category": "SQL Injection", "cvss": "8.0", "kev": "False", "true_risk_score": "8"},
    ]
    def predictor(text):
        observed.append(text)
        return {"category": "Remote Code Execution" if "remote" in text else "SQL Injection", "confidence": 0.9}
    report = evaluate(rows, predictor)
    assert report["accuracy"] == 1.0
    assert report["risk_score_mae"] is not None
    assert all("true_category" not in text for text in observed)
