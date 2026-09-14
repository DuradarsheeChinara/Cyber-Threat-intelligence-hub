"""Held-out evaluation; true_category is intentionally never passed to inference."""
from __future__ import annotations
import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Callable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.ai.classifier import CATEGORIES as MODEL_CATEGORIES, _get_classifier, classify
from backend.services.risk_engine import calculate_risk

CATEGORIES = ["Remote Code Execution", "Denial of Service", "Privilege Escalation", "SQL Injection", "Other"]


def _batch_classify(texts: list[str]) -> list[dict]:
    """Use the existing zero-shot model in batches for practical CPU evaluation."""
    if not texts:
        return []
    results = _get_classifier()(texts, candidate_labels=MODEL_CATEGORIES, multi_label=False, batch_size=16)
    if isinstance(results, dict):
        results = [results]
    return [
        {"category": item["labels"][0], "confidence": round(float(item["scores"][0]), 4)}
        if item.get("labels") and item.get("scores") else {"category": "Other", "confidence": 0.0}
        for item in results
    ]

def evaluate(rows: list[dict[str, str]], predictor: Callable[[str], dict] = classify) -> dict:
    matrix = {actual: {predicted: 0 for predicted in CATEGORIES} for actual in CATEGORIES}
    correct = total = 0; absolute_errors: list[float] = []
    texts = ["\n".join(filter(None, [row.get("title"), row.get("description"), row.get("cwe")])) for row in rows]
    predictions = _batch_classify(texts) if predictor is classify else [predictor(text) for text in texts]
    for row, prediction in zip(rows, predictions):
        actual = row.get("true_category")
        if actual not in CATEGORIES: continue
        predicted = prediction.get("category", "Other")
        if predicted not in CATEGORIES: predicted = "Other"
        matrix[actual][predicted] += 1; total += 1; correct += actual == predicted
        if row.get("true_risk_score"):
            predicted_risk = calculate_risk({"cvss": row.get("cvss"), "kev": row.get("kev") == "True"}, prediction)["risk_score"]
            absolute_errors.append(abs(predicted_risk - float(row["true_risk_score"])))
    per_class = {}
    for category in CATEGORIES:
        tp = matrix[category][category]; fp = sum(matrix[other][category] for other in CATEGORIES if other != category); fn = sum(matrix[category][other] for other in CATEGORIES if other != category)
        precision = tp / (tp + fp) if tp + fp else 0.0; recall = tp / (tp + fn) if tp + fn else 0.0
        per_class[category] = {"precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0}
    return {"records_evaluated": total, "accuracy": correct / total if total else 0.0, "macro_precision": sum(x["precision"] for x in per_class.values()) / len(CATEGORIES), "macro_recall": sum(x["recall"] for x in per_class.values()) / len(CATEGORIES), "macro_f1": sum(x["f1"] for x in per_class.values()) / len(CATEGORIES), "confusion_matrix": matrix, "risk_score_mae": sum(absolute_errors) / len(absolute_errors) if absolute_errors else None, "per_class": per_class}

def main() -> None:
    parser = argparse.ArgumentParser(); parser.add_argument("--input", type=Path, default=Path("data/threats_test.csv")); parser.add_argument("--output", type=Path, default=Path("backend/output/evaluation.json")); args = parser.parse_args()
    with args.input.open(encoding="utf-8-sig", newline="") as stream: report = evaluate(list(csv.DictReader(stream)))
    args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(json.dumps(report, indent=2), encoding="utf-8"); print(json.dumps(report, indent=2))

if __name__ == "__main__": main()
