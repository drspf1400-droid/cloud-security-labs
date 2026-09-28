#!/usr/bin/env python3

import json
import sys
from pathlib import Path


SEVERITY_RANK = {
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}


def prioritize_finding(finding, asset):
    severity = finding["baseline_severity"]
    score = SEVERITY_RANK[severity]

    reasons = [
        f"baseline_severity={severity}"
    ]

    if asset.get("internet_exposed") is True:
        score += 1
        reasons.append("internet_exposed=true")

    criticality = asset.get("business_criticality")
    if criticality in {"high", "critical"}:
        score += 1
        reasons.append(f"business_criticality={criticality}")

    if asset.get("environment") == "production":
        score += 1
        reasons.append("environment=production")

    return {
        "finding_id": finding["finding_id"],
        "baseline_severity": severity,
        "priority_score": score,
        "priority_reasons": reasons,
    }


def main():
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: prioritize.py INPUT_ASSESSMENT OUTPUT_FILE"
        )

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    assessment = json.loads(input_path.read_text())
    asset = assessment["asset"]

    priorities = [
        prioritize_finding(finding, asset)
        for finding in assessment["findings"]
    ]

    priorities.sort(
        key=lambda item: (
            item["priority_score"],
            SEVERITY_RANK[item["baseline_severity"]],
            item["finding_id"],
        ),
        reverse=True,
    )

    result = {
        "engine": {
            "name": "deterministic-baseline",
            "version": "1.0",
        },
        "assessment_id": assessment["assessment"]["assessment_id"],
        "priorities": priorities,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, indent=2) + "\n")

    for item in priorities:
        print(
            f"{item['finding_id']}: "
            f"score={item['priority_score']} "
            f"severity={item['baseline_severity']}"
        )


if __name__ == "__main__":
    main()
