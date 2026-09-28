#!/usr/bin/env python3

import copy
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

ENGINE_NAME = "deterministic-baseline"
ENGINE_VERSION = "1.0"


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
        "score": score,
        "reasons": reasons,
        "engine": {
            "name": ENGINE_NAME,
            "version": ENGINE_VERSION
        }
    }


def prioritize_assessment(assessment):
    result = copy.deepcopy(assessment)
    asset = result["asset"]

    for finding in result["findings"]:
        finding["priority"] = prioritize_finding(
            finding,
            asset
        )

    result["findings"].sort(
        key=lambda finding: (
            finding["priority"]["score"],
            SEVERITY_RANK[finding["baseline_severity"]],
            finding["finding_id"],
        ),
        reverse=True,
    )

    return result


def main():
    if len(sys.argv) != 3:
        raise SystemExit(
            "Usage: prioritize.py INPUT_ASSESSMENT OUTPUT_ASSESSMENT"
        )

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    assessment = json.loads(input_path.read_text())
    prioritized = prioritize_assessment(assessment)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(prioritized, indent=2) + "\n"
    )

    for finding in prioritized["findings"]:
        priority = finding["priority"]
        print(
            f"{finding['finding_id']}: "
            f"score={priority['score']} "
            f"severity={finding['baseline_severity']}"
        )

    print(
        f"PRIORITIZED ASSESSMENT CREATED: {output_path}"
    )


if __name__ == "__main__":
    main()
