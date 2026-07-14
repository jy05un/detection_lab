#!/usr/bin/env python3
"""Minimal, dependency-light Sigma validator.

Checks every detections/**/sigma/*.yml for:
  - valid YAML
  - required Sigma fields (title, id, logsource, detection, condition, level)
  - a well-formed UUID in `id`
  - at least one attack.* tag
Exits non-zero on any failure so CI goes red.
"""
import glob
import sys
import uuid

import yaml

REQUIRED = ["title", "id", "logsource", "detection", "level"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}

def check(path):
    errors = []
    with open(path, encoding="utf-8") as fh:
        try:
            rule = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            return [f"invalid YAML: {exc}"]

    if not isinstance(rule, dict):
        return ["top-level document is not a mapping"]

    for field in REQUIRED:
        if field not in rule:
            errors.append(f"missing required field: {field}")

    if "id" in rule:
        try:
            uuid.UUID(str(rule["id"]))
        except ValueError:
            errors.append(f"id is not a valid UUID: {rule['id']!r}")

    det = rule.get("detection")
    if not isinstance(det, dict) or "condition" not in det:
        errors.append("detection block missing a 'condition'")

    if rule.get("level") not in VALID_LEVELS:
        errors.append(f"level must be one of {sorted(VALID_LEVELS)}")

    tags = rule.get("tags", []) or []
    if not any(str(t).startswith("attack.") for t in tags):
        errors.append("no attack.* tag found")

    return errors


def main():
    files = sorted(glob.glob("detections/**/sigma/*.yml", recursive=True))
    if not files:
        print("no Sigma rules found")
        return 0

    failed = False
    for path in files:
        errs = check(path)
        if errs:
            failed = True
            print(f"FAIL {path}")
            for e in errs:
                print(f"     - {e}")
        else:
            print(f"OK   {path}")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
