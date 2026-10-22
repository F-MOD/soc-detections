#!/usr/bin/env python3
"""
Validates the Sigma rules in this repository:
  - Valid YAML
  - Required fields present
  - Unique id in UUID format
  - Valid level and status
  - At least one MITRE ATT&CK technique tag (attack.tXXXX)
  - A detection 'condition' exists
  - Every rule has a playbook in /playbooks with the same name

Usage:  python scripts/validate_rules.py
Exits with code 1 if any rule fails, so CI marks the check as failed.
"""
import re
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
PLAYBOOKS_DIR = ROOT / "playbooks"

REQUIRED = ["title", "id", "status", "description", "author", "date",
            "tags", "logsource", "detection", "falsepositives", "level"]
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"experimental", "test", "stable", "deprecated", "unsupported"}
ATTACK_TECHNIQUE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def check_rule(path: Path, seen_ids: dict) -> list[str]:
    errors = []

    # 1. The file must be valid YAML
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return [f"Invalid YAML: {e}"]
    if not isinstance(rule, dict):
        return ["File does not contain a valid rule"]

    # 2. Required fields
    for field in REQUIRED:
        if field not in rule:
            errors.append(f"Missing required field '{field}'")

    # 3. id must be a UUID and unique across the repo
    rule_id = str(rule.get("id", ""))
    try:
        uuid.UUID(rule_id)
    except ValueError:
        errors.append(f"id '{rule_id}' is not a valid UUID")
    if rule_id in seen_ids:
        errors.append(f"Duplicate id, already used in {seen_ids[rule_id]}")
    seen_ids[rule_id] = path.name

    # 4. Allowed values for level and status
    if rule.get("level") not in VALID_LEVELS:
        errors.append(f"Invalid level '{rule.get('level')}'")
    if rule.get("status") not in VALID_STATUS:
        errors.append(f"Invalid status '{rule.get('status')}'")

    # 5. At least one MITRE ATT&CK technique
    tags = rule.get("tags") or []
    if not any(ATTACK_TECHNIQUE.match(str(t)) for t in tags):
        errors.append("No MITRE ATT&CK technique tag (attack.tXXXX)")

    # 6. Detection must have a condition
    if "condition" not in (rule.get("detection") or {}):
        errors.append("detection block has no 'condition'")

    # 7. Matching playbook
    playbook = PLAYBOOKS_DIR / f"{path.stem}.md"
    if not playbook.exists():
        errors.append(f"Missing playbook: playbooks/{playbook.name}")

    return errors


def main() -> int:
    rules = sorted(RULES_DIR.rglob("*.yml"))
    if not rules:
        print("No rules found in /rules")
        return 1

    seen_ids: dict = {}
    failed = 0
    for path in rules:
        errors = check_rule(path, seen_ids)
        rel = path.relative_to(ROOT)
        if errors:
            failed += 1
            print(f"[FAIL] {rel}")
            for e in errors:
                print(f"       - {e}")
        else:
            print(f"[ OK ] {rel}")

    print(f"\n{len(rules) - failed}/{len(rules)} rules passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())