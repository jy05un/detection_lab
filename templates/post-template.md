---
title: "<Actor> <Technique> — from <source> to detection"
date: YYYY-MM-DD
actor_cn: "<中文名>"
actor_western: "<Western/MITRE name>"
vendor_id: "<APT-Q-XX / APT-C-XX>"
attack_techniques: ["T1218.004", "T1137.001"]
platforms: ["Windows"]
sources:
  - "<primary CN report URL>"
  - "<Western cross-reference URL>"
---

## TL;DR

- **Who:** <actor> (<CN name> / <Western name>, <vendor id>)
- **What's new:** <one line>
- **Why it matters:** <one line>
- **Detectable?** <yes/partial + which telemetry>

## 1. Background (CTI layer)

Group overview, CN ↔ Western naming, what's new in this campaign, target
industries/regions. Link primary source(s).

## 2. TTP breakdown (ATT&CK)

| # | Technique | ATT&CK | Observable |
|---|-----------|--------|------------|
| 1 |           |        |            |

## 3. Detection engineering (the spine)

**Telemetry:** which log sources / sourcetypes surface this.

**Sigma:** see `sigma/<rule>.yml`.

**Splunk SPL:** see `splunk/<search>.spl`.

**Tuning / FPs:** known benign triggers, allowlist strategy, thresholds.

**Coverage gaps:** what this does *not* catch.

## 4. Cloud angle (optional)

Deployment/onboarding notes for Tencent Cloud / AWS China / O365 environments,
CSPM or log-source considerations. Skip if not applicable.

## 5. IOCs

Summary table here; full IOC list and rules in the folder. Pull from the cited
report — do not invent.

## 6. Limitations

Built from public sources; validate and tune in your own environment.
