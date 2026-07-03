---
title: "BITTER (蔓灵花 / APT-Q-37) — csc.exe + InstallUtil.exe LOLBin chain"
date: 2026-07-04
actor_cn: "蔓灵花"
actor_western: "BITTER"
vendor_id: "APT-Q-37 (QiAnXin) / APT-C-08 (360)"
attack_techniques: ["T1218.004", "T1137.001", "T1059.005"]
platforms: ["Windows"]
sources:
  - "https://ti.qianxin.com/blog/category/事件追踪/  # replace with the exact article URL"
  - "https://attack.mitre.org/software/S0187/  # cross-reference"
---

## TL;DR

- **Who:** 蔓灵花 / BITTER (APT-Q-37 / APT-C-08), South Asia-nexus.
- **What's new:** C# backdoor delivered two ways — (a) VBA macro in an `.xlam`
  drops C# source, compiled on-host with `.NET csc.exe` then run via
  `InstallUtil.exe`; (b) a WinRAR path-traversal replaces the user's
  `Normal.dotm` template for persistence.
- **Why it matters:** the whole chain is living-off-the-land — signed Microsoft
  binaries, no dropped PE to scan.
- **Detectable?** Yes — process-lineage and template-write telemetry catch it
  cleanly.

## 1. Background (CTI layer)

> Fill from the cited QiAnXin report. Include: BITTER overview, CN↔Western
> naming (see ../../naming-map.md), what changed this campaign, targets.

## 2. TTP breakdown (ATT&CK)

| # | Technique | ATT&CK | Observable |
|---|-----------|--------|------------|
| 1 | On-host C# compilation | T1059.005 / T1027.004 | `csc.exe` spawned by Office/script host |
| 2 | InstallUtil proxy execution | T1218.004 | `InstallUtil.exe` with `/logfile= /LogToConsole=false /U` |
| 3 | Office template persistence | T1137.001 | write to `...\Templates\Normal.dotm` by non-Word process |

## 3. Detection engineering (the spine)

**Telemetry:** process creation (Sysmon EID 1 or EDR) for #1–2; file creation
(Sysmon EID 11 / EDR file events) for #3.

**Sigma:** `sigma/installutil-suspicious-flags.yml`,
`sigma/csc-office-parent.yml`, `sigma/normal-dotm-write.yml`.

**Splunk SPL:** `splunk/installutil-lolbin.spl`.

**Tuning / FPs:** `csc.exe` fires for legit .NET build/dev activity — scope by
parent (Office/`wscript`/`mshta`) and by non-developer hosts. `InstallUtil` is
used by some legit installers — the `/LogToConsole=false /U` combination is the
high-signal part. `Normal.dotm` is written by Word itself constantly — the
signal is a **non-Word** writer (archive tools, scripts).

**Coverage gaps:** does not catch the initial `.xlam` delivery or the WinRAR
CVE exploitation itself — pair with mail/attachment and vuln-management controls.

## 4. Cloud angle (optional)

If the `.xlam` arrives via email, add an O365/Exchange message-trace correlation
for the lure. Otherwise endpoint-only; skip.

## 5. IOCs

> Populate from the report — hashes, C2 domains/IPs, filenames. Do **not**
> invent values.

| Type | Value | Note |
|------|-------|------|
| SHA256 | `<from report>` | C# loader |
| Domain | `<from report>` | C2 |

## 6. Limitations

Built from public sources; technique-based logic. Validate and tune before use.
