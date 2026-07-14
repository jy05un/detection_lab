---
title: "BITTER (蔓灵花 / APT-Q-37) — on-host C# compile + InstallUtil LOLBin chain"
date: 2026-07-04
actor_cn: "蔓灵花"
actor_western: "BITTER"
vendor_id: "APT-Q-37 (QiAnXin) / APT-C-08 (360) / T-APT-17"
attack_techniques: ["T1218.004", "T1137.001", "T1059.005", "T1027.004", "T1053.005"]
platforms: ["Windows"]
sources:
  - "QiAnXin RedDrip: 蔓灵花（APT-Q-37）以多样化手段投递新型后门组件 (2025-10-20)"
---

## TL;DR

- **Who:** 蔓灵花 / BITTER (APT-Q-37 / APT-C-08 / T-APT-17). South Asia-nexus, active since Nov 2013; targets gov/military/power/nuclear in Pakistan & China.
- **What's new:** two delivery modes, one shared C# backdoor (fetches arbitrary EXE from C2). Backdoor is compiled on-host (no stable hash) and executed via signed MS binaries.
- **Detectable?** Yes — process lineage (csc/InstallUtil) and non-Word Normal.dotm writes.

## 1. Background

BITTER was first named by Forcepoint (2016) from a `BITTER` string in its RAT traffic; QiAnXin named it 蔓灵花 the same year. Long-running espionage actor. Historically CHM + macro-Office spearphishing; this campaign adds on-host compilation and a WinRAR-traversal template overwrite.

## 2. TTP breakdown (ATT&CK)

| # | Technique | ATT&CK | Observable |
|---|-----------|--------|------------|
| 1 | On-host C# compilation | T1059.005 / T1027.004 | `csc.exe` spawned by Office/script host; output DLL in `C:\ProgramData\USOShared\` |
| 2 | InstallUtil proxy execution | T1218.004 | `InstallUtil.exe` with `/logfile= /LogToConsole=false /U` |
| 3 | Startup + scheduled task persistence | T1053.005 | `kefe.bat` in Startup → task beaconing to C2 |
| 4 | Office template persistence | T1137.001 | write to `...\Templates\Normal.dotm` by non-Word process |

**Delivery:**
- **Mode 1:** `Nominated Officials for the Conference.xlam` → macro decoy msgbox → base64 C# → `C:\programdata\cayote.log` → `csc.exe` → `C:\Programdata\USOShared\vlcplayer.dll` → `InstallUtil.exe`. Persistence: `kefe.bat` (Startup) → scheduled task → `keeferbeautytrends[.]com/d6Z2.php?rz=`.
- **Mode 2:** WinRAR path traversal (suspected CVE-2025-8088; traverses on 7.11, not 7.12 → likely earlier bug) → RAR carries `Document.docx` + `Normal.dotm` (two-level parent traversal) → overwrites template library `Normal.dotm` → opening the docx runs the template macro → payload from `koliwooclients[.]com`.

## 3. Detection engineering

**Telemetry:** process creation (Sysmon EID 1 / EDR) for #1–2; file events (EID 11 / EDR) for #4.

- `sigma/installutil-suspicious-flags.yml` — T1218.004
- `sigma/csc-office-parent.yml` — T1027.004 / T1059.005
- `sigma/normal-dotm-write.yml` — T1137.001
- `splunk/installutil-lolbin.spl` — Splunk translation

**Tuning / FPs:** scope `csc.exe` to non-dev hosts + suspicious parents; InstallUtil high-confidence only with the `/LogToConsole=false /U` + ProgramData DLL combo; allowlist backup/sync agents for Normal.dotm by Image, not path.

**Coverage gaps:** does not catch `.xlam` delivery or the WinRAR extraction — pair with mail/attachment controls and WinRAR patching.

## 4. Cloud angle

If the `.xlam` arrives by email, add an O365/Exchange message-trace correlation on the lure filename/sender. Otherwise endpoint-only.

## 5. IOCs

| Type | Value | Note |
|------|-------|------|
| Domain | `keeferbeautytrends[.]com` | Mode 1 scheduled-task C2 |
| Domain | `koliwooclients[.]com` | Mode 2 Normal.dotm C2 |
| Filename | `Nominated Officials for the Conference.xlam` | Mode 1 lure |
| Path | `C:\programdata\cayote.log` | dropped C# source |
| Path | `C:\Programdata\USOShared\vlcplayer.dll` | compiled backdoor |
| File | `kefe.bat` | Startup persistence |

> Add SHA256 hashes from the report's IOC appendix — do not invent values.

## 6. Limitations

Public sources only; technique-based logic. Validate and tune before use.
