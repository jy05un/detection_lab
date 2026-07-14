# BITTER's LOLBin Playbook: Turning a Chinese-Language APT Report into Sigma & Splunk Detections

*How the South Asian APT known in China as 蔓灵花 (BITTER / APT-Q-37) compiles its C# backdoor on the victim's own machine, and how to catch it.*

## The series

This is the first in a series where I read threat-intel reporting that shows up first, or only, in Chinese, and turn it into detections you can actually deploy. Chinese vendors put out a lot of primary-source APT analysis every week, and most of it never crosses the language barrier into English detection content. The plan each post is the same: one campaign, the actor's Chinese name mapped to the one you already know, the TTPs against ATT&CK, then a Sigma rule and a Splunk translation with real tuning notes.

For the debut I went with a late-2025 QiAnXin (奇安信) RedDrip report on BITTER, mostly because the technique chain is about as clean a teaching case for living-off-the-land detection as you'll find.

## Who is BITTER?

You probably know this group as BITTER. Forcepoint named it in 2016 after spotting the string `BITTER` in its RAT traffic. In Chinese reporting it's 蔓灵花, and the tracking IDs differ by vendor, so here's the map:

| Chinese | QiAnXin | 360 | Western / MITRE |
|---------|---------|-----|-----------------|
| 蔓灵花 | APT-Q-37 | APT-C-08 | BITTER (T-APT-17) |

It's a South Asia-nexus espionage actor, active since at least November 2013, mostly going after government, military, power, and nuclear targets in Pakistan and China. For years its signature was spearphishing with macro-laden Office docs and malicious CHM files. This campaign is the group trying something newer.

## What changed this time

QiAnXin collected samples that split into two delivery paths but land the same C# backdoor, which just pulls an arbitrary EXE from a remote server. The backdoor itself is unremarkable. What's worth writing up is how it gets there.

Two things stand out. The C# payload is compiled on the victim's own machine, so there's no stable hash to blocklist. And the whole chain runs on signed Microsoft binaries, csc.exe and InstallUtil.exe. Textbook LOLBin.

### Mode 1: xlam → VBA → csc.exe → InstallUtil.exe

The lure is an Excel add-in, `Nominated Officials for the Conference.xlam`. Open it, it asks you to enable macros, then pops a decoy message box claiming the file is corrupted and failed to parse. That's just cover while the macro runs.

Underneath, the VBA macro base64-decodes a C# source file to `C:\programdata\cayote.log`, calls csc.exe to compile it into `C:\Programdata\USOShared\vlcplayer.dll`, and runs the result through InstallUtil.exe. For persistence it drops `kefe.bat` into the Startup folder, which registers a scheduled task that beacons to `hxxps://www.keeferbeautytrends[.]com/d6Z2.php?rz=`.

### Mode 2: WinRAR path traversal → Normal.dotm overwrite

The second path abuses a WinRAR path-traversal bug. The analysts first suspected CVE-2025-8088, which affects WinRAR below 7.13, but the malicious archive traverses on 7.11 and not on 7.12, which points to an earlier bug instead.

The RAR carries two files: a `Document.docx` and a `Normal.dotm` whose path has two parent-directory hops tacked on. Extracting it drops that Normal.dotm into the user's Word template library and overwrites the global template. The next time the victim opens the docx, the weaponized template macro fires and grabs the payload, this time from `koliwooclients[.]com`, a domain already burned as BITTER infrastructure.

## Why this is worth catching

The chain is a good detection target precisely because it walks past the controls people lean on. On-host compilation means the resulting DLL is different on every victim, so hash blocklists and a lot of static AV just miss it. And csc.exe and InstallUtil.exe ship with Windows and .NET, so they tend to sit on allowlists.

So you don't chase the payload. You watch behavior and process lineage.

## Detection engineering

Three detections cover the chain between them. Full rules are in the repo; here's the logic.

### 1. InstallUtil proxy execution (T1218.004)

InstallUtil.exe run with the quiet-uninstall flag combo (`/logfile=`, `/LogToConsole=false`, `/U`) is a well-worn proxy-execution pattern. This case adds a tell: the DLL it loads lives in `C:\ProgramData\USOShared\`, and no legitimate installer is running assemblies out of there.

Telemetry: process creation (Sysmon EID 1 / EDR).

### 2. csc.exe with an Office or script-host parent (T1027.004 / T1059.005)

On-host C# compilation is normal on a developer box. It's not normal when the parent is EXCEL.EXE, WINWORD.EXE, wscript.exe, or mshta.exe. That pairing is the signal.

Telemetry: process creation with parent image.

### 3. Normal.dotm written by a non-Word process (T1137.001)

Word rewrites Normal.dotm all the time, so the file changing tells you nothing. Who changed it is the point. A write to `...\Templates\Normal.dotm` by anything other than WINWORD.EXE, say an archiver or a script, is a strong signal for template-macro persistence.

Telemetry: file-creation events (Sysmon EID 11 / EDR).

### Splunk translation (sketch)

```spl
index=<endpoint_index> sourcetype=<sysmon_or_edr>
    (process_name="InstallUtil.exe" OR OriginalFileName="InstallUtil.exe")
    CommandLine="*logfile=*" CommandLine="*LogToConsole=false*" CommandLine="*/U*"
| stats min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as CommandLine
        by host, user, parent_process_name, process_name
```

Append detection #2 as a subsearch, or run all three as separate correlation searches and tie them together with risk-based alerting so a host that trips two of them escalates.

### Tuning and false positives

When you run these you'll get noise, so a few notes. csc.exe fires on real .NET builds, so scope it to non-developer hosts and the suspicious parents above; a blanket csc.exe rule will bury you. InstallUtil shows up in some legit installers too, but the `/LogToConsole=false /U` combo plus a ProgramData DLL path is the high-confidence corner. Normal.dotm gets written by Word and by some backup and sync agents, so allowlist those by the writing process (Image), not by the path.

### Coverage gaps

None of these catch the initial xlam delivery or the WinRAR extraction. That's on mail and attachment controls and on WinRAR patching, so get past the vulnerable builds. These detections fire at execution and persistence, not at delivery.

## IOCs

| Type | Value | Note |
|------|-------|------|
| Domain | `keeferbeautytrends[.]com` | Mode 1 scheduled-task C2 (`/d6Z2.php?rz=`) |
| Domain | `koliwooclients[.]com` | Mode 2 Normal.dotm C2 |
| Filename | `Nominated Officials for the Conference.xlam` | Mode 1 lure |
| File path | `C:\programdata\cayote.log` | dropped C# source |
| File path | `C:\Programdata\USOShared\vlcplayer.dll` | compiled backdoor |
| File | `kefe.bat` (Startup) | persistence |

*(Grab the sample SHA256s from the report's IOC appendix. I'm not reproducing hashes I couldn't verify directly.)*

## Wrapping up

BITTER's goal is the usual one, quiet espionage against government and critical-infrastructure targets. But the compile-on-host, proxy-execute chain is a good reminder that hash- and signature-based controls go stale fast. Behavioral, lineage-based detection is what holds up.

Rules for this writeup (Sigma + Splunk) are in the repo: github.com/jy05un/detection_lab

*Source: QiAnXin Threat Intelligence Center (RedDrip Team), report on BITTER (APT-Q-37) multi-vector backdoor delivery, 2025-10-20.*

---

*Everything here is built from public sources only, with no employer or client data. Detections are provided as-is, so validate and tune in your own environment. Attribution follows the cited reporting.*
