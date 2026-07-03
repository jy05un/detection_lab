# Detection Lab — Threat Intel → Detections

> Reproducible detection logic derived from open-source threat intelligence,
> with a focus on **Chinese-language primary sources** that are
> underrepresented in English-language detection content.

Each entry takes a real, publicly reported campaign and turns it into
something a defender can actually deploy: an intel summary, an ATT&CK mapping,
a vendor-neutral **Sigma** rule, a **Splunk SPL** translation, and honest
tuning / false-positive notes.

I read the Chinese-language reports (QiAnXin/奇安信 RedDrip, 360, Antiy, Tencent
Security, etc.), map the actor's Chinese name to its Western/MITRE name, and
publish the *detection* — not just a translation.

---

## Why this repo

- **Detection-first.** Every entry ships a detection artifact, not a news summary.
- **Source access.** Coverage of campaigns reported first (or only) in Chinese.
- **Naming bridge.** A maintained CN ↔ Western actor-name map (`naming-map.md`).
- **Reproducible.** Technique-based logic you can validate in your own lab.

---

## Structure

```
detection-lab/
├── README.md                 # this file
├── naming-map.md             # CN ↔ Western APT name mapping (signature asset)
├── templates/                # reusable skeletons
│   ├── post-template.md
│   ├── sigma-template.yml
│   └── splunk-template.spl
└── detections/
    └── YYYY-MM-DD-<actor>-<technique>/
        ├── README.md         # writeup: intel → ATT&CK → detection → tuning
        ├── sigma/
        │   └── <rule>.yml
        └── splunk/
            └── <search>.spl
```

## Index

| Date | Actor (CN / Western) | Technique | ATT&CK | Platform | Writeup |
|------|----------------------|-----------|--------|----------|---------|
| _(pending)_ | 蔓灵花 / BITTER (APT-Q-37) | InstallUtil + csc.exe LOLBin, Normal.dotm persistence | T1218.004, T1137.001 | Windows | [link](detections/) |

<!-- add a row per published detection; keep newest on top -->

---

## Disclaimer

Everything here is built **only from publicly available sources**. Nothing in
this repository is derived from any employer or client environment, telemetry,
or engagement. Detections are provided as-is for research and defensive use —
validate and tune in your own environment before relying on them. Actor
attribution reflects the cited public reporting and may differ across vendors.

## License

Suggested: MIT for code (Sigma/SPL) and CC BY 4.0 for writeups. Pick before
first push.
