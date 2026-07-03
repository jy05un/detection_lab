# APT Naming Map — Chinese ↔ Western

Chinese vendors use their own actor names and IDs (奇安信 `APT-Q-*` / `APT-C-*` /
`UTG-Q-*`, 360 `APT-C-*`). Mapping these to the Western/MITRE names most English
readers know is the single most useful cross-reference this repo provides.

**Caveat:** attribution and clustering differ between vendors. Chinese and
Western vendors sometimes split or merge the same activity differently. Treat
this as a *bridge*, not ground truth — always cite the specific report.

| Chinese name | 奇安信 (QiAnXin) | 360 | Western / MITRE | Suspected origin | Notes |
|--------------|-----------------|-----|-----------------|------------------|-------|
| 海莲花 | APT-Q-31 | APT-C-00 | OceanLotus / APT32 | Vietnam-nexus | Heavy East/Southeast Asia targeting |
| 蔓灵花 | APT-Q-37 | APT-C-08 | BITTER | South Asia-nexus | CHM/LNK lures, C# backdoors, InstallUtil |
| 摩诃草 | APT-Q-36 | APT-C-09 | Patchwork / Hangover | South Asia-nexus | Shares resources w/ Donot |
| 肚脑虫 | — | APT-C-35 | Donot / APT-Q-38 | South Asia-nexus | PDF/document lures |
| 响尾蛇 | — | APT-C-17 | SideWinder | South Asia-nexus | Rapid infra rotation |
| 毒云藤 | APT-Q-20 | APT-C-01 | Poison Vine / APT-C-01 | Cross-strait | Long-running espionage |
| 伪猎者 | APT-Q-12 | — | (vendor-specific) | — | Email-client exploitation (Foxmail RCE) |
| 白象 | (umbrella) | (umbrella) | umbrella term for South Asian APTs | South Asia | Not a single group — verify per report |
| — | APT-Q-1 | — | Lazarus | DPRK-nexus | Korea-relevant coverage |
| — | — | — | Kimsuky | DPRK-nexus | Korea-relevant coverage |

> Add a row whenever a writeup introduces a new actor. Link the row to the
> writeup so the map doubles as an index by actor.
