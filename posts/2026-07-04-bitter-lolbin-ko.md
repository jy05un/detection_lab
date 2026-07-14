# 중국어 APT 리포트를 탐지로 옮기기 (1) — BITTER의 LOLBin 체인

> 치안신(Qianxin) 레드드립(RedDrip) 리포트로 본 BITTER. 피해자 PC의 정품 도구로 백도어를 직접 컴파일하는 수법과, 이걸 Sigma·Splunk로 잡는 법.

## 들어가며

치안신이나 360, 텐센트 같은 중국 보안 벤더들은 매주 1차 APT 분석을 꽤 많이 냅니다. 문제는 이게 언어 장벽에 막혀서 한국이나 영어권 탐지 실무자한테는 거의 안 넘어온다는 거죠. 그래서 이 시리즈에서는 그런 중국어 리포트를 읽고, 매번 바로 쓸 수 있는 탐지 로직(Sigma에서 Splunk까지)으로 옮겨보려고 합니다.

첫 회로 고른 건 작년 10월 치안신 레드드립 팀이 낸 BITTER 리포트예요. 공격 흐름이 LOLBin(정상 도구를 악용하는 기법) 탐지를 설명하기에 딱 좋은 사례라서요.

## BITTER는 누구인가

서구에선 BITTER, 중국에선 만링화라고 부르는 그룹입니다. 2016년에 Forcepoint가 이 조직 RAT 트래픽에서 `BITTER`라는 문자열을 보고 이름을 붙였고, 같은 해 치안신도 중국 내 공격을 잡아 만링화로 명명했어요. 추적번호는 벤더마다 다른데 정리하면 이렇습니다.

| 중국명 | 치안신 | 360 | 서구/MITRE |
|--------|--------|-----|-----------|
| 蔓灵花 | APT-Q-37 | APT-C-08 | BITTER (T-APT-17) |

남아시아 배경으로 추정되는 첩보형 APT고, 적어도 2013년 11월부터 활동해 왔습니다. 주 타깃은 파키스탄과 중국의 정부·군·전력·원자력 쪽이고 목적은 민감 자료 탈취예요. 원래는 매크로 심은 오피스 문서나 악성 CHM으로 스피어피싱하는 게 주특기였는데, 이번 캠페인에선 전달 방식을 좀 바꿔서 실험하는 티가 납니다.

## 이번 캠페인에서 달라진 점

치안신이 모은 샘플을 보면 감염 경로는 둘로 갈리는데 결국 똑같은 C# 백도어로 모입니다. 백도어 자체는 원격 서버에서 EXE 받아다 실행하는 평범한 물건이에요. 정작 눈여겨볼 건 백도어가 아니라 그게 떨어지는 방식입니다.

포인트는 두 가지예요. C# 페이로드를 피해자 PC에서 직접 컴파일하니까 고정된 파일 해시가 안 생기고(그래서 해시 차단이나 정적 AV가 잘 안 걸립니다), 실행이 전부 서명된 MS 정품 바이너리(csc.exe, InstallUtil.exe) 위에서 돌아갑니다. 전형적인 LOLBin이죠.

### Mode 1 — xlam → VBA → csc.exe → InstallUtil.exe

미끼는 `Nominated Officials for the Conference.xlam`이라는 엑셀 추가기능 파일입니다. 열면 매크로 켜라고 유도하고, 켜면 "파일 파싱 실패, 내용 손상됨" 비슷한 가짜 오류창을 띄워요. 그냥 눈속임이고 뒤에선 매크로가 돌아갑니다.

매크로가 하는 일은 이래요. base64로 인코딩된 C# 소스를 `C:\programdata\cayote.log`에 풀고, .NET 컴파일러 csc.exe로 `C:\Programdata\USOShared\vlcplayer.dll`을 빌드한 다음 InstallUtil.exe로 실행합니다. 지속화는 시작프로그램 폴더에 `kefe.bat`을 떨궈서 `keeferbeautytrends[.]com`으로 비컨하는 예약 작업을 거는 식이고요.

### Mode 2 — WinRAR 경로 탐색 → Normal.dotm 덮어쓰기

두 번째는 WinRAR 경로 탐색 취약점을 씁니다. 분석팀도 처음엔 CVE-2025-8088(7.13 미만 영향)인 줄 알았대요. 그런데 악성 RAR을 돌려보니 7.11에선 경로 탐색이 되고 7.12에선 안 돼서, 그보다 이전 버그로 결론 냈다고 합니다.

RAR 안에는 `Document.docx`랑, 경로에 상위 폴더 두 단계가 붙은 `Normal.dotm`이 같이 들어 있어요. 압축을 풀면 이 Normal.dotm이 사용자 워드 템플릿 폴더로 넘어가 전역 템플릿을 덮어씁니다. 그다음 피해자가 docx를 여는 순간 심어둔 템플릿 매크로가 실행되면서 페이로드를 받아오는데, 이쪽 C2는 `koliwooclients[.]com`이고 예전에 BITTER 인프라로 이미 공개됐던 도메인이에요.

## 왜 방어자가 신경 써야 하나

이 체인이 탐지 소재로 좋은 이유는, 흔히 믿고 쓰는 통제 두 개를 그냥 통과해버려서입니다. 우선 온호스트 컴파일이라 결과 DLL이 감염된 PC마다 달라져요. 해시 블록리스트는 물론이고 정적 AV도 상당 부분 그냥 지나갑니다. 게다가 csc.exe와 InstallUtil.exe는 윈도우랑 .NET에 기본으로 딸려오는 서명된 바이너리라 화이트리스트에 올라가 있는 경우가 많죠.

그러니 페이로드로 잡을 생각은 접고, 행위랑 프로세스 계보로 봐야 합니다.

## 탐지 엔지니어링

세 개를 조합하면 체인을 얼추 커버합니다. 전체 룰은 리포에 올려놨고 여기선 로직만 짚을게요.

### 1. InstallUtil 프록시 실행 (T1218.004)

InstallUtil.exe가 조용한 언인스톨 플래그 조합(`/logfile=`, `/LogToConsole=false`, `/U`)으로 뜨는 건 꽤 알려진 프록시 실행 패턴입니다. 이번 건은 여기에 하나 더 얹혀요. 로드되는 DLL이 `C:\ProgramData\USOShared\`에 있는데, 정상 인스톨러가 여기서 어셈블리 돌릴 일은 없거든요.

텔레메트리는 프로세스 생성(Sysmon EID 1이나 EDR)이면 됩니다.

### 2. 오피스·스크립트 호스트가 부모인 csc.exe (T1027.004 / T1059.005)

온호스트 C# 컴파일 자체는 개발자 PC에선 흔하고 정상입니다. 근데 부모 프로세스가 EXCEL.EXE, WINWORD.EXE, wscript.exe, mshta.exe 이런 거면 얘기가 다르죠. 이 부모-자식 조합이 신호입니다.

텔레메트리는 부모 이미지까지 찍히는 프로세스 생성 로그.

### 3. 워드가 아닌 프로세스가 건드린 Normal.dotm (T1137.001)

Normal.dotm은 워드가 수시로 다시 씁니다. 그래서 이 파일이 바뀌었다는 것만으론 의미가 없어요. 봐야 할 건 누가 썼느냐입니다. `...\Templates\Normal.dotm`을 WINWORD.EXE가 아닌 뭔가(압축 프로그램이나 스크립트 같은)가 건드렸다면 템플릿 매크로 지속화를 강하게 의심할 만합니다.

텔레메트리는 파일 생성 이벤트(Sysmon EID 11이나 EDR).

### Splunk 변환 (스케치)

```spl
index=<endpoint_index> sourcetype=<sysmon_or_edr>
    (process_name="InstallUtil.exe" OR OriginalFileName="InstallUtil.exe")
    CommandLine="*logfile=*" CommandLine="*LogToConsole=false*" CommandLine="*/U*"
| stats min(_time) as firstTime max(_time) as lastTime
        values(CommandLine) as CommandLine
        by host, user, parent_process_name, process_name
```

2번 탐지를 append 서브서치로 붙여도 되고, 셋을 각각 상관검색으로 돌린 다음 RBA(위험 기반 알림)로 묶어 한 호스트가 두 개 이상 터지면 등급을 올리는 식으로 가도 좋습니다.

### 오탐 튜닝

돌려보면 걸리는 게 좀 있어요. csc.exe는 실제 .NET 빌드에서 계속 뜨니까 비개발 호스트에다 위에 적은 의심 부모로 범위를 좁혀야 합니다. 그냥 csc.exe 다 잡으면 알림에 파묻혀요. InstallUtil도 정상 인스톨러가 가끔 쓰는데, `/LogToConsole=false /U` 조합에 ProgramData DLL 경로까지 겹칠 때가 진짜 고신뢰 구간입니다. Normal.dotm은 워드 말고 백업이나 동기화 에이전트가 건드리기도 하니, 경로가 아니라 쓴 주체(Image) 기준으로 화이트리스트를 잡는 게 맞습니다.

### 커버리지 갭

솔직히 이 세 개로는 초기 xlam 전달이나 WinRAR 압축 해제 자체는 못 잡습니다. 그건 메일·첨부 통제랑 WinRAR 패치 관리(취약 버전 올리기)로 메꿔야 해요. 이 탐지들이 걸리는 지점은 전달이 아니라 실행·지속화 단계입니다.

## IOC

| 유형 | 값 | 비고 |
|------|-----|------|
| 도메인 | `keeferbeautytrends[.]com` | Mode 1 예약 작업 C2 (`/d6Z2.php?rz=`) |
| 도메인 | `koliwooclients[.]com` | Mode 2 Normal.dotm C2 |
| 파일명 | `Nominated Officials for the Conference.xlam` | Mode 1 미끼 |
| 경로 | `C:\programdata\cayote.log` | 드롭된 C# 소스 |
| 경로 | `C:\Programdata\USOShared\vlcplayer.dll` | 컴파일된 백도어 |
| 파일 | `kefe.bat` (시작프로그램) | 지속화 |

*(샘플 SHA256 해시는 원문 리포트 IOC 부록에서 그대로 옮겨 넣으세요. 검증 못 한 값은 지어내지 않았습니다.)*

## 마무리

BITTER가 노리는 건 늘 비슷합니다. 정부나 기간시설 상대로 조용히 정보 빼가는 거죠. 근데 이번 온호스트 컴파일 + 프록시 실행 체인은 해시나 시그니처 기반 통제가 얼마나 금방 낡는지를 다시 보여줍니다. 결국 오래 버티는 건 행위·계보 기반 탐지예요.

이 글에서 다룬 룰(Sigma + Splunk)은 리포에 있습니다: github.com/jy05un/detection_lab

*출처: 치안신 레드드립팀 "BITTER(APT-Q-37) 신종 백도어 다중 전달 수법" 리포트, 2025-10-20.*

---

*이 글은 공개 소스만으로 작성했고, 고용주나 고객사 데이터는 하나도 들어가지 않았습니다. 탐지는 있는 그대로 제공하니 각자 환경에서 검증·튜닝하고 쓰세요. Attribution은 인용한 리포트를 따릅니다.*
