# OSS Compliance Scanner - 빠른 시작 가이드

## 🚀 빠른 실행

### 1. CLI로 프로젝트 스캔

```bash
# 기본 스캔
./start-cli.sh test-projects/nodejs-app

# 상세 출력으로 스캔
./start-cli.sh -v test-projects/cpp-app

# 특정 모듈만 스캔
./start-cli.sh -m backend test-projects/multi-module

# 도움말 보기
./start-cli.sh --help
```

### 2. 웹 서버 실행

```bash
# 기본 포트(8080)로 서버 시작
./start-server.sh

# 데몬 모드로 백그라운드 실행
./start-server.sh -d

# 다른 포트로 실행
./start-server.sh -p 9090

# 서버 상태 확인
./start-server.sh --status

# 서버 중지
./start-server.sh --stop

# 도움말 보기
./start-server.sh --help
```

## 📋 스크립트 기능

### start-cli.sh 기능

| 옵션 | 설명 | 예제 |
|------|------|------|
| `-h, --help` | 도움말 표시 | `./start-cli.sh --help` |
| `-v, --verbose` | 상세 출력 | `./start-cli.sh -v /path/to/repo` |
| `-m, --module` | 특정 모듈 스캔 | `./start-cli.sh -m frontend /path/to/repo` |
| `-o, --output` | 출력 형식 지정 | `./start-cli.sh -o json /path/to/repo` |
| `-n, --notify` | Slack 알림 활성화 | `./start-cli.sh -n /path/to/repo` |
| `--skip-sbom` | SBOM 생성 건너뛰기 | `./start-cli.sh --skip-sbom /path/to/repo` |
| `--skip-vuln` | 취약점 스캔 건너뛰기 | `./start-cli.sh --skip-vuln /path/to/repo` |
| `--force` | 강제 재스캔 | `./start-cli.sh --force /path/to/repo` |

### start-server.sh 기능

| 옵션 | 설명 | 예제 |
|------|------|------|
| `-h, --help` | 도움말 표시 | `./start-server.sh --help` |
| `-p, --port` | 서버 포트 설정 | `./start-server.sh -p 9090` |
| `-v, --verbose` | 상세 출력 | `./start-server.sh -v` |
| `-d, --daemon` | 데몬 모드 실행 | `./start-server.sh -d` |
| `--dev` | 개발 모드 (자동 재시작) | `./start-server.sh --dev` |
| `--stop` | 서버 중지 | `./start-server.sh --stop` |
| `--status` | 서버 상태 확인 | `./start-server.sh --status` |
| `--logs` | 서버 로그 확인 | `./start-server.sh --logs` |

## 🧪 테스트 프로젝트

프로젝트에 포함된 테스트 프로젝트들:

| 프로젝트 | 언어 | 설명 |
|----------|------|------|
| `test-projects/nodejs-app` | Node.js | npm 패키지, 취약점 포함 |
| `test-projects/go-app` | Go | go mod, JWT 라이브러리 |
| `test-projects/python-app` | Python | pip 패키지, Flask 등 |
| `test-projects/java-app` | Java | Maven, Log4j 등 |
| `test-projects/cpp-app` | C++ | CMake, Conan, vcpkg |
| `test-projects/multi-module` | 다중언어 | 프론트엔드, 백엔드, 데이터 서비스 |

## 📊 사용 예제

### 1. 전체 워크플로우

```bash
# 1. 프로젝트 스캔
./start-cli.sh test-projects/multi-module

# 2. 웹 서버 시작 (데몬 모드)
./start-server.sh -d

# 3. 웹 브라우저에서 결과 확인
open http://localhost:8080

# 4. 특정 모듈만 재스캔
./start-cli.sh -m backend test-projects/multi-module

# 5. 서버 상태 확인
./start-server.sh --status

# 6. 서버 중지
./start-server.sh --stop
```

### 2. 개발 워크플로우

```bash
# 개발 모드로 서버 시작 (파일 변경 시 자동 재시작)
./start-server.sh --dev

# 다른 터미널에서 스캔 실행
./start-cli.sh -v test-projects/cpp-app

# 로그 확인
./start-server.sh --logs
```

### 3. 프로덕션 워크플로우

```bash
# 백그라운드에서 서버 실행
./start-server.sh -d -p 8080

# 정기적인 스캔 (cron 등에서 사용)
./start-cli.sh --notify /path/to/production/repo

# 서버 상태 모니터링
./start-server.sh --status
```

## 🔧 자동 초기화 기능

스크립트들은 다음을 자동으로 확인하고 설정합니다:

### CLI 스크립트 (start-cli.sh)
- ✅ 바이너리 존재 및 실행 권한
- ✅ 필수 도구 설치 (syft, grype)
- ✅ 데이터베이스 초기화
- ✅ 설정 파일 생성
- ✅ 저장소 경로 검증

### 서버 스크립트 (start-server.sh)
- ✅ 바이너리 존재 및 실행 권한
- ✅ 데이터베이스 초기화
- ✅ 설정 파일 생성
- ✅ 포트 충돌 검사 및 해결
- ✅ 프로세스 관리 (시작/중지/상태확인)

## 🚨 문제 해결

### 일반적인 문제들

#### 1. 바이너리가 없는 경우
```bash
# 프로젝트 빌드
go build -o oss-compliance-scanner .
```

#### 2. 필수 도구가 설치되지 않은 경우
```bash
# macOS
brew install anchore/syft/syft
brew install anchore/grype/grype

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

#### 3. 포트가 이미 사용 중인 경우
```bash
# 다른 포트 사용
./start-server.sh -p 9090

# 또는 기존 프로세스 확인 후 종료
lsof -i :8080
kill -9 <PID>
```

#### 4. 데이터베이스 문제
```bash
# 데이터베이스 재초기화
rm db/oss_scan.db
sqlite3 db/oss_scan.db < db/schema.sql
```

### 로그 확인

```bash
# 서버 로그 확인
./start-server.sh --logs

# 또는 직접 파일 확인
tail -f logs/server.log
```

## 🔗 추가 리소스

- **전체 문서**: [README.md](README.md)
- **데이터베이스 스키마**: [db/schema.sql](db/schema.sql)
- **설정 예제**: [.oss-compliance-scanner.yaml.sample](.oss-compliance-scanner.yaml.sample)
- **테스트 스크립트**: [test-projects/run-tests.sh](test-projects/run-tests.sh)

---

**💡 팁**: 스크립트는 모든 필수 구성 요소를 자동으로 확인하고 설정하므로, 처음 사용할 때도 별도의 설정 없이 바로 실행할 수 있습니다! 