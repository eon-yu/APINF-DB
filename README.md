# OSS Compliance Scanner

> Syft, CycloneDX SBOM, 그리고 Dependency-Track을 활용한 멀티-모듈 소프트웨어 구성 분석 자동화 도구

---

## 📖 프로젝트 개요

본 프로젝트는 **Syft**(Anchore)와 **CycloneDX** 생태계의 다양한 툴을 이용해 애플리케이션(소스·바이너리·컨테이너 이미지 등)의 SBOM(Software Bill Of Materials)을 자동으로 생성하고, 이를 **Dependency-Track**에 업로드하여 시각화·취약점 분석·정책 관리까지 한 번에 수행할 수 있도록 돕는 CLI 스캐너입니다.

* 멀티 모듈/다중 패키지 매니저 프로젝트에서도 동작하도록 설계되었습니다.
* SBOM 스키마는 CycloneDX v1.5 JSON을 사용합니다.
* Go 로 작성된 경량 CLI 로 로컬·CI 어디서나 빠르게 실행할 수 있습니다.

## 🏗️ 주요 구성 요소

| 구성 요소 | 용도 |
|-----------|------|
| [Syft](https://github.com/anchore/syft) | 파일 시스템·컨테이너 이미지·디렉터리 스캔 후 SBOM 생성 |
| [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli) | SBOM 변환·검증·정렬 |
| [cdxgen](https://github.com/CycloneDX/cdxgen) | C/C++, Dockerfile 등 Syft가 지원하지 않는 대상의 SBOM 생성 |
| [Dependency-Track](https://dependencytrack.org/) | SBOM 저장·시각화·취약점 상관분석 |
| Go(⚙️) 스캐너 코드 | 멀티 모듈 순회, SBOM 패치 및 D-Track 업로드 로직 |

## ⚙️ 사전 준비 사항

### 1. 필수 프로그램 설치

macOS(Homebrew 기준):

```bash
brew install go  # Go >= 1.23
brew install syft
brew install cyclonedx/cyclonedx/cyclonedx-cli
npm install -g @cyclonedx/cdxgen  # 또는 npx 사용 가능
```

Linux(Ubuntu 예시):

```bash
sudo snap install go --channel=1.23/stable --classic  # 또는 패키지 매니저 사용
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-linux-x64 -o /usr/local/bin/cyclonedx && chmod +x /usr/local/bin/cyclonedx
npm install -g @cyclonedx/cdxgen
```

### 2. Dependency-Track 구동

프로젝트 루트에서 다음 명령으로 API 서버·프론트엔드·PostgreSQL 을 실행합니다.

```bash
docker compose up -d
```

첫 구동 시 데이터베이스 초기화로 **수 분** 정도 소요될 수 있습니다.

#### API Key 발급

1. http://localhost:8080 접속 → 기본 관리자(admin / admin) 로그인
2. Administration → API Keys → `+` 클릭 후 **Upload SBOM** 권한을 가진 Key 생성
3. 발급된 Key 를 `.env` 파일에 저장 (예시는 아래 "환경 변수" 참고)

> 보안을 위해 실제 운영 시에는 관리자 비밀번호 및 API Key 를 즉시 변경하세요.

### 3. 환경 변수 설정

루트에 `.env` 파일을 생성하고 다음 값을 입력합니다.

```ini
# Dependency-Track API Key
API_KEY=<발급받은 값>
```

## 🚀 사용 방법

### 1. CLI 실행

```bash
# 예시: /path/to/project 전체를 스캔하여 iq2_square 라는 부모 프로젝트로 업로드

go run . -root /path/to/project -parent iq2_square -parent-version 1.0.0
```

인자 설명:

| 옵션 | 설명 | 기본값 |
|-------|------|---------|
| `-root` | SBOM 생성을 시작할 루트 디렉터리 | `/Users/…`(소스 상 default) |
| `-parent` | Dependency-Track 내 최상위 프로젝트 이름 | (필수) |
| `-parent-version` | 최상위 프로젝트 버전 | `latest` |

### 2. 스캔·업로드 흐름

1. 루트 디렉터리 이하를 **재귀 탐색**하며 `go.mod`, `package-lock.json`, `Dockerfile` 등 패키지 관리 파일을 발견
2. Syft 또는 cdxgen 으로 SBOM(⚙️
   CycloneDX v1.5 JSON) 생성
3. SBOM `metadata.component.name` 필드에 모듈 이름을 주입해 식별성 확보
4. cyclonedx-cli 로 포맷 변환/정렬 후 base64 인코딩
5. Dependency-Track API(`PUT /api/v1/bom`) 호출하여 업로드
6. 업로드 완료 시 콘솔에 ✅ 로그 출력, D-Track UI에서 실시간 확인 가능

## 🧩 디렉터리 구조

```
├── main.go             # 엔트리포인트 (CLI)
├── dp-track.go         # SBOM 생성·패치·업로드 로직
├── docker-compose.yml  # Dependency-Track 스택
├── start.sh            # 예시 실행 스크립트
├── init.sh             # 필수 툴 설치 스크립트(macOS)
└── client/             # 추후 Web 클라이언트(미사용)
```

## 🛠️ 개발 & 테스트

1. 의존성 설치: `go mod tidy`
2. 코드 포맷팅: `go fmt ./...`
3. (테스트 케이스 추가 시) `go test ./...`

현재 저장소에는 테스트 코드가 존재하지 않습니다. 기능 확장 시 `*_test.go` 파일을 추가해 주세요.

## 📝 라이선스

본 프로젝트는 MIT License를 따릅니다. 자세한 내용은 `LICENSE` 파일을 참고하세요.

## 🙏 참고 자료

- [Syft 공식 문서](https://anchore.com/syft/)
- [CycloneDX 사양](https://cyclonedx.org/docs/latest/json/)
- [Dependency-Track Docs](https://docs.dependencytrack.org/)
- [cdxgen GitHub](https://github.com/CycloneDX/cdxgen) 