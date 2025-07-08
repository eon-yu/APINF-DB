# C OSS Compliance Test Project

이 프로젝트는 OSS Compliance Scanner의 **순수 C 언어** 지원을 테스트하기 위한 샘플 프로젝트입니다.

## 🔍 C vs C++ 구분

이 프로젝트는 **C++ 프로젝트가 아닌 순수 C 언어 프로젝트**입니다:

### ✅ Pure C 특징
- **언어**: C99 표준 순수 C 언어
- **빌드 시스템**: Make (전통적인 C 빌드 도구)
- **라이브러리**: 시스템 C 라이브러리만 사용
- **파일 확장자**: `.c`, `.h` (C++ 확장자 없음)
- **패키지 관리**: 시스템 패키지 매니저 의존

### ❌ C++과의 차이점
- Conan, vcpkg 같은 현대적 C++ 패키지 매니저 **미사용**
- C++ STL, Boost 같은 C++ 라이브러리 **미사용**
- `.cpp`, `.hpp` 확장자 **미사용**
- C++ 전용 빌드 도구 **미사용**

## 📁 프로젝트 구조

```
c-app/
├── Makefile            # Make 빌드 시스템 (C 전용)
├── src/
│   ├── main.c          # 메인 소스 (C99)
│   ├── network.c       # 네트워크 관련 (libcurl)
│   ├── crypto.c        # 암호화 관련 (OpenSSL)
│   └── utils.c         # 유틸리티 (zlib, pthread)
├── include/            # 헤더 파일 (*.h만)
│   ├── network.h
│   ├── crypto.h
│   └── utils.h
└── README.md
```

## 📚 사용된 C 라이브러리

### 시스템 C 라이브러리 (취약점 가능성)
- **OpenSSL** (`libssl`, `libcrypto`) - C 암호화 라이브러리
- **libcurl** - C HTTP 클라이언트 라이브러리
- **zlib** - C 압축 라이브러리
- **json-c** - C JSON 파싱 라이브러리 (C++ nlohmann/json과 구분)
- **pthread** - POSIX 스레드 라이브러리

### vs C++ 라이브러리 비교
| C 라이브러리 | C++ 대응 라이브러리 |
|-------------|-------------------|
| json-c | nlohmann/json |
| OpenSSL (C API) | OpenSSL (C++ wrapper) |
| libcurl (C API) | libcurl (C++ wrapper) |
| pthread | std::thread |
| 시스템 malloc/free | std::unique_ptr, std::shared_ptr |

## 🏗️ 빌드 방법

### 의존성 설치

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y libssl-dev libcurl4-openssl-dev zlib1g-dev libjson-c-dev
```

**CentOS/RHEL:**
```bash
sudo yum install -y openssl-devel libcurl-devel zlib-devel json-c-devel
```

**macOS (Homebrew):**
```bash
brew install openssl curl zlib json-c
```

### 빌드 실행
```bash
cd test-projects/c-app
make deps-check    # 의존성 확인
make all           # 빌드
./c-oss-test       # 실행
```

## 🧪 테스트 목적

이 프로젝트는 다음을 테스트하기 위해 설계되었습니다:

### 1. **언어 구분 검증**
- C와 C++이 별도 언어로 올바르게 인식되는지
- 파일 확장자 기반 언어 감지 (`.c` vs `.cpp`)
- 빌드 시스템 기반 언어 감지 (Make for C)

### 2. **C 전용 라이브러리 감지**
- 시스템 C 라이브러리 스캔
- C API 사용 패턴 인식
- C 표준 라이브러리 vs C++ STL 구분

### 3. **취약점 스캔**
- C 라이브러리 취약점 감지
- CVE 매핑 정확성
- C vs C++ 라이브러리 취약점 구분

## 🔒 예상 검출 취약점

### OpenSSL (C)
- CVE-2021-3711 (Critical)
- CVE-2021-3712 (High)
- CVE-2022-0778 (High)

### libcurl (C)
- CVE-2021-22876 (Medium)
- CVE-2021-22890 (High)
- CVE-2022-22576 (Medium)

### zlib (C)
- CVE-2022-37434 (Critical)
- CVE-2018-25032 (High)

### json-c (C)
- CVE-2020-12762 (High)

## 🆚 C++ 프로젝트와의 비교

| 특징 | C 프로젝트 (c-app) | C++ 프로젝트 (cpp-app) |
|------|-------------------|----------------------|
| **언어** | C99 | C++17 |
| **빌드 도구** | Make | CMake, Conan, vcpkg |
| **JSON 라이브러리** | json-c | nlohmann/json |
| **패키지 관리** | 시스템 패키지 | Conan, vcpkg |
| **스레딩** | pthread | std::thread |
| **메모리 관리** | malloc/free | smart pointers |
| **파일 확장자** | .c, .h | .cpp, .hpp |

## 🎯 스캔 결과 기대값

OSS Compliance Scanner는 이 프로젝트를 다음과 같이 식별해야 합니다:

- **언어**: `C` (C++이 아님)
- **빌드 시스템**: `make-c`
- **패키지 매니저**: 시스템 의존성
- **라이브러리 타입**: C 시스템 라이브러리
- **취약점**: C 라이브러리 특정 CVE

이를 통해 C와 C++이 올바르게 구분되어 처리되는지 검증할 수 있습니다. 