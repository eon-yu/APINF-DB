# C++ OSS Compliance Test Project

이 프로젝트는 OSS Compliance Scanner의 **현대적 C++** 지원을 테스트하기 위한 샘플 프로젝트입니다.

## 🔍 C++ vs C 구분

이 프로젝트는 **순수 C가 아닌 현대적 C++ 프로젝트**입니다:

### ✅ Modern C++ 특징
- **언어**: C++17 표준
- **빌드 시스템**: CMake, Conan, vcpkg (현대적 도구)
- **라이브러리**: C++ STL, Boost, 현대적 C++ 라이브러리
- **파일 확장자**: `.cpp`, `.hpp` (C++ 전용)
- **패키지 관리**: Conan, vcpkg (C++ 전용)

### ❌ C와의 차이점
- Make 같은 전통적 C 빌드 도구 **미사용**
- json-c 같은 C 전용 라이브러리 **미사용**
- `.c`, `.h` 확장자 **미사용**
- 시스템 패키지 매니저만 의존 **안함**

## 프로젝트 구조

```
cpp-app/
├── CMakeLists.txt      # CMake 빌드 시스템
├── conanfile.txt       # Conan 패키지 매니저
├── vcpkg.json          # vcpkg 패키지 매니저
├── src/
│   ├── main.cpp        # 메인 소스 파일
│   ├── network.cpp     # 네트워크 관련 코드
│   └── crypto.cpp      # 암호화 관련 코드
├── include/            # 헤더 파일 디렉토리
└── README.md
```

## 사용된 의존성

### 시스템 라이브러리
- **OpenSSL**: 암호화 라이브러리 (취약점 가능성 있음)
- **libcurl**: HTTP 클라이언트 라이브러리
- **zlib**: 압축 라이브러리

### 현대적 C++ 라이브러리
- **Boost**: C++ 유틸리티 라이브러리 (C++ 전용)
- **nlohmann/json**: C++ JSON 라이브러리 (vs C의 json-c)
- **spdlog**: C++ 로깅 라이브러리
- **fmt**: C++ 포맷팅 라이브러리
- **gtest**: C++ 단위 테스트 프레임워크

### vs C 라이브러리 비교
| C++ 라이브러리 | C 대응 라이브러리 |
|---------------|-----------------|
| nlohmann/json | json-c |
| spdlog | syslog |
| std::thread | pthread |
| std::unique_ptr | malloc/free |
| Boost | 시스템 C 라이브러리 |

## 지원하는 패키지 매니저

### 1. CMake (시스템 패키지)
```bash
mkdir build && cd build
cmake ..
make
```

### 2. Conan
```bash
conan install . --build missing
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
make
```

### 3. vcpkg
```bash
vcpkg install
mkdir build && cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=[vcpkg root]/scripts/buildsystems/vcpkg.cmake
make
```

## 테스트 목적

이 프로젝트는 다음을 테스트하기 위해 설계되었습니다:

1. **C/C++ 패키지 감지**: CMake, Conan, vcpkg 파일 인식
2. **의존성 스캔**: 시스템 라이브러리 및 서드파티 라이브러리 검출
3. **취약점 스캔**: OpenSSL, libcurl 등의 알려진 취약점 검출
4. **라이선스 컴플라이언스**: 다양한 라이선스의 라이브러리 검출

## 예상 검출 사항

- **OpenSSL**: 버전에 따른 다양한 취약점 (CVE-2021-3711, CVE-2021-3712 등)
- **libcurl**: 버전에 따른 취약점 (CVE-2021-22876, CVE-2021-22890 등)
- **Boost**: 라이선스 컴플라이언스 (Boost Software License)
- **다양한 라이선스**: MIT, Apache-2.0, BSD 등의 라이선스 혼재

## 빌드 시스템별 특징

- **CMake**: 시스템에 설치된 라이브러리 사용
- **Conan**: 명시적 버전 지정으로 정확한 의존성 관리
- **vcpkg**: Microsoft의 C++ 패키지 매니저, 크로스 플랫폼 지원 