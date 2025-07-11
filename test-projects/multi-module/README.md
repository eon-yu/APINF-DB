# Multi-Module Test Project

이 프로젝트는 OSS Compliance Scanner의 멀티 모듈 지원을 테스트하기 위한 샘플 프로젝트입니다.

## 프로젝트 구조

```
multi-module/
├── frontend/          # React.js 프론트엔드
│   ├── package.json
│   └── src/
├── backend/           # Go 백엔드 API
│   ├── go.mod
│   └── main.go
├── data-service/      # Python 데이터 서비스
│   ├── requirements.txt
│   └── app.py
└── README.md
```

## 각 모듈 설명

### Frontend (Node.js/React)
- React 17.0.2 기반 프론트엔드
- 취약한 버전의 axios, lodash 등 포함
- Bootstrap, jQuery 등 UI 라이브러리 사용

### Backend (Go)
- Gin 웹 프레임워크 사용
- PostgreSQL, Redis 연동
- JWT 인증 (취약한 버전 사용)

### Data Service (Python)
- Flask 기반 데이터 처리 서비스
- pandas, numpy 등 데이터 분석 라이브러리
- 취약한 버전의 라이브러리들 포함

## 테스트 목적

이 프로젝트는 다음을 테스트하기 위해 설계되었습니다:

1. **멀티 모듈 스캔**: 각 언어별 모듈을 개별적으로 스캔
2. **라이선스 컴플라이언스**: 다양한 라이선스의 패키지 검출
3. **취약점 스캔**: 알려진 취약점이 있는 패키지들 검출
4. **정책 위반**: 설정된 정책에 따른 위반 사항 검출

## 예상 검출 사항

- **Node.js**: axios 0.21.1 (취약점), lodash 4.17.19 (취약점)
- **Go**: dgrijalva/jwt-go (deprecated/vulnerable)
- **Python**: 다양한 취약한 버전의 패키지들 