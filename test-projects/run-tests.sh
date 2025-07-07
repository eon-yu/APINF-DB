#!/bin/bash

# OSS Compliance Scanner 테스트 실행 스크립트

set -e

echo "🚀 OSS Compliance Scanner 테스트 시작"
echo "======================================"

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 테스트 결과 저장 디렉토리
RESULTS_DIR="test-results"
mkdir -p "$RESULTS_DIR"

# 현재 시간
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# OSS Scanner 바이너리 경로 확인
OSS_SCANNER="../oss-compliance-scanner"
if [ ! -f "$OSS_SCANNER" ]; then
    echo -e "${RED}❌ OSS Scanner 바이너리를 찾을 수 없습니다: $OSS_SCANNER${NC}"
    echo "먼저 메인 디렉토리에서 'go build -o oss-compliance-scanner .'를 실행하세요."
    exit 1
fi

echo -e "${GREEN}✅ OSS Scanner 바이너리 확인: $OSS_SCANNER${NC}"

# 테스트 함수
run_test() {
    local test_name="$1"
    local test_dir="$2"
    local module_name="$3"
    
    echo ""
    echo -e "${BLUE}📋 테스트: $test_name${NC}"
    echo "----------------------------------------"
    echo "디렉토리: $test_dir"
    echo "모듈: $module_name"
    
    local output_file="$RESULTS_DIR/${test_name}_${TIMESTAMP}.json"
    local log_file="$RESULTS_DIR/${test_name}_${TIMESTAMP}.log"
    
    echo "결과 파일: $output_file"
    echo ""
    
    # OSS Scanner 실행
    if [ -n "$module_name" ]; then
        echo "명령어: $OSS_SCANNER scan --repo $test_dir --module $module_name"
        $OSS_SCANNER scan --repo "$test_dir" --module "$module_name" > "$log_file" 2>&1
    else
        echo "명령어: $OSS_SCANNER scan --repo $test_dir"
        $OSS_SCANNER scan --repo "$test_dir" > "$log_file" 2>&1
    fi
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ 스캔 완료${NC}"
    else
        echo -e "${YELLOW}⚠️  스캔 완료 (경고/오류 발생, exit code: $exit_code)${NC}"
    fi
    
    # 결과 요약 출력
    echo "로그 파일에서 주요 정보 추출..."
    if [ -f "$log_file" ]; then
        echo "마지막 10줄:"
        tail -10 "$log_file"
    fi
}

# 1. Node.js 프로젝트 테스트
run_test "nodejs-app" "nodejs-app" ""

# 2. Go 프로젝트 테스트  
run_test "go-app" "go-app" ""

# 3. Python 프로젝트 테스트
run_test "python-app" "python-app" ""

# 4. 멀티 모듈 프로젝트 테스트 - 전체
run_test "multi-module-all" "multi-module" ""

# 5. 멀티 모듈 프로젝트 테스트 - 개별 모듈
run_test "multi-module-frontend" "multi-module" "frontend"
run_test "multi-module-backend" "multi-module" "backend"
run_test "multi-module-data-service" "multi-module" "data-service"

echo ""
echo -e "${GREEN}🎉 모든 테스트 완료!${NC}"
echo "======================================"
echo "결과 파일들:"
ls -la "$RESULTS_DIR"/*"$TIMESTAMP"*

echo ""
echo -e "${BLUE}📊 테스트 결과 요약:${NC}"
echo "1. Node.js 앱: 취약한 axios, lodash 등 검출 예상"
echo "2. Go 앱: 취약한 JWT 라이브러리 등 검출 예상"  
echo "3. Python 앱: 다양한 취약한 패키지들 검출 예상"
echo "4. 멀티 모듈: 각 모듈별 개별 스캔 및 통합 스캔"

echo ""
echo -e "${YELLOW}💡 다음 단계:${NC}"
echo "1. $RESULTS_DIR 디렉토리의 로그 파일들을 확인하세요"
echo "2. 웹 대시보드에서 결과를 확인하세요: ../oss-compliance-scanner server"
echo "3. 정책 설정을 조정하고 재테스트하세요"

echo ""
echo -e "${GREEN}✨ 테스트 스크립트 실행 완료!${NC}" 