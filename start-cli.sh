#!/bin/bash

# OSS Compliance Scanner - CLI 시작 스크립트
# 사용법: ./start-cli.sh [옵션] [저장소 경로]

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 스크립트 디렉토리 확인
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="$SCRIPT_DIR/oss-compliance-scanner"

# 도움말 함수
show_help() {
    echo -e "${BLUE}OSS Compliance Scanner CLI 시작 스크립트${NC}"
    echo ""
    echo "사용법:"
    echo "  ./start-cli.sh [옵션] [저장소 경로]"
    echo ""
    echo "옵션:"
    echo "  -h, --help              이 도움말 표시"
    echo "  -v, --verbose           상세 출력"
    echo "  -m, --module <경로>     특정 모듈만 스캔"
    echo "  -o, --output <형식>     출력 형식 (json, yaml, table)"
    echo "  -n, --notify            Slack 알림 활성화"
    echo "  --skip-sbom             SBOM 생성 건너뛰기"
    echo "  --skip-vuln             취약점 스캔 건너뛰기"
    echo "  --force                 강제 재스캔"
    echo ""
    echo "예제:"
    echo "  ./start-cli.sh /path/to/repo"
    echo "  ./start-cli.sh -m frontend /path/to/monorepo"
    echo "  ./start-cli.sh -v --notify /path/to/repo"
    echo "  ./start-cli.sh --output json /path/to/repo"
    echo ""
    echo "테스트 프로젝트 스캔:"
    echo "  ./start-cli.sh test-projects/nodejs-app"
    echo "  ./start-cli.sh test-projects/cpp-app"
    echo "  ./start-cli.sh test-projects/multi-module"
}

# 바이너리 존재 확인
check_binary() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "${RED}❌ 바이너리를 찾을 수 없습니다: $BINARY_PATH${NC}"
        echo -e "${YELLOW}💡 다음 명령어로 빌드하세요:${NC}"
        echo "   go build -o oss-compliance-scanner ."
        exit 1
    fi
    
    if [ ! -x "$BINARY_PATH" ]; then
        echo -e "${YELLOW}⚠️  바이너리에 실행 권한이 없습니다. 권한을 설정합니다...${NC}"
        chmod +x "$BINARY_PATH"
    fi
}

# 필수 도구 확인
check_dependencies() {
    local missing_tools=()
    
    if ! command -v syft &> /dev/null; then
        missing_tools+=("syft")
    fi
    
    if ! command -v grype &> /dev/null; then
        missing_tools+=("grype")
    fi
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo -e "${RED}❌ 필수 도구가 설치되지 않았습니다:${NC}"
        for tool in "${missing_tools[@]}"; do
            echo "   - $tool"
        done
        echo ""
        echo -e "${YELLOW}💡 설치 방법:${NC}"
        echo "   # macOS (Homebrew)"
        echo "   brew install anchore/syft/syft"
        echo "   brew install anchore/grype/grype"
        echo ""
        echo "   # Linux"
        echo "   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
        echo "   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
        exit 1
    fi
}

# 데이터베이스 초기화 확인
check_database() {
    local db_path="$SCRIPT_DIR/db/oss_scan.db"
    local schema_path="$SCRIPT_DIR/db/schema.sql"
    
    if [ ! -f "$db_path" ]; then
        if [ -f "$schema_path" ]; then
            echo -e "${YELLOW}⚠️  데이터베이스가 없습니다. 초기화합니다...${NC}"
            mkdir -p "$SCRIPT_DIR/db"
            sqlite3 "$db_path" < "$schema_path"
            echo -e "${GREEN}✅ 데이터베이스가 초기화되었습니다.${NC}"
        else
            echo -e "${RED}❌ 데이터베이스 스키마 파일을 찾을 수 없습니다: $schema_path${NC}"
            exit 1
        fi
    fi
}

# 설정 파일 확인
check_config() {
    local config_path="$SCRIPT_DIR/.oss-compliance-scanner.yaml"
    local sample_config="$SCRIPT_DIR/.oss-compliance-scanner.yaml.sample"
    
    if [ ! -f "$config_path" ] && [ -f "$sample_config" ]; then
        echo -e "${YELLOW}⚠️  설정 파일이 없습니다. 샘플에서 복사합니다...${NC}"
        cp "$sample_config" "$config_path"
        echo -e "${GREEN}✅ 설정 파일이 생성되었습니다: $config_path${NC}"
    fi
}

# 인수 파싱
parse_args() {
    REPO_PATH=""
    SCAN_ARGS=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--verbose)
                SCAN_ARGS+=("--verbose")
                shift
                ;;
            -m|--module)
                SCAN_ARGS+=("--module" "$2")
                shift 2
                ;;
            -o|--output)
                SCAN_ARGS+=("--output" "$2")
                shift 2
                ;;
            -n|--notify)
                SCAN_ARGS+=("--notify")
                shift
                ;;
            --skip-sbom)
                SCAN_ARGS+=("--skip-sbom")
                shift
                ;;
            --skip-vuln)
                SCAN_ARGS+=("--skip-vuln")
                shift
                ;;
            --force)
                SCAN_ARGS+=("--force")
                shift
                ;;
            -*)
                echo -e "${RED}❌ 알 수 없는 옵션: $1${NC}"
                echo "도움말을 보려면 './start-cli.sh --help'를 실행하세요."
                exit 1
                ;;
            *)
                if [ -z "$REPO_PATH" ]; then
                    REPO_PATH="$1"
                else
                    echo -e "${RED}❌ 저장소 경로는 하나만 지정할 수 있습니다.${NC}"
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    if [ -z "$REPO_PATH" ]; then
        echo -e "${RED}❌ 저장소 경로를 지정해야 합니다.${NC}"
        echo "도움말을 보려면 './start-cli.sh --help'를 실행하세요."
        exit 1
    fi
}

# 저장소 경로 검증
validate_repo_path() {
    if [ ! -d "$REPO_PATH" ]; then
        echo -e "${RED}❌ 저장소 경로가 존재하지 않습니다: $REPO_PATH${NC}"
        exit 1
    fi
    
    # 절대 경로로 변환
    REPO_PATH="$(cd "$REPO_PATH" && pwd)"
    echo -e "${BLUE}📁 스캔 대상: $REPO_PATH${NC}"
}

# 스캔 실행
run_scan() {
    echo -e "${GREEN}🚀 OSS Compliance Scanner 시작${NC}"
    echo "========================================"
    
    local start_time=$(date +%s)
    
    # 스캔 명령어 구성
    local cmd=("$BINARY_PATH" "scan" "--repo" "$REPO_PATH")
    cmd+=("${SCAN_ARGS[@]}")
    
    echo -e "${BLUE}📋 실행 명령어:${NC}"
    echo "   ${cmd[*]}"
    echo ""
    
    # 스캔 실행
    if "${cmd[@]}"; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        echo ""
        echo -e "${GREEN}✅ 스캔이 성공적으로 완료되었습니다!${NC}"
        echo -e "${BLUE}⏱️  소요 시간: ${duration}초${NC}"
        echo ""
        echo -e "${YELLOW}💡 다음 단계:${NC}"
        echo "   1. 웹 대시보드에서 결과 확인: ./start-server.sh"
        echo "   2. 데이터베이스 직접 조회: sqlite3 db/oss_scan.db"
        echo "   3. 정책 설정 조정: vi .oss-compliance-scanner.yaml"
    else
        echo ""
        echo -e "${RED}❌ 스캔 중 오류가 발생했습니다.${NC}"
        echo -e "${YELLOW}💡 문제 해결:${NC}"
        echo "   1. --verbose 옵션으로 상세 로그 확인"
        echo "   2. 저장소 경로 및 권한 확인"
        echo "   3. 필수 도구 설치 상태 확인"
        exit 1
    fi
}

# 메인 실행
main() {
    echo -e "${BLUE}🔍 OSS Compliance Scanner CLI${NC}"
    echo "========================================"
    
    # 사전 검사
    check_binary
    check_dependencies
    check_database
    check_config
    
    # 인수 파싱 및 검증
    parse_args "$@"
    validate_repo_path
    
    # 스캔 실행
    run_scan
}

# 스크립트 실행
main "$@" 