#!/bin/bash

# OSS Compliance Scanner - 웹 서버 시작 스크립트
# 사용법: ./start-server.sh [옵션]

set -e

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 스크립트 디렉토리 확인
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY_PATH="$SCRIPT_DIR/oss-compliance-scanner"

# 기본 설정
DEFAULT_PORT=8080
DEFAULT_HOST="0.0.0.0"

# 도움말 함수
show_help() {
    echo -e "${BLUE}OSS Compliance Scanner 웹 서버 시작 스크립트${NC}"
    echo ""
    echo "사용법:"
    echo "  ./start-server.sh [옵션]"
    echo ""
    echo "옵션:"
    echo "  -h, --help              이 도움말 표시"
    echo "  -p, --port <포트>       서버 포트 (기본: $DEFAULT_PORT)"
    echo "  -H, --host <호스트>     서버 호스트 (기본: $DEFAULT_HOST)"
    echo "  -v, --verbose           상세 출력"
    echo "  -d, --daemon            데몬 모드로 실행"
    echo "  --dev                   개발 모드 (자동 재시작)"
    echo "  --stop                  실행 중인 서버 중지"
    echo "  --status                서버 상태 확인"
    echo "  --logs                  서버 로그 확인"
    echo ""
    echo "예제:"
    echo "  ./start-server.sh"
    echo "  ./start-server.sh -p 9090"
    echo "  ./start-server.sh -d"
    echo "  ./start-server.sh --stop"
    echo ""
    echo "접속 URL:"
    echo "  http://localhost:$DEFAULT_PORT"
}

# 바이너리 존재 확인 및 빌드
check_binary() {
    if [ ! -f "$BINARY_PATH" ]; then
        echo -e "${YELLOW}⚠️  바이너리를 찾을 수 없습니다. 빌드합니다...${NC}"
        echo -e "${BLUE}🔨 Go 바이너리 빌드 중...${NC}"
        
        if command -v go >/dev/null 2>&1; then
            go build -o "$BINARY_PATH" .
            if [ $? -eq 0 ]; then
                echo -e "${GREEN}✅ 바이너리 빌드가 완료되었습니다: $BINARY_PATH${NC}"
            else
                echo -e "${RED}❌ 바이너리 빌드에 실패했습니다.${NC}"
                exit 1
            fi
        else
            echo -e "${RED}❌ Go가 설치되어 있지 않습니다.${NC}"
            echo -e "${YELLOW}💡 Go를 설치하거나 미리 빌드된 바이너리를 사용하세요.${NC}"
            exit 1
        fi
    fi
    
    if [ ! -x "$BINARY_PATH" ]; then
        echo -e "${YELLOW}⚠️  바이너리에 실행 권한이 없습니다. 권한을 설정합니다...${NC}"
        chmod +x "$BINARY_PATH"
    fi
}

# 데이터베이스 마이그레이션 실행
check_database() {
    local db_path="$SCRIPT_DIR/oss_scan.db"
    local migrations_dir="$SCRIPT_DIR/db/migrations"
    
    # 데이터베이스 디렉토리 생성
    mkdir -p "$SCRIPT_DIR/db"
    
    # 마이그레이션이 있는 경우 실행
    if [ -d "$migrations_dir" ] && [ "$(ls -A $migrations_dir/*.sql 2>/dev/null)" ]; then
        echo -e "${YELLOW}🔄 데이터베이스 마이그레이션을 실행합니다...${NC}"
        "$BINARY_PATH" migrate up
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ 데이터베이스 마이그레이션이 완료되었습니다.${NC}"
        else
            echo -e "${RED}❌ 데이터베이스 마이그레이션에 실패했습니다.${NC}"
            exit 1
        fi
    else
        echo -e "${BLUE}📋 마이그레이션 파일이 없습니다. 기본 스키마를 사용합니다.${NC}"
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

# 포트 사용 중인지 확인
check_port() {
    local port=$1
    if lsof -i :$port > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  포트 $port이 이미 사용 중입니다.${NC}"
        
        # 실행 중인 프로세스 정보 표시
        local pid=$(lsof -ti :$port)
        if [ -n "$pid" ]; then
            local process_info=$(ps -p $pid -o pid,ppid,command 2>/dev/null | tail -1 || echo "Unknown process")
            echo -e "${BLUE}📋 실행 중인 프로세스:${NC}"
            echo "   PID: $pid"
            echo "   Info: $process_info"
            echo ""
            
            read -p "기존 프로세스를 종료하고 계속하시겠습니까? (y/N): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo -e "${YELLOW}🔄 프로세스를 종료합니다...${NC}"
                kill -9 $pid
                sleep 2
                if lsof -i :$port > /dev/null 2>&1; then
                    echo -e "${RED}❌ 프로세스 종료에 실패했습니다.${NC}"
                    exit 1
                else
                    echo -e "${GREEN}✅ 프로세스가 종료되었습니다.${NC}"
                fi
            else
                echo -e "${RED}❌ 서버 시작을 취소합니다.${NC}"
                exit 1
            fi
        fi
    fi
}

# 서버 상태 확인
check_server_status() {
    local port=$1
    if lsof -i :$port > /dev/null 2>&1; then
        local pid=$(lsof -ti :$port)
        echo -e "${GREEN}✅ 서버가 실행 중입니다.${NC}"
        echo -e "${BLUE}📋 서버 정보:${NC}"
        echo "   포트: $port"
        echo "   PID: $pid"
        echo "   URL: http://localhost:$port"
        
        if ps -p $pid > /dev/null 2>&1; then
            local process_info=$(ps -p $pid -o pid,ppid,etime,command 2>/dev/null | tail -1)
            echo "   프로세스: $process_info"
        fi
        return 0
    else
        echo -e "${RED}❌ 서버가 실행되지 않고 있습니다.${NC}"
        return 1
    fi
}

# 서버 중지
stop_server() {
    local port=$1
    echo -e "${YELLOW}🛑 서버를 중지합니다...${NC}"
    
    if lsof -i :$port > /dev/null 2>&1; then
        local pid=$(lsof -ti :$port)
        kill -9 $pid
        sleep 2
        
        if lsof -i :$port > /dev/null 2>&1; then
            echo -e "${RED}❌ 서버 중지에 실패했습니다.${NC}"
            exit 1
        else
            echo -e "${GREEN}✅ 서버가 중지되었습니다.${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️  실행 중인 서버가 없습니다.${NC}"
    fi
}

# 서버 로그 확인
show_server_logs() {
    local log_file="$SCRIPT_DIR/logs/server.log"
    
    if [ -f "$log_file" ]; then
        echo -e "${BLUE}📋 서버 로그 (마지막 50줄):${NC}"
        echo "========================================"
        tail -50 "$log_file"
    else
        echo -e "${YELLOW}⚠️  로그 파일이 없습니다: $log_file${NC}"
    fi
}

# 인수 파싱
parse_args() {
    PORT=$DEFAULT_PORT
    HOST=$DEFAULT_HOST
    VERBOSE=false
    DAEMON=false
    DEV_MODE=false
    STOP_SERVER=false
    CHECK_STATUS=false
    SHOW_LOGS=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -p|--port)
                PORT="$2"
                shift 2
                ;;
            -H|--host)
                HOST="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -d|--daemon)
                DAEMON=true
                shift
                ;;
            --dev)
                DEV_MODE=true
                shift
                ;;
            --stop)
                STOP_SERVER=true
                shift
                ;;
            --status)
                CHECK_STATUS=true
                shift
                ;;
            --logs)
                SHOW_LOGS=true
                shift
                ;;
            -*)
                echo -e "${RED}❌ 알 수 없는 옵션: $1${NC}"
                echo "도움말을 보려면 './start-server.sh --help'를 실행하세요."
                exit 1
                ;;
            *)
                echo -e "${RED}❌ 잘못된 인수: $1${NC}"
                echo "도움말을 보려면 './start-server.sh --help'를 실행하세요."
                exit 1
                ;;
        esac
    done
    
    # 포트 번호 검증
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        echo -e "${RED}❌ 잘못된 포트 번호: $PORT${NC}"
        exit 1
    fi
}

# 서버 시작
start_server() {
    echo -e "${GREEN}🚀 OSS Compliance Scanner 웹 서버 시작${NC}"
    echo "========================================"
    
    # 서버 명령어 구성
    local cmd=("$BINARY_PATH" "server" "--port" "$PORT")
    
    if [ "$VERBOSE" = true ]; then
        cmd+=("--verbose")
    fi
    
    echo -e "${BLUE}📋 서버 정보:${NC}"
    echo "   호스트: $HOST"
    echo "   포트: $PORT"
    echo "   URL: http://localhost:$PORT"
    echo "   바이너리: $BINARY_PATH"
    echo ""
    
    # 로그 디렉토리 생성
    mkdir -p "$SCRIPT_DIR/logs"
    
    if [ "$DAEMON" = true ]; then
        # 데몬 모드로 실행
        echo -e "${YELLOW}🔄 데몬 모드로 서버를 시작합니다...${NC}"
        nohup "${cmd[@]}" > "$SCRIPT_DIR/logs/server.log" 2>&1 &
        local server_pid=$!
        
        # 서버 시작 확인
        sleep 3
        if ps -p $server_pid > /dev/null 2>&1; then
            echo -e "${GREEN}✅ 서버가 백그라운드에서 시작되었습니다.${NC}"
            echo -e "${BLUE}📋 서버 PID: $server_pid${NC}"
            echo -e "${YELLOW}💡 서버 중지: ./start-server.sh --stop${NC}"
            echo -e "${YELLOW}💡 서버 상태: ./start-server.sh --status${NC}"
            echo -e "${YELLOW}💡 서버 로그: ./start-server.sh --logs${NC}"
        else
            echo -e "${RED}❌ 서버 시작에 실패했습니다.${NC}"
            exit 1
        fi
    else
        # 포그라운드 모드로 실행
        echo -e "${YELLOW}🔄 서버를 시작합니다...${NC}"
        echo -e "${CYAN}💡 서버를 중지하려면 Ctrl+C를 누르세요.${NC}"
        echo ""
        
        # 신호 처리
        trap 'echo -e "\n${YELLOW}🛑 서버를 중지합니다...${NC}"; exit 0' INT TERM
        
        # 서버 실행
        "${cmd[@]}"
    fi
}

# 개발 모드 실행
start_dev_mode() {
    echo -e "${PURPLE}🔧 개발 모드로 서버를 시작합니다...${NC}"
    echo -e "${YELLOW}💡 파일 변경 시 자동으로 재시작됩니다.${NC}"
    echo ""
    
    # 파일 감시 및 자동 재시작
    while true; do
        echo -e "${BLUE}🔄 서버를 시작합니다...${NC}"
        
        # 서버 시작
        "$BINARY_PATH" server --port "$PORT" &
        local server_pid=$!
        
        # 파일 변경 감시 (간단한 구현)
        local last_modified=$(find . -name "*.go" -o -name "*.yaml" -o -name "*.html" | xargs stat -f "%m" 2>/dev/null | sort -nr | head -1)
        
        while ps -p $server_pid > /dev/null 2>&1; do
            sleep 2
            local current_modified=$(find . -name "*.go" -o -name "*.yaml" -o -name "*.html" | xargs stat -f "%m" 2>/dev/null | sort -nr | head -1)
            
            if [ "$current_modified" != "$last_modified" ]; then
                echo -e "${YELLOW}🔄 파일 변경 감지. 서버를 재시작합니다...${NC}"
                kill $server_pid
                break
            fi
        done
        
        wait $server_pid 2>/dev/null
        sleep 1
    done
}

# 메인 실행
main() {
    echo -e "${BLUE}🌐 OSS Compliance Scanner 웹 서버${NC}"
    echo "========================================"
    
    # 인수 파싱
    parse_args "$@"
    
    # 특별한 작업 처리
    if [ "$STOP_SERVER" = true ]; then
        stop_server "$PORT"
        exit 0
    fi
    
    if [ "$CHECK_STATUS" = true ]; then
        check_server_status "$PORT"
        exit $?
    fi
    
    if [ "$SHOW_LOGS" = true ]; then
        show_server_logs
        exit 0
    fi
    
    # 사전 검사
    check_binary
    check_database
    check_config
    check_port "$PORT"
    
    # 서버 시작
    if [ "$DEV_MODE" = true ]; then
        start_dev_mode
    else
        start_server
    fi
}

# 스크립트 실행
main "$@" 