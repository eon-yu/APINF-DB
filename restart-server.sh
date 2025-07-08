#!/bin/bash

# OSS Compliance Scanner - 웹 서버 재시작 스크립트
# 사용법: ./restart-server.sh [옵션]

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
START_SCRIPT="$SCRIPT_DIR/start-server.sh"
STOP_SCRIPT="$SCRIPT_DIR/stop-server.sh"

# 기본 설정
DEFAULT_PORT=8080
DEFAULT_HOST="0.0.0.0"

# 도움말 함수
show_help() {
    echo -e "${BLUE}OSS Compliance Scanner 웹 서버 재시작 스크립트${NC}"
    echo ""
    echo "사용법:"
    echo "  ./restart-server.sh [옵션]"
    echo ""
    echo "옵션:"
    echo "  -h, --help              이 도움말 표시"
    echo "  -p, --port <포트>       서버 포트 (기본: $DEFAULT_PORT)"
    echo "  -H, --host <호스트>     서버 호스트 (기본: $DEFAULT_HOST)"
    echo "  -v, --verbose           상세 출력"
    echo "  -d, --daemon            데몬 모드로 재시작"
    echo "  -f, --force             강제 종료 후 재시작"
    echo "  --dev                   개발 모드로 재시작"
    echo "  --quick                 빠른 재시작 (마이그레이션 스킵)"
    echo "  --status                재시작 후 상태 확인"
    echo ""
    echo "예제:"
    echo "  ./restart-server.sh"
    echo "  ./restart-server.sh -p 9090 -d"
    echo "  ./restart-server.sh -f"
    echo "  ./restart-server.sh --dev"
    echo ""
    echo "접속 URL:"
    echo "  http://localhost:$DEFAULT_PORT"
}

# 스크립트 존재 확인
check_scripts() {
    if [ ! -f "$START_SCRIPT" ]; then
        echo -e "${RED}❌ 시작 스크립트를 찾을 수 없습니다: $START_SCRIPT${NC}"
        exit 1
    fi
    
    if [ ! -f "$STOP_SCRIPT" ]; then
        echo -e "${RED}❌ 중지 스크립트를 찾을 수 없습니다: $STOP_SCRIPT${NC}"
        exit 1
    fi
    
    # 실행 권한 확인
    if [ ! -x "$START_SCRIPT" ]; then
        echo -e "${YELLOW}⚠️  시작 스크립트에 실행 권한이 없습니다. 권한을 설정합니다...${NC}"
        chmod +x "$START_SCRIPT"
    fi
    
    if [ ! -x "$STOP_SCRIPT" ]; then
        echo -e "${YELLOW}⚠️  중지 스크립트에 실행 권한이 없습니다. 권한을 설정합니다...${NC}"
        chmod +x "$STOP_SCRIPT"
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
        return 0
    else
        echo -e "${RED}❌ 서버가 실행되지 않고 있습니다.${NC}"
        return 1
    fi
}

# 재시작 전 확인
pre_restart_check() {
    echo -e "${BLUE}🔍 재시작 전 상태를 확인합니다...${NC}"
    
    # 현재 서버 상태 확인
    if lsof -i :$PORT > /dev/null 2>&1; then
        local pid=$(lsof -ti :$PORT)
        echo -e "${YELLOW}⚠️  포트 $PORT에서 서버가 실행 중입니다 (PID: $pid).${NC}"
        
        if [ $VERBOSE = true ]; then
            local process_info=$(ps -p $pid -o pid,ppid,etime,command 2>/dev/null | tail -1 || echo "Unknown process")
            echo -e "${BLUE}📋 현재 프로세스:${NC}"
            echo "   $process_info"
        fi
        
        return 0
    else
        echo -e "${BLUE}📋 포트 $PORT에서 실행 중인 서버가 없습니다.${NC}"
        return 1
    fi
}

# 서버 중지
stop_server() {
    echo -e "${YELLOW}🛑 서버를 중지합니다...${NC}"
    
    local stop_args=()
    
    # 포트 설정
    stop_args+=("-p" "$PORT")
    
    # 옵션 전달
    if [ $VERBOSE = true ]; then
        stop_args+=("-v")
    fi
    
    if [ $FORCE = true ]; then
        stop_args+=("-f")
    fi
    
    # 중지 스크립트 실행
    "$STOP_SCRIPT" "${stop_args[@]}"
    
    # 중지 확인을 위한 짧은 대기
    sleep 2
    
    # 중지 확인
    if lsof -i :$PORT > /dev/null 2>&1; then
        echo -e "${RED}❌ 서버 중지에 실패했습니다.${NC}"
        exit 1
    else
        echo -e "${GREEN}✅ 서버가 성공적으로 중지되었습니다.${NC}"
    fi
}

# 서버 시작
start_server() {
    echo -e "${GREEN}🚀 서버를 시작합니다...${NC}"
    
    local start_args=()
    
    # 포트 설정
    start_args+=("-p" "$PORT")
    
    # 호스트 설정
    start_args+=("-H" "$HOST")
    
    # 옵션 전달
    if [ $VERBOSE = true ]; then
        start_args+=("-v")
    fi
    
    if [ $DAEMON = true ]; then
        start_args+=("-d")
    fi
    
    if [ $DEV_MODE = true ]; then
        start_args+=("--dev")
    fi
    
    # 시작 스크립트 실행
    "$START_SCRIPT" "${start_args[@]}"
}

# 빠른 재시작 (마이그레이션 스킵)
quick_restart() {
    echo -e "${PURPLE}⚡ 빠른 재시작을 수행합니다...${NC}"
    echo -e "${YELLOW}💡 마이그레이션과 사전 검사를 스킵합니다.${NC}"
    
    # 서버 중지
    if lsof -i :$PORT > /dev/null 2>&1; then
        local pid=$(lsof -ti :$PORT)
        echo -e "${YELLOW}🛑 서버를 중지합니다 (PID: $pid)...${NC}"
        kill -TERM $pid 2>/dev/null || kill -9 $pid 2>/dev/null
        sleep 2
    fi
    
    # 바이너리 직접 실행
    local binary_path="$SCRIPT_DIR/oss-compliance-scanner"
    if [ ! -f "$binary_path" ]; then
        echo -e "${RED}❌ 바이너리를 찾을 수 없습니다: $binary_path${NC}"
        echo -e "${YELLOW}💡 일반 재시작을 사용하세요.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}🚀 서버를 빠르게 시작합니다...${NC}"
    
    if [ $DAEMON = true ]; then
        nohup "$binary_path" server --port "$PORT" > "$SCRIPT_DIR/logs/server.log" 2>&1 &
        local server_pid=$!
        sleep 2
        if ps -p $server_pid > /dev/null 2>&1; then
            echo -e "${GREEN}✅ 서버가 빠르게 재시작되었습니다 (PID: $server_pid).${NC}"
        else
            echo -e "${RED}❌ 빠른 재시작에 실패했습니다.${NC}"
            exit 1
        fi
    else
        exec "$binary_path" server --port "$PORT"
    fi
}

# 재시작 후 상태 확인
post_restart_check() {
    if [ $CHECK_STATUS = true ]; then
        echo ""
        echo -e "${BLUE}🔍 재시작 후 상태를 확인합니다...${NC}"
        
        # 서버 시작을 위한 대기
        local max_attempts=10
        local attempt=1
        
        while [ $attempt -le $max_attempts ]; do
            if check_server_status "$PORT"; then
                echo -e "${GREEN}🎉 서버가 성공적으로 재시작되었습니다!${NC}"
                
                # 간단한 헬스 체크
                echo -e "${BLUE}🏥 헬스 체크를 수행합니다...${NC}"
                if curl -f -s "http://localhost:$PORT/health" > /dev/null 2>&1; then
                    echo -e "${GREEN}✅ 헬스 체크 통과${NC}"
                else
                    echo -e "${YELLOW}⚠️  헬스 체크 엔드포인트에 접근할 수 없습니다.${NC}"
                    echo -e "${BLUE}💡 웹 브라우저에서 http://localhost:$PORT 에 접속해보세요.${NC}"
                fi
                
                return 0
            fi
            
            echo -e "${CYAN}⏳ 서버 시작 대기 중... ($attempt/$max_attempts)${NC}"
            sleep 2
            ((attempt++))
        done
        
        echo -e "${RED}❌ 서버 재시작 확인에 실패했습니다.${NC}"
        return 1
    fi
}

# 인수 파싱
parse_args() {
    PORT=$DEFAULT_PORT
    HOST=$DEFAULT_HOST
    VERBOSE=false
    DAEMON=false
    FORCE=false
    DEV_MODE=false
    QUICK=false
    CHECK_STATUS=true  # 기본적으로 상태 확인
    
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
            -f|--force)
                FORCE=true
                shift
                ;;
            --dev)
                DEV_MODE=true
                shift
                ;;
            --quick)
                QUICK=true
                shift
                ;;
            --status)
                CHECK_STATUS=true
                shift
                ;;
            --no-status)
                CHECK_STATUS=false
                shift
                ;;
            -*)
                echo -e "${RED}❌ 알 수 없는 옵션: $1${NC}"
                echo "도움말을 보려면 './restart-server.sh --help'를 실행하세요."
                exit 1
                ;;
            *)
                echo -e "${RED}❌ 잘못된 인수: $1${NC}"
                echo "도움말을 보려면 './restart-server.sh --help'를 실행하세요."
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

# 메인 실행
main() {
    echo -e "${BLUE}🔄 OSS Compliance Scanner 웹 서버 재시작${NC}"
    echo "========================================"
    
    # 인수 파싱
    parse_args "$@"
    
    # 빠른 재시작
    if [ $QUICK = true ]; then
        quick_restart
        return
    fi
    
    # 스크립트 존재 확인
    check_scripts
    
    # 재시작 전 확인
    local server_was_running=false
    if pre_restart_check; then
        server_was_running=true
    fi
    
    # 서버 중지 (실행 중인 경우만)
    if [ $server_was_running = true ]; then
        stop_server
    else
        echo -e "${BLUE}📋 서버가 중지되어 있어 중지 단계를 건너뜁니다.${NC}"
    fi
    
    # 짧은 대기
    echo -e "${CYAN}⏳ 잠시 대기 중...${NC}"
    sleep 1
    
    # 서버 시작
    start_server
    
    # 재시작 후 상태 확인
    if [ $DAEMON = true ]; then
        post_restart_check
    fi
    
    echo ""
    echo -e "${GREEN}🎉 서버 재시작이 완료되었습니다!${NC}"
    echo -e "${BLUE}💡 접속 URL: http://localhost:$PORT${NC}"
}

# 스크립트 실행
main "$@" 