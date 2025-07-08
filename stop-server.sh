#!/bin/bash

# OSS Compliance Scanner - 웹 서버 중지 스크립트
# 사용법: ./stop-server.sh [옵션]

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
BINARY_NAME="oss-compliance-scanner"

# 기본 설정
DEFAULT_PORT=8080

# 도움말 함수
show_help() {
    echo -e "${BLUE}OSS Compliance Scanner 웹 서버 중지 스크립트${NC}"
    echo ""
    echo "사용법:"
    echo "  ./stop-server.sh [옵션]"
    echo ""
    echo "옵션:"
    echo "  -h, --help              이 도움말 표시"
    echo "  -p, --port <포트>       중지할 서버 포트 (기본: $DEFAULT_PORT)"
    echo "  -a, --all               모든 포트에서 실행 중인 서버 중지"
    echo "  -f, --force             강제 종료 (SIGKILL 사용)"
    echo "  -v, --verbose           상세 출력"
    echo "  --status                서버 상태 확인만"
    echo ""
    echo "예제:"
    echo "  ./stop-server.sh"
    echo "  ./stop-server.sh -p 9090"
    echo "  ./stop-server.sh -a"
    echo "  ./stop-server.sh -f"
    echo ""
}

# 프로세스 찾기 (포트 기반)
find_process_by_port() {
    local port=$1
    local pid=$(lsof -ti :$port 2>/dev/null)
    echo "$pid"
}

# 프로세스 찾기 (바이너리 이름 기반)
find_process_by_name() {
    local name=$1
    local pids=$(pgrep -f "$name" 2>/dev/null || true)
    echo "$pids"
}

# 프로세스 정보 표시
show_process_info() {
    local pid=$1
    if [ -n "$pid" ] && ps -p $pid > /dev/null 2>&1; then
        local process_info=$(ps -p $pid -o pid,ppid,etime,command 2>/dev/null | tail -1)
        echo -e "${BLUE}📋 프로세스 정보:${NC}"
        echo "   PID: $pid"
        echo "   정보: $process_info"
        
        # 포트 정보 확인
        local port_info=$(lsof -p $pid -i 2>/dev/null | grep LISTEN || true)
        if [ -n "$port_info" ]; then
            echo -e "${BLUE}📋 리스닝 포트:${NC}"
            echo "$port_info" | awk '{print "   " $9}'
        fi
    fi
}

# 프로세스 종료 (우아한 종료)
graceful_stop() {
    local pid=$1
    local timeout=${2:-10}
    
    echo -e "${YELLOW}🛑 프로세스를 우아하게 종료합니다 (PID: $pid)...${NC}"
    
    # SIGTERM 신호 전송
    kill -TERM $pid 2>/dev/null || {
        echo -e "${RED}❌ 프로세스에 SIGTERM 신호를 보낼 수 없습니다.${NC}"
        return 1
    }
    
    # 프로세스가 종료될 때까지 대기
    local count=0
    while [ $count -lt $timeout ] && ps -p $pid > /dev/null 2>&1; do
        sleep 1
        ((count++))
        if [ $VERBOSE = true ]; then
            echo -e "${CYAN}⏳ 종료 대기 중... ($count/$timeout)${NC}"
        fi
    done
    
    # 프로세스가 아직 실행 중인지 확인
    if ps -p $pid > /dev/null 2>&1; then
        echo -e "${YELLOW}⚠️  우아한 종료에 실패했습니다. 강제 종료를 시도합니다...${NC}"
        return 1
    else
        echo -e "${GREEN}✅ 프로세스가 우아하게 종료되었습니다.${NC}"
        return 0
    fi
}

# 프로세스 종료 (강제 종료)
force_stop() {
    local pid=$1
    
    echo -e "${RED}💀 프로세스를 강제 종료합니다 (PID: $pid)...${NC}"
    
    # SIGKILL 신호 전송
    kill -9 $pid 2>/dev/null || {
        echo -e "${RED}❌ 프로세스에 SIGKILL 신호를 보낼 수 없습니다.${NC}"
        return 1
    }
    
    # 짧은 대기 후 확인
    sleep 1
    
    if ps -p $pid > /dev/null 2>&1; then
        echo -e "${RED}❌ 강제 종료에 실패했습니다.${NC}"
        return 1
    else
        echo -e "${GREEN}✅ 프로세스가 강제 종료되었습니다.${NC}"
        return 0
    fi
}

# 서버 상태 확인
check_server_status() {
    local port=$1
    local pid=$(find_process_by_port $port)
    
    if [ -n "$pid" ]; then
        echo -e "${GREEN}✅ 서버가 실행 중입니다.${NC}"
        show_process_info $pid
        return 0
    else
        echo -e "${RED}❌ 포트 $port에서 실행 중인 서버가 없습니다.${NC}"
        
        # 바이너리 이름으로 실행 중인 프로세스 찾기
        local pids=$(find_process_by_name $BINARY_NAME)
        if [ -n "$pids" ]; then
            echo -e "${YELLOW}⚠️  다른 포트에서 실행 중인 서버를 발견했습니다:${NC}"
            for pid in $pids; do
                show_process_info $pid
            done
        fi
        return 1
    fi
}

# 특정 포트의 서버 중지
stop_server_by_port() {
    local port=$1
    local force=$2
    
    echo -e "${BLUE}🔍 포트 $port에서 실행 중인 서버를 찾습니다...${NC}"
    
    local pid=$(find_process_by_port $port)
    
    if [ -z "$pid" ]; then
        echo -e "${YELLOW}⚠️  포트 $port에서 실행 중인 서버가 없습니다.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}🎯 서버를 찾았습니다.${NC}"
    if [ $VERBOSE = true ]; then
        show_process_info $pid
    fi
    
    # 프로세스 종료
    if [ "$force" = true ]; then
        force_stop $pid
    else
        if ! graceful_stop $pid; then
            echo -e "${YELLOW}🔄 강제 종료를 시도합니다...${NC}"
            force_stop $pid
        fi
    fi
}

# 모든 서버 중지
stop_all_servers() {
    local force=$1
    
    echo -e "${BLUE}🔍 모든 OSS Compliance Scanner 프로세스를 찾습니다...${NC}"
    
    local pids=$(find_process_by_name $BINARY_NAME)
    
    if [ -z "$pids" ]; then
        echo -e "${YELLOW}⚠️  실행 중인 서버가 없습니다.${NC}"
        return 1
    fi
    
    echo -e "${BLUE}🎯 실행 중인 서버를 찾았습니다.${NC}"
    
    for pid in $pids; do
        echo ""
        if [ $VERBOSE = true ]; then
            show_process_info $pid
        fi
        
        # 프로세스 종료
        if [ "$force" = true ]; then
            force_stop $pid
        else
            if ! graceful_stop $pid; then
                echo -e "${YELLOW}🔄 강제 종료를 시도합니다...${NC}"
                force_stop $pid
            fi
        fi
    done
}

# 인수 파싱
parse_args() {
    PORT=$DEFAULT_PORT
    STOP_ALL=false
    FORCE=false
    VERBOSE=false
    CHECK_STATUS=false
    
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
            -a|--all)
                STOP_ALL=true
                shift
                ;;
            -f|--force)
                FORCE=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --status)
                CHECK_STATUS=true
                shift
                ;;
            -*)
                echo -e "${RED}❌ 알 수 없는 옵션: $1${NC}"
                echo "도움말을 보려면 './stop-server.sh --help'를 실행하세요."
                exit 1
                ;;
            *)
                echo -e "${RED}❌ 잘못된 인수: $1${NC}"
                echo "도움말을 보려면 './stop-server.sh --help'를 실행하세요."
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
    echo -e "${BLUE}🛑 OSS Compliance Scanner 웹 서버 중지${NC}"
    echo "========================================"
    
    # 인수 파싱
    parse_args "$@"
    
    # 상태 확인만
    if [ "$CHECK_STATUS" = true ]; then
        check_server_status "$PORT"
        exit $?
    fi
    
    # 서버 중지
    if [ "$STOP_ALL" = true ]; then
        stop_all_servers "$FORCE"
    else
        stop_server_by_port "$PORT" "$FORCE"
    fi
    
    echo ""
    echo -e "${GREEN}🎉 서버 중지 작업이 완료되었습니다.${NC}"
}

# 스크립트 실행
main "$@" 