package cmd

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"oss-compliance-scanner/config"
	"oss-compliance-scanner/db"
	"oss-compliance-scanner/web"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "웹 대시보드 서버 시작",
	Long:  `OSS Compliance Scanner의 웹 대시보드를 시작합니다. 브라우저를 통해 SBOM, 취약점, 정책을 관리할 수 있습니다.`,
	Run:   runServer,
}

var (
	serverPort string
)

func init() {
	rootCmd.AddCommand(serverCmd)

	serverCmd.Flags().StringVarP(&serverPort, "port", "p", "8080", "웹 서버 포트")
}

func runServer(cmd *cobra.Command, args []string) {
	// 설정 로드
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// 데이터베이스 연결
	database, err := db.NewDatabase(cfg.Database.Driver, cfg.Database.GetDSN())
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer database.Close()

	// 웹 서버 생성
	server := web.NewServer(database, serverPort)

	// Graceful shutdown 설정
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down server...")
		if err := server.Stop(); err != nil {
			log.Printf("Server forced to shutdown: %v", err)
		}
		os.Exit(0)
	}()

	// 서버 시작
	log.Printf("Starting OSS Compliance Dashboard on port %s", serverPort)
	log.Printf("Dashboard URL: http://localhost:%s", serverPort)
	log.Printf("API URL: http://localhost:%s/api/v1", serverPort)

	if err := server.Start(); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
