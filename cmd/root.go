package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool

	// Version information
	appVersion string
	appCommit  string
	appDate    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "oss-compliance-scanner",
	Short: "OSS Compliance Scanner for detecting vulnerabilities and license violations",
	Long: `OSS Compliance Scanner는 모노레포/MSA 환경에서 각 모듈의 
오픈소스 라이브러리 의존성을 스캔하여 취약점과 라이선스 위반을 탐지하고
Slack으로 알림을 전송하는 도구입니다.

주요 기능:
- Syft를 이용한 SBOM(Software Bill of Materials) 생성
- Grype를 이용한 취약점 스캔
- 라이선스 정책 준수 검사
- SQLite3 기반 스캔 결과 저장
- Slack 알림 연동
- Jenkins 스케줄링 지원`,
	Version: getVersionString(),
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(version, commit, date string) error {
	appVersion = version
	appCommit = commit
	appDate = date
	rootCmd.Version = getVersionString()

	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.oss-compliance-scanner.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")

	// Bind flags to viper
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := os.UserHomeDir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".oss-compliance-scanner" (without extension).
		viper.AddConfigPath(home)
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".oss-compliance-scanner")
	}

	// Environment variables
	viper.SetEnvPrefix("OSS_SCANNER")
	viper.AutomaticEnv()

	// Read configuration file
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
		}
	}
}

// getVersionString returns formatted version information
func getVersionString() string {
	if appVersion == "" {
		appVersion = "unknown"
	}
	if appCommit == "" {
		appCommit = "unknown"
	}
	if appDate == "" {
		appDate = "unknown"
	}

	return fmt.Sprintf("%s (commit: %s, date: %s)", appVersion, appCommit, appDate)
}
