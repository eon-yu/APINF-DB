package models

import "time"

type ScanJob struct {
	ID           string    `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	RepoName     string    `json:"repo_name" gorm:"column:repo_name;not null"`
	RepoPath     string    `json:"repo_path" gorm:"column:repo_path;not null"`
	ModulePath   string    `json:"module_path" gorm:"column:module_path"`
	ScanType     string    `json:"scan_type" gorm:"column:scan_type;not null"`
	Status       string    `json:"status" gorm:"column:status;not null"`
	Progress     int       `json:"progress" gorm:"column:progress;default:0"`
	Message      string    `json:"message" gorm:"column:message"`
	ErrorMessage string    `json:"error_message" gorm:"column:error_message"`
	StartedAt    time.Time `json:"started_at" gorm:"column:started_at"`
	CompletedAt  time.Time `json:"completed_at" gorm:"column:completed_at"`
	CreatedAt    time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}
