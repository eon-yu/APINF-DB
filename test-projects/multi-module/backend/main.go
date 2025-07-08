package main

import (
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func main() {
	// Initialize Gin router
	r := gin.Default()

	// Sample endpoint
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
			"time":    time.Now(),
			"uuid":    uuid.New(),
		})
	})

	// JWT token generation endpoint
	r.POST("/auth", func(c *gin.Context) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": "test",
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})

		tokenString, err := token.SignedString([]byte("secret"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Database connection example (not actually connected)
	dsn := "host=localhost user=test password=test dbname=test port=5432 sslmode=disable"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logrus.Warn("Database connection failed:", err)
	} else {
		logrus.Info("Database connection established")
		_ = db // Use db variable to avoid unused warning
	}

	// Redis client example (not actually connected)
	rdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "", // no password
		DB:       0,  // default DB
	})
	_ = rdb // Use rdb variable to avoid unused warning

	logrus.Info("Starting backend server on :8080")
	r.Run(":8080")
}
