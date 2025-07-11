package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

var (
	requestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "endpoint"},
	)
)

func init() {
	prometheus.MustRegister(requestCount)
}

type User struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	Created  time.Time `json:"created"`
}

// JWT Claims struct
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	logrus.Info("Starting Go test application")

	// Using Gin framework
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		requestCount.WithLabelValues("GET", "/").Inc()
		c.JSON(http.StatusOK, gin.H{
			"message":   "Go test application for OSS compliance scanning",
			"timestamp": time.Now().Format(time.RFC3339),
			"version":   "1.0.0",
		})
	})

	r.GET("/users", func(c *gin.Context) {
		requestCount.WithLabelValues("GET", "/users").Inc()
		users := []User{
			{
				ID:       uuid.New().String(),
				Username: "testuser1",
				Email:    "test1@example.com",
				Created:  time.Now(),
			},
			{
				ID:       uuid.New().String(),
				Username: "testuser2",
				Email:    "test2@example.com",
				Created:  time.Now(),
			},
		}
		c.JSON(http.StatusOK, users)
	})

	r.POST("/login", func(c *gin.Context) {
		requestCount.WithLabelValues("POST", "/login").Inc()
		var loginData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Generate JWT token (using vulnerable library)
		claims := &Claims{
			Username: loginData.Username,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString([]byte("secret-key"))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": tokenString})
	})

	// Prometheus metrics endpoint
	r.GET("/metrics", gin.WrapH(promhttp.Handler()))

	// Alternative using Gorilla Mux
	muxRouter := mux.NewRouter()
	muxRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "healthy", "timestamp": "` + time.Now().Format(time.RFC3339) + `"}`))
	})

	go func() {
		log.Println("Starting Gorilla Mux server on :8081")
		log.Fatal(http.ListenAndServe(":8081", muxRouter))
	}()

	log.Println("Starting Gin server on :8080")
	r.Run(":8080")
}
