package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"` // 添加 role 屬性
}

type Item struct {
	ID          int       `json:"id"`
	OwnerID     int       `json:"owner_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func main() {
	r := gin.Default()

	// Enable CORS for all origins
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://172.24.8.156:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Connect to MySQL database
	db, err := sql.Open("mysql", "admin:J;3ej032k7todolist@tcp(localhost:3306)/BorrowingSystem")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Ping database to ensure it's working
	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("Connected to MySQL database")

	// Define routes
	r.POST("/login", func(c *gin.Context) {
		var loginData struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := c.ShouldBindJSON(&loginData); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON payload"})
			return
		}

		if loginData.Username == "" || loginData.Password == "" {
			c.JSON(400, gin.H{"error": "Username and password cannot be empty"})
			return
		}

		var user User
		var hashedPassword string
		row := db.QueryRow("SELECT id, username, email, role, password FROM users WHERE username = ?", loginData.Username)
		err := row.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &hashedPassword)
		if err != nil {
			log.Printf("Error fetching user from database: %v", err)
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		log.Printf("Fetched user: %+v", user)

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginData.Password))
		if err != nil {
			log.Printf("Password mismatch: %v", err)
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		token, err := generateJWT(user.Username)
		if err != nil {
			log.Printf("Error generating token: %v", err)
			c.JSON(500, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(200, gin.H{
			"user":  user,
			"token": token,
		})
	})

	r.POST("/register", func(c *gin.Context) {
		var registerData struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Email    string `json:"email"`
			Role     string `json:"role"` // 添加 role 欄位
		}
		if err := c.ShouldBindJSON(&registerData); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON payload"})
			return
		}

		if registerData.Username == "" || registerData.Password == "" || registerData.Email == "" || registerData.Role == "" {
			c.JSON(400, gin.H{"error": "Username, password, email, and role cannot be empty"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerData.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to hash password"})
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", registerData.Username, hashedPassword, registerData.Email, registerData.Role)
		if err != nil {
			log.Printf("Error inserting user into database: %v", err)
			c.JSON(500, gin.H{"error": "Failed to register user"})
			return
		}

		token, err := generateJWT(registerData.Username)
		if err != nil {
			log.Printf("Error generating token: %v", err)
			c.JSON(500, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(200, gin.H{
			"user": gin.H{
				"username": registerData.Username,
				"email":    registerData.Email,
				"role":     registerData.Role, // 返回 role
			},
			"token": token,
		})
	})

	// 新增一个获取所有items的路由
	r.GET("/items", func(c *gin.Context) {
		var items []Item
		rows, err := db.Query("SELECT id, owner_id, name, description, status, created_at, updated_at FROM items")
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch items"})
			return
		}
		defer rows.Close()

		for rows.Next() {
			var item Item
			var createdAtRaw, updatedAtRaw []byte
			err := rows.Scan(&item.ID, &item.OwnerID, &item.Name, &item.Description, &item.Status, &createdAtRaw, &updatedAtRaw)
			if err != nil {
				log.Printf("Error scanning item: %v", err)
				c.JSON(500, gin.H{"error": "Failed to scan item"})
				return
			}

			item.CreatedAt, err = time.Parse("2006-01-02 15:04:05", string(createdAtRaw))
			if err != nil {
				log.Printf("Error parsing created_at: %v", err)
				c.JSON(500, gin.H{"error": "Failed to parse created_at"})
				return
			}

			item.UpdatedAt, err = time.Parse("2006-01-02 15:04:05", string(updatedAtRaw))
			if err != nil {
				log.Printf("Error parsing updated_at: %v", err)
				c.JSON(500, gin.H{"error": "Failed to parse updated_at"})
				return
			}

			items = append(items, item)
		}

		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": "Failed to iterate items"})
			return
		}

		c.JSON(200, items)
	})

	// Run the server
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
