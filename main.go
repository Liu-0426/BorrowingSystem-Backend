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
	Role     string `json:"role"`
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

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://172.24.8.156:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	db, err := sql.Open("mysql", "admin:J;3ej032k7todolist@tcp(localhost:3306)/BorrowingSystem")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("Connected to MySQL database")

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
			Role     string `json:"role"`
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
				"role":     registerData.Role,
			},
			"token": token,
		})
	})

	// Existing GET items endpoint
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

	// New endpoint to create an item
	r.POST("/items", func(c *gin.Context) {
		var item Item
		if err := c.ShouldBindJSON(&item); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON payload", "details": err.Error()})
			return
		}

		// 打印接收到的資料
		fmt.Printf("Received item data: %+v\n", item)

		// 檢查 owner_id 是否存在於 users 表中
		var userExists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)", item.OwnerID).Scan(&userExists)
		if err != nil {
			log.Printf("Error checking user existence: %v", err)
			c.JSON(500, gin.H{"error": "Failed to check user existence", "details": err.Error()})
			return
		}

		if !userExists {
			c.JSON(400, gin.H{"error": "Invalid owner_id"})
			return
		}

		_, err = db.Exec("INSERT INTO items (owner_id, name, description, status, created_at, updated_at) VALUES (?, ?, ?, ?, NOW(), NOW())", item.OwnerID, item.Name, item.Description, item.Status)
		if err != nil {
			log.Printf("Error inserting item into database: %v", err)
			c.JSON(500, gin.H{"error": "Failed to create item", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "Item created successfully"})
	})

	// New endpoint to update an item
	r.PUT("/items/:id", func(c *gin.Context) {
		var item Item
		if err := c.ShouldBindJSON(&item); err != nil {
			c.JSON(400, gin.H{"error": "Invalid JSON payload", "details": err.Error()})
			return
		}

		fmt.Printf("Received item data for update: %+v\n", item)

		itemId := c.Param("id")

		var userExists bool
		err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = ?)", item.OwnerID).Scan(&userExists)
		if err != nil {
			log.Printf("Error checking user existence: %v", err)
			c.JSON(500, gin.H{"error": "Failed to check user existence", "details": err.Error()})
			return
		}

		if !userExists {
			c.JSON(400, gin.H{"error": "Invalid owner_id"})
			return
		}

		_, err = db.Exec("UPDATE items SET owner_id = ?, name = ?, description = ?, status = ?, updated_at = NOW() WHERE id = ?", item.OwnerID, item.Name, item.Description, item.Status, itemId)
		if err != nil {
			log.Printf("Error updating item in database: %v", err)
			c.JSON(500, gin.H{"error": "Failed to update item", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "Item updated successfully"})
	})

	// New endpoint to delete an item
	r.DELETE("/items/:id", func(c *gin.Context) {
		id := c.Param("id")

		_, err := db.Exec("DELETE FROM items WHERE id = ?", id)
		if err != nil {
			log.Printf("Error deleting item from database: %v", err)
			c.JSON(500, gin.H{"error": "Failed to delete item"})
			return
		}

		c.JSON(200, gin.H{"message": "Item deleted successfully"})
	})

	// New endpoint to search items
	r.GET("/items/search", func(c *gin.Context) {
		query := c.Query("q")
		var items []Item
		searchQuery := "%" + query + "%"
		rows, err := db.Query("SELECT id, owner_id, name, description, status, created_at, updated_at FROM items WHERE name LIKE ? OR description LIKE ?", searchQuery, searchQuery)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to search items"})
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

	r.Run(":8080")
}
