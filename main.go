
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
			fmt.Printf("Login with empty data")
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
		rows, err := db.Query("SELECT id, name, description, status, created_at, updated_at FROM items")
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch items"})
			return
		}
		defer rows.Close()

		for rows.Next() {
			var item Item
			var createdAtRaw, updatedAtRaw []byte
			err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Status, &createdAtRaw, &updatedAtRaw)
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
	// 新增項目
	r.POST("/items", func(c *gin.Context) {
		var item Item
		if err := c.ShouldBindJSON(&item); err != nil {
			c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
			return
		}

		fmt.Printf("接收到的項目數據: %+v\n", item)

		// 確保 status 欄位值有效
		validStatuses := map[string]bool{
			"available": true,
			"borrowed":  true,
		}
		if !validStatuses[item.Status] {
			c.JSON(400, gin.H{"error": "無效的 status 值"})
			return
		}

		_, err = db.Exec("INSERT INTO items (name, description, status, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())", item.Name, item.Description, item.Status)
		if err != nil {
			log.Printf("將項目插入數據庫時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "創建項目失敗", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "項目創建成功"})
	})

	// New endpoint to update an item
	// 更新項目
	r.PUT("/items/:id", func(c *gin.Context) {
		var item Item
		if err := c.ShouldBindJSON(&item); err != nil {
			c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
			return
		}
		fmt.Printf("接收到的PUT: %+v\n", item)

		itemID := c.Param("id")

		// 確保 status 欄位值有效
		validStatuses := map[string]bool{
			"available": true,
			"borrowed":  true,
		}
		if !validStatuses[item.Status] {
			c.JSON(400, gin.H{"error": "無效的 status 值"})
			return
		}

		_, err := db.Exec("UPDATE items SET name = ?, description = ?, status = ?, updated_at = NOW() WHERE id = ?", item.Name, item.Description, item.Status, itemID)
		if err != nil {
			log.Printf("更新項目數據庫時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "更新項目失敗", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "項目更新成功"})
	})

	// New endpoint to delete an item
	// 刪除項目
	r.DELETE("/items/:id", func(c *gin.Context) {
		itemID := c.Param("id")

		_, err := db.Exec("DELETE FROM items WHERE id = ?", itemID)
		if err != nil {
			log.Printf("從數據庫中刪除項目時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "刪除項目失敗", "details": err.Error()})
			return
		}

		c.JSON(200, gin.H{"message": "項目刪除成功"})
	})

	// Existing GET items/search endpoint
	r.GET("/items/search", func(c *gin.Context) {
		term := c.Query("term")
	
		var items []Item
		rows, err := db.Query("SELECT id, name, description, status, created_at, updated_at FROM items WHERE name LIKE ?", "%"+term+"%")
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to search items"})
			return
		}
		defer rows.Close()
	
		for rows.Next() {
			var item Item
			var createdAtRaw, updatedAtRaw []byte
			err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Status, &createdAtRaw, &updatedAtRaw)
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

	// 新增端點來回傳使用者列表
	r.GET("/users", func(c *gin.Context) {
		role := c.Query("role")
	
		var users []User
		var rows *sql.Rows
		var err error
	
		if role == "" {
			rows, err = db.Query("SELECT id, username, role FROM users")
		} else {
			rows, err = db.Query("SELECT id, username, role FROM users WHERE role = ?", role)
		}
	
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to fetch users"})
			return
		}
		defer rows.Close()
	
		for rows.Next() {
			var user User
			err := rows.Scan(&user.ID, &user.Username, &user.Role)
			if err != nil {
				log.Printf("Error scanning user: %v", err)
				c.JSON(500, gin.H{"error": "Failed to scan user"})
				return
			}
			users = append(users, user)
		}
	
		if err := rows.Err(); err != nil {
			c.JSON(500, gin.H{"error": "Failed to iterate users"})
			return
		}
	
		c.JSON(200, users)
	})

	// New endpoint to borrow an item
	r.POST("/borrow", func(c *gin.Context) {
		var requestData struct {
			ItemID       int    `json:"item_id"`
			AdminUsername string `json:"admin_username"`
			Password     string `json:"password"`
		}
	
		if err := c.ShouldBindJSON(&requestData); err != nil {
			fmt.Println(err.Error())
			c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
			return
		}
		fmt.Printf("接收到的借用請求: %+v\n", requestData)
	
		// 驗證管理員密碼
		var adminPasswordHash string
		err := db.QueryRow("SELECT password FROM users WHERE username = 'admin'").Scan(&adminPasswordHash)
		if err != nil {
			log.Printf("查詢管理員密碼時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "查詢管理員密碼失敗", "details": err.Error()})
			return
		}
	
		err = bcrypt.CompareHashAndPassword([]byte(adminPasswordHash), []byte(requestData.Password))
		if err != nil {
			log.Printf("管理員密碼不正確: %v", err)
			c.JSON(401, gin.H{"error": "管理員密碼不正確"})
			return
		}
	
		// 查詢項目狀態
		var status string
		err = db.QueryRow("SELECT status FROM items WHERE id = ?", requestData.ItemID).Scan(&status)
		if err != nil {
			log.Printf("查詢項目狀態時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "查詢項目狀態失敗", "details": err.Error()})
			return
		}
	
		if status == "borrowed" {
			c.JSON(400, gin.H{"error": "該項目已被借出"})
			return
		}
	
		// 更新項目狀態
		_, err = db.Exec("UPDATE items SET status = 'borrowed', updated_at = NOW() WHERE id = ?", requestData.ItemID)
		if err != nil {
			log.Printf("更新項目狀態時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "更新項目狀態失敗", "details": err.Error()})
			return
		}
	
		c.JSON(200, gin.H{"message": "項目狀態已更新為借出"})
	})
	r.POST("/return", func(c *gin.Context) {
		var requestData struct {
			ItemID     int    `json:"item_id"`
			Password   string `json:"password"`
		}
		
		if err := c.ShouldBindJSON(&requestData); err != nil {
			fmt.Println(err.Error())
			c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
			return
		}
		fmt.Printf("接收到的歸還請求: %+v\n", requestData)
	
		// 驗證管理員密碼
		var adminPasswordHash string
		err := db.QueryRow("SELECT password FROM users WHERE username = 'admin'").Scan(&adminPasswordHash)
		if err != nil {
			log.Printf("查詢管理員密碼時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "查詢管理員密碼失敗", "details": err.Error()})
			return
		}
	
		err = bcrypt.CompareHashAndPassword([]byte(adminPasswordHash), []byte(requestData.Password))
		if err != nil {
			log.Printf("管理員密碼不正確: %v", err)
			c.JSON(401, gin.H{"error": "管理員密碼不正確"})
			return
		}
	
		// 查詢項目狀態
		var status string
		err = db.QueryRow("SELECT status FROM items WHERE id = ?", requestData.ItemID).Scan(&status)
		if err != nil {
			log.Printf("查詢項目狀態時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "查詢項目狀態失敗", "details": err.Error()})
			return
		}
	
		if status != "borrowed" {
			c.JSON(400, gin.H{"error": "該項目未被借出"})
			return
		}
	
		// 更新項目狀態
		_, err = db.Exec("UPDATE items SET status = 'available', updated_at = NOW() WHERE id = ?", requestData.ItemID)
		if err != nil {
			log.Printf("更新項目狀態時發生錯誤: %v", err)
			c.JSON(500, gin.H{"error": "更新項目狀態失敗", "details": err.Error()})
			return
		}
	
		c.JSON(200, gin.H{"message": "項目狀態已更新為可用"})
	})
	

	
	r.Run(":8080")
}