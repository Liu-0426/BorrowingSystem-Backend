package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"time"

	"crypto/tls"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

type NullInt64 struct {
	sql.NullInt64
}

func (n *NullInt64) UnmarshalJSON(b []byte) error {
	var x interface{}
	if err := json.Unmarshal(b, &x); err != nil {
		return err
	}
	switch v := x.(type) {
	case float64:
		n.Valid = true
		n.Int64 = int64(v)
	case string:
		var intValue int64
		if _, err := fmt.Sscan(v, &intValue); err != nil {
			return fmt.Errorf("invalid string value for NullInt64: %v", err)
		}
		n.Valid = true
		n.Int64 = intValue
	case nil:
		n.Valid = false
	default:
		return fmt.Errorf("invalid type for NullInt64: %T", v)
	}
	return nil
}

type Item struct {
	ID          int       `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	BorrowerID  NullInt64 `json:"borrower_id"`
	Borrower    string    `json:"borrower,omitempty"`
}

var jwtKey = []byte("my_secret_key")

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func generateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Hour)
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

func sendEmail(to string, subject string, body string) error {
	from := "nmg@cs.thu.edu.tw"
	password := "/"
	smtpHost := "/"
	smtpPort := 587

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", body)

	d := gomail.NewDialer(smtpHost, smtpPort, from, password)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		return fmt.Errorf("發送郵件失敗: %v", err)
	}
	return nil
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Printf("Authorization header is missing")
			c.JSON(401, gin.H{"error": "未提供授權令牌"})
			c.Abort()
			return
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			log.Printf("Token validation error: %v", err) // 加入日誌
			c.JSON(401, gin.H{"error": "無效的令牌"})
			c.Abort()
			return
		}

		c.Set("username", claims.Username)
		c.Next()
	}
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://172.24.8.156", "http://172.24.8.156:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// 從環境變數讀取資料庫連線資訊
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbName := os.Getenv("DB_NAME")

	// 建立資料庫連線字串
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s", dbUser, dbPassword, dbHost, dbPort, dbName)

	// 連線到資料庫
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}
	fmt.Println("Connected to MySQL database")

	// 開放路由
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
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginData.Password))
		if err != nil {
			c.JSON(401, gin.H{"error": "Invalid credentials"})
			return
		}

		token, err := generateJWT(user.Username)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to generate token"})
			return
		}

		c.JSON(200, gin.H{
			"user":  user,
			"token": token,
		})
	})

	// 受保護的路由
	authorized := r.Group("/")
	authorized.Use(authMiddleware())
	{
		authorized.GET("/items", func(c *gin.Context) {
			var items []Item
			query := `
			SELECT items.id, items.name, items.description, items.status, 
			       items.created_at, items.updated_at, items.borrower_id, 
			       users.username as borrower
			FROM items
			LEFT JOIN users ON items.borrower_id = users.id
		`
			rows, err := db.Query(query)
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to fetch items"})
				return
			}
			defer rows.Close()

			for rows.Next() {
				var item Item
				var createdAtRaw, updatedAtRaw []byte
				var borrower sql.NullString
				err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Status,
					&createdAtRaw, &updatedAtRaw, &item.BorrowerID, &borrower)
				//&item.ID, &item.Name, &item.Description, &item.Status, &item.CreatedAt, &item.UpdatedAt, &item.BorrowerID, &borrower
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

				if borrower.Valid {
					item.Borrower = borrower.String
				} else {
					item.Borrower = ""
				}

				items = append(items, item)
			}

			if err := rows.Err(); err != nil {
				c.JSON(500, gin.H{"error": "Failed to iterate items"})
				return
			}

			c.JSON(200, items)
		})
		authorized.POST("/items", func(c *gin.Context) {
			var item Item
			if err := c.ShouldBindJSON(&item); err != nil {
				c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
				return
			}

			_, err := db.Exec("INSERT INTO items (name, description, status, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())", item.Name, item.Description, item.Status)
			if err != nil {
				c.JSON(500, gin.H{"error": "創建項目失敗", "details": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "項創建成功"})
		})
		authorized.GET("/items/search", func(c *gin.Context) {
			term := c.Query("term")

			var items []Item
			rows, err := db.Query("SELECT id, name, description, status, created_at, updated_at, borrower_id FROM items WHERE name LIKE ?", "%"+term+"%")
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to search items"})
				return
			}
			defer rows.Close()

			for rows.Next() {
				var item Item
				var createdAtRaw, updatedAtRaw []byte
				err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Status, &createdAtRaw, &updatedAtRaw, &item.BorrowerID)
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
		authorized.PUT("/items/:id", func(c *gin.Context) {
			var item Item
			if err := c.ShouldBindJSON(&item); err != nil {
				c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
				return
			}

			itemID := c.Param("id")
			_, err := db.Exec("UPDATE items SET name = ?, description = ?, status = ?, updated_at = NOW() WHERE id = ?", item.Name, item.Description, item.Status, itemID)
			if err != nil {
				c.JSON(500, gin.H{"error": "更新項目失敗", "details": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "項目更新成功"})
		})
		authorized.DELETE("/items/:id", func(c *gin.Context) {
			itemID := c.Param("id")

			_, err := db.Exec("DELETE FROM items WHERE id = ?", itemID)
			if err != nil {
				c.JSON(500, gin.H{"error": "刪除項目失敗", "details": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "項目刪除成功"})
		})
		authorized.POST("/borrow", func(c *gin.Context) {
			var requestData struct {
				ItemID     int    `json:"item_id"`
				AdminID    string `json:"admin_id"`
				BorrowerID string `json:"borrower_id"`
				Password   string `json:"password"`
			}

			if err := c.ShouldBindJSON(&requestData); err != nil {
				fmt.Println(err.Error())
				c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
				return
			}
			fmt.Printf("接收到的借用請求: %+v\n", requestData)

			// 將 admin_id 和 borrower_id 轉換為 int
			adminID, err := strconv.Atoi(requestData.AdminID)
			if err != nil {
				c.JSON(400, gin.H{"error": "無效的 admin_id 值", "details": err.Error()})
				return
			}

			var borrowerID NullInt64
			if requestData.BorrowerID != "" {
				borrowerID.Valid = true
				borrowerID.Int64, err = strconv.ParseInt(requestData.BorrowerID, 10, 64)
				if err != nil {
					c.JSON(400, gin.H{"error": "無效的 borrower_id 值", "details": err.Error()})
					return
				}
			} else {
				borrowerID.Valid = false
			}

			// 驗證管理員密碼
			var adminPasswordHash string
			err = db.QueryRow("SELECT password FROM users WHERE id = ?", adminID).Scan(&adminPasswordHash)
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

			// 更新項目狀態和借用人ID
			_, err = db.Exec("UPDATE items SET status = 'borrowed', borrower_id = ?, updated_at = NOW() WHERE id = ?", borrowerID, requestData.ItemID)
			if err != nil {
				log.Printf("更新項目狀態時發生錯誤: %v", err)
				c.JSON(500, gin.H{"error": "更新項目狀態失敗", "details": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "項目狀態已更新為借出"})
		})
		authorized.POST("/return", func(c *gin.Context) {
			var requestData struct {
				ItemID   int    `json:"item_id"`
				Password string `json:"password"`
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
			_, err = db.Exec("UPDATE items SET status = 'available', borrower_id = NULL, updated_at = NOW() WHERE id = ?", requestData.ItemID)
			if err != nil {
				log.Printf("更新項目狀態時發生錯誤: %v", err)
				c.JSON(500, gin.H{"error": "更新項目狀態失敗", "details": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "項目狀態已更新為可用"})
		})
		authorized.POST("/reminder", func(c *gin.Context) {
			var requestData struct {
				ItemID int `json:"item_id"`
			}

			if err := c.ShouldBindJSON(&requestData); err != nil {
				c.JSON(400, gin.H{"error": "無效的 JSON 載荷", "details": err.Error()})
				return
			}

			// 查詢項目狀態及借用者郵箱
			var borrowerEmail string
			query := `
				SELECT u.email 
				FROM items i 
				JOIN users u ON i.borrower_id = u.id 
				WHERE i.id = ?
			`
			err := db.QueryRow(query, requestData.ItemID).Scan(&borrowerEmail)
			if err != nil {
				log.Printf("查詢借用者郵箱失敗: %v", err)
				c.JSON(500, gin.H{"error": "查詢借用者郵箱失敗", "details": err.Error()})
				return
			}

			// 檢查是否有借用者
			if borrowerEmail == "" {
				c.JSON(400, gin.H{"error": "該項目沒有借用者"})
				return
			}

			// 發送郵件給借用者
			subject := "催還提醒：請儘快歸還項目"
			body := "尊敬的借用者，\n\n您借用的項目已超過預定歸還日期，請儘快歸還。謝謝！"
			if err := sendEmail(borrowerEmail, subject, body); err != nil {
				log.Printf("發送郵件失敗: %v", err)
				c.JSON(500, gin.H{"error": "發送郵件失敗", "details": err.Error()})
				return
			}

			c.JSON(200, gin.H{"message": "催還郵件已發送"})
		})
		authorized.GET("/users", func(c *gin.Context) {
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
					c.JSON(500, gin.H{"error": "Failed to scan user"})
					return
				}
				users = append(users, user)
			}

			c.JSON(200, users)
		})
	}

	r.Run(":8080")
}
