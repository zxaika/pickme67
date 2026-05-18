package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	Role     string `json:"role"`
}

type Poll struct {
	ID          int       `json:"id"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	CreatedBy   int       `json:"createdBy"`
	CreatedAt   time.Time `json:"createdAt"`
	Active      bool      `json:"active"`
}

type Option struct {
	ID     int    `json:"id"`
	PollID int    `json:"pollId"`
	Text   string `json:"text"`
}

type Vote struct {
	ID          int       `json:"id"`
	PollID      int       `json:"pollId"`
	OptionID    int       `json:"optionId"`
	UserID      *int      `json:"userId"`
	GuestID     *string   `json:"guestId"`
	IP          string    `json:"ip"`
	CountryCode string    `json:"countryCode"`
	CountryName string    `json:"countryName"`
	UserAgent   string    `json:"userAgent"`
	OS          string    `json:"os"`
	VotedAt     time.Time `json:"votedAt"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

var (
	db        *sql.DB
	store     *sessions.CookieStore
	antifraud *AntiFraudSystem
)

func init() {
	sessionSecret := os.Getenv("SESSION_SECRET")
	if sessionSecret == "" {
		sessionSecret = "change-this-session-secret-in-production"
		log.Println("ВНИМАНИЕ: SESSION_SECRET не задан. Для домена обязательно задайте безопасный секрет в окружении.")
	}

	store = sessions.NewCookieStore([]byte(sessionSecret))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.EqualFold(os.Getenv("COOKIE_SECURE"), "true"),
	}
}

func main() {
	initDB()
	createAdminUser()

	antifraud = NewAntiFraudSystem()

	r := mux.NewRouter()

	r.HandleFunc("/api/register", register).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/login", login).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/logout", logout).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/polls", getAllPolls).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/polls/active", getActivePolls).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/polls/{id}/results", getPollResults).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/health", healthCheck).Methods("GET", "HEAD", "OPTIONS")
	r.Handle("/api/vote", authMiddleware(http.HandlerFunc(vote))).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/fingerprint", getFingerprint).Methods("GET", "OPTIONS")

	userRouter := r.PathPrefix("/api/user").Subrouter()
	userRouter.Use(authMiddleware)
	userRouter.HandleFunc("/my-votes", getUserVotes).Methods("GET", "OPTIONS")
	userRouter.HandleFunc("/polls", createUserPoll).Methods("POST", "OPTIONS")
	userRouter.HandleFunc("/polls", getUserCreatedPolls).Methods("GET", "OPTIONS")

	adminRouter := r.PathPrefix("/api/admin").Subrouter()
	adminRouter.Use(adminAuthMiddleware)
	adminRouter.HandleFunc("/polls", createPoll).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/polls", getAdminPolls).Methods("GET", "OPTIONS")
	adminRouter.HandleFunc("/polls/{id}/approve", approvePoll).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/polls/{id}/reject", rejectPoll).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/polls/{id}/activate", activatePoll).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/polls/{id}/deactivate", deactivatePoll).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/polls/{id}/delete", deletePoll).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/fraud-info", getFraudInfo).Methods("GET", "OPTIONS")

	adminRouter.HandleFunc("/dashboard", getAdminDashboard).Methods("GET", "OPTIONS")
	adminRouter.HandleFunc("/incidents", getIncidents).Methods("GET", "OPTIONS")
	adminRouter.HandleFunc("/rules", getRules).Methods("GET", "OPTIONS")
	adminRouter.HandleFunc("/rules", createRule).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/rules/{id}/toggle", toggleRule).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/rules/{id}/delete", deleteRule).Methods("POST", "OPTIONS")
	adminRouter.HandleFunc("/analytics", getAnalytics).Methods("GET", "OPTIONS")
	adminRouter.HandleFunc("/logs", getLogs).Methods("GET", "OPTIONS")

	// Главная страница сайта
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/public.html")
	}).Methods("GET")

	r.HandleFunc("/public-vote", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/public.html")
	}).Methods("GET")

	r.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/login.html")
	}).Methods("GET")

	r.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/admin.html")
	}).Methods("GET")

	r.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./static/user.html")
	}).Methods("GET")

	// Раздача CSS
	r.PathPrefix("/css/").Handler(
		http.StripPrefix("/css/",
			http.FileServer(http.Dir("./static/css/")),
		),
	)

	// Раздача JavaScript
	r.PathPrefix("/js/").Handler(
		http.StripPrefix("/js/",
			http.FileServer(http.Dir("./static/js/")),
		),
	)

	// Раздача изображений
	r.PathPrefix("/images/").Handler(
		http.StripPrefix("/images/",
			http.FileServer(http.Dir("./static/images/")),
		),
	)

	allowedOrigins := getAllowedOrigins()
	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
	})

	handler := c.Handler(r)

	port := getEnv("PORT", "8080")
	log.Printf("Сервер запущен на порту %s. Разрешённые домены: %s", port, strings.Join(allowedOrigins, ", "))
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./voting.db")
	if err != nil {
		log.Fatal(err)
	}

	createTables := `
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS polls (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        created_by INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        active BOOLEAN DEFAULT 0,
        status TEXT DEFAULT 'approved',
        admin_comment TEXT,
        FOREIGN KEY (created_by) REFERENCES users (id)
    );

    CREATE TABLE IF NOT EXISTS options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        FOREIGN KEY (poll_id) REFERENCES polls (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        poll_id INTEGER NOT NULL,
        option_id INTEGER NOT NULL,
        user_id INTEGER,
        guest_id TEXT,
        ip TEXT,
        country_code TEXT,
        country_name TEXT,
        user_agent TEXT,
        os TEXT,
        voted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (poll_id) REFERENCES polls (id),
        FOREIGN KEY (option_id) REFERENCES options (id),
        FOREIGN KEY (user_id) REFERENCES users (id),
        CHECK (
            (user_id IS NOT NULL AND guest_id IS NULL) OR
            (user_id IS NULL AND guest_id IS NOT NULL)
        )
    );

    CREATE INDEX IF NOT EXISTS idx_votes_guest ON votes(guest_id, poll_id);
    CREATE INDEX IF NOT EXISTS idx_votes_user ON votes(user_id, poll_id);

    CREATE TABLE IF NOT EXISTS fraud_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        fingerprint TEXT NOT NULL,
        poll_id INTEGER NOT NULL,
        reason TEXT NOT NULL,
        country_code TEXT,
        country_name TEXT,
        ip TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS fraud_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        rule_type TEXT NOT NULL,
        target_value TEXT,
        threshold INTEGER,
        window_minutes INTEGER,
        poll_id INTEGER,
        action TEXT NOT NULL DEFAULT 'block',
        active BOOLEAN DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS admin_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        level TEXT NOT NULL,
        message TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    `

	_, err = db.Exec(createTables)
	if err != nil {
		log.Fatal(err)
	}

	_, _ = db.Exec(`ALTER TABLE polls ADD COLUMN status TEXT DEFAULT 'approved'`)
	_, _ = db.Exec(`ALTER TABLE polls ADD COLUMN admin_comment TEXT`)

	_, _ = db.Exec(`ALTER TABLE votes ADD COLUMN ip TEXT`)
	_, _ = db.Exec(`ALTER TABLE votes ADD COLUMN country_code TEXT`)
	_, _ = db.Exec(`ALTER TABLE votes ADD COLUMN country_name TEXT`)
	_, _ = db.Exec(`ALTER TABLE votes ADD COLUMN user_agent TEXT`)
	_, _ = db.Exec(`ALTER TABLE votes ADD COLUMN os TEXT`)
}

func getEnv(key, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	return value
}

func getAllowedOrigins() []string {
	value := strings.TrimSpace(os.Getenv("CORS_ALLOWED_ORIGINS"))
	if value == "" {
		return []string{
			"http://localhost:8080",
			"http://pickme67.ru",
			"https://pickme67.ru",
			"http://www.pickme67.ru",
			"https://www.pickme67.ru",
			"http://pickme67.online",
			"https://pickme67.online",
			"http://www.pickme67.online",
			"https://www.pickme67.online",
		}
	}

	items := strings.Split(value, ",")
	origins := make([]string, 0, len(items))
	for _, item := range items {
		origin := strings.TrimSpace(item)
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

func createAdminUser() {
	admins := parseAdminCredentials()
	if len(admins) == 0 {
		log.Println("ВНИМАНИЕ: администраторы не заданы. Укажите ADMIN_CREDENTIALS или ADMIN_USERNAME и ADMIN_PASSWORD в окружении.")
		return
	}

	demoteAdminsNotInEnv(admins)

	for username, password := range admins {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("Ошибка хеширования пароля админа %s: %v", username, err)
			continue
		}

		var exists bool
		err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", username).Scan(&exists)
		if err != nil {
			log.Printf("Ошибка проверки админа %s: %v", username, err)
			continue
		}

		if exists {
			_, err = db.Exec("UPDATE users SET password = ?, role = 'admin' WHERE username = ?", string(hashedPassword), username)
		} else {
			_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, 'admin')", username, string(hashedPassword))
		}

		if err != nil {
			log.Printf("Ошибка сохранения админа %s: %v", username, err)
			continue
		}

		log.Printf("Администратор %s синхронизирован из окружения", username)
	}
}

func demoteAdminsNotInEnv(admins map[string]string) {
	placeholders := make([]string, 0, len(admins))
	args := make([]interface{}, 0, len(admins))
	for username := range admins {
		placeholders = append(placeholders, "?")
		args = append(args, username)
	}

	query := "UPDATE users SET role = 'user' WHERE role = 'admin'"
	if len(placeholders) > 0 {
		query += " AND username NOT IN (" + strings.Join(placeholders, ",") + ")"
	}

	if _, err := db.Exec(query, args...); err != nil {
		log.Printf("Ошибка синхронизации списка админов: %v", err)
	}
}

func parseAdminCredentials() map[string]string {
	admins := make(map[string]string)

	// Можно добавить несколько админов:
	// ADMIN_CREDENTIALS=admin:strongPassword,manager:anotherPassword
	credentials := strings.TrimSpace(os.Getenv("ADMIN_CREDENTIALS"))
	if credentials != "" {
		for _, pair := range strings.Split(credentials, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) != 2 {
				log.Printf("Пропущена неверная запись ADMIN_CREDENTIALS: %s", pair)
				continue
			}

			username := strings.TrimSpace(parts[0])
			password := strings.TrimSpace(parts[1])
			if username == "" || len(password) < 6 {
				log.Printf("Пропущен админ %s: логин пустой или пароль короче 6 символов", username)
				continue
			}

			admins[username] = password
		}
	}

	// Альтернативный вариант для одного админа:
	// ADMIN_USERNAME=admin
	// ADMIN_PASSWORD=strongPassword
	username := strings.TrimSpace(os.Getenv("ADMIN_USERNAME"))
	password := strings.TrimSpace(os.Getenv("ADMIN_PASSWORD"))
	if username != "" && password != "" {
		if len(password) < 6 {
			log.Printf("Пропущен админ %s: пароль короче 6 символов", username)
		} else {
			admins[username] = password
		}
	}

	return admins
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")

		if userID, ok := session.Values["userID"]; ok {
			var uid int
			switch v := userID.(type) {
			case int:
				uid = v
			case float64:
				uid = int(v)
			default:
				next.ServeHTTP(w, r)
				return
			}

			var user User
			err := db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", uid).
				Scan(&user.ID, &user.Username, &user.Role)

			if err == nil {
				ctx := context.WithValue(r.Context(), "user", user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

func adminAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := store.Get(r, "session")

		userID, ok := session.Values["userID"]
		if !ok {
			json.NewEncoder(w).Encode(Response{
				Success: false,
				Message: "Не авторизован",
			})
			return
		}

		var uid int
		switch v := userID.(type) {
		case int:
			uid = v
		case float64:
			uid = int(v)
		default:
			json.NewEncoder(w).Encode(Response{
				Success: false,
				Message: "Ошибка авторизации",
			})
			return
		}

		var user User
		err := db.QueryRow("SELECT id, username, role FROM users WHERE id = ?", uid).
			Scan(&user.ID, &user.Username, &user.Role)

		if err != nil {
			json.NewEncoder(w).Encode(Response{
				Success: false,
				Message: "Пользователь не найден",
			})
			return
		}

		if user.Role != "admin" {
			json.NewEncoder(w).Encode(Response{
				Success: false,
				Message: "Доступ запрещен. Требуются права администратора",
			})
			return
		}

		ctx := context.WithValue(r.Context(), "user", user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Сервер работает",
		Data: map[string]interface{}{
			"time":   time.Now(),
			"status": "ok",
		},
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	if len(req.Username) < 3 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Имя пользователя должно содержать минимум 3 символа",
		})
		return
	}

	if len(req.Password) < 6 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Пароль должен содержать минимум 6 символов",
		})
		return
	}

	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)", req.Username).Scan(&exists)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка при проверке пользователя",
		})
		return
	}

	if exists {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Пользователь с таким именем уже существует",
		})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка при создании пользователя",
		})
		return
	}

	_, err = db.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')",
		req.Username, string(hashedPassword))
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка при создании пользователя",
		})
		return
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Регистрация прошла успешно",
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req LoginRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	var user User
	var hashedPassword string
	err = db.QueryRow("SELECT id, username, password, role FROM users WHERE username = ?",
		req.Username).Scan(&user.ID, &user.Username, &hashedPassword, &user.Role)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверное имя пользователя или пароль",
		})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password))
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверное имя пользователя или пароль",
		})
		return
	}

	session, _ := store.Get(r, "session")
	session.Values["userID"] = user.ID
	session.Values["username"] = user.Username
	session.Values["role"] = user.Role

	err = session.Save(r, w)
	if err != nil {
		log.Printf("Ошибка сохранения сессии: %v", err)
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Успешный вход",
		Data: map[string]interface{}{
			"id":       user.ID,
			"username": user.Username,
			"role":     user.Role,
		},
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	session, _ := store.Get(r, "session")
	session.Values = make(map[interface{}]interface{})
	session.Save(r, w)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Выход выполнен успешно",
	})
}

func getAllPolls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
        SELECT p.id, p.title, p.description, p.created_at, p.active, p.status,
               COALESCE(u.username, 'Админ') as creator
        FROM polls p
        LEFT JOIN users u ON p.created_by = u.id
        WHERE p.status != 'rejected'
        ORDER BY p.created_at DESC
    `)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки голосований",
		})
		return
	}
	defer rows.Close()

	var polls []map[string]interface{}
	for rows.Next() {
		var id int
		var title, description, creator, status string
		var createdAt time.Time
		var active bool

		err := rows.Scan(&id, &title, &description, &createdAt, &active, &status, &creator)
		if err != nil {
			continue
		}

		polls = append(polls, map[string]interface{}{
			"id":          id,
			"title":       title,
			"description": description,
			"createdAt":   createdAt,
			"active":      active,
			"status":      status,
			"creator":     creator,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    polls,
	})
}

func getActivePolls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
        SELECT p.id, p.title, p.description, p.created_at, p.active, p.status,
               COALESCE(u.username, 'Админ') as creator
        FROM polls p
        LEFT JOIN users u ON p.created_by = u.id
        WHERE p.active = 1 AND p.status = 'approved'
        ORDER BY p.created_at DESC
    `)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки голосований",
		})
		return
	}
	defer rows.Close()

	var polls []map[string]interface{}
	for rows.Next() {
		var id int
		var title, description, creator, status string
		var createdAt time.Time
		var active bool

		err := rows.Scan(&id, &title, &description, &createdAt, &active, &status, &creator)
		if err != nil {
			continue
		}

		polls = append(polls, map[string]interface{}{
			"id":          id,
			"title":       title,
			"description": description,
			"createdAt":   createdAt,
			"active":      active,
			"status":      status,
			"creator":     creator,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    polls,
	})
}

func vote(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user, ok := r.Context().Value("user").(User)
	var userID *int
	if ok && user.ID > 0 {
		userID = &user.ID
	}

	var voteData struct {
		PollID   int `json:"pollId"`
		OptionID int `json:"optionId"`
	}

	err := json.NewDecoder(r.Body).Decode(&voteData)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	var pollExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM polls WHERE id = ?)", voteData.PollID).Scan(&pollExists)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка проверки голосования",
		})
		return
	}

	if !pollExists {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Голосование не найдено",
		})
		return
	}

	var active bool
	var status string
	err = db.QueryRow("SELECT active, status FROM polls WHERE id = ?", voteData.PollID).Scan(&active, &status)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка проверки статуса голосования",
		})
		return
	}

	if status != "approved" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Голосование еще не одобрено администратором",
		})
		return
	}

	if !active {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Голосование недоступно",
		})
		return
	}

	var optionExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM options WHERE id = ? AND poll_id = ?)",
		voteData.OptionID, voteData.PollID).Scan(&optionExists)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка проверки варианта ответа",
		})
		return
	}

	if !optionExists {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Выбранный вариант не найден",
		})
		return
	}

	allowed, message := antifraud.IsAllowed(r, voteData.PollID, userID)
	if !allowed {
		voterInfo := antifraud.GetVoterInfo(r)
		fingerprint := antifraud.GetFingerprint(r)

		db.Exec(
			"INSERT INTO fraud_alerts (fingerprint, poll_id, reason, country_code, country_name, ip, details) VALUES (?, ?, ?, ?, ?, ?, ?)",
			fingerprint,
			voteData.PollID,
			message,
			voterInfo["country_code"],
			voterInfo["country"],
			voterInfo["checked_ip"],
			toJSONString(voterInfo),
		)

		logAdminEvent("warning", "Заблокирована попытка голосования: "+message)

		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: message,
		})
		return
	}

	voterInfo := antifraud.GetVoterInfo(r)
	ip := voterInfo["checked_ip"]
	countryCode := voterInfo["country_code"]
	countryName := voterInfo["country"]
	userAgent := voterInfo["user_agent"]
	osName := voterInfo["os"]

	if userID != nil {
		_, err = db.Exec(`
			INSERT INTO votes (poll_id, option_id, user_id, ip, country_code, country_name, user_agent, os)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`,
			voteData.PollID,
			voteData.OptionID,
			userID,
			ip,
			countryCode,
			countryName,
			userAgent,
			osName,
		)
	} else {
		guestID := antifraud.GetFingerprint(r)
		_, err = db.Exec(`
			INSERT INTO votes (poll_id, option_id, guest_id, ip, country_code, country_name, user_agent, os)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`,
			voteData.PollID,
			voteData.OptionID,
			guestID,
			ip,
			countryCode,
			countryName,
			userAgent,
			osName,
		)
	}

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка при сохранении голоса: " + err.Error(),
		})
		return
	}

	logAdminEvent("info", "Голос успешно учтен")
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Голос успешно учтен",
	})
}

func getUserVotes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user, ok := r.Context().Value("user").(User)
	if !ok || user.ID == 0 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Необходимо авторизоваться для просмотра истории голосований",
		})
		return
	}

	rows, err := db.Query(`
        SELECT p.id, p.title, o.text, v.voted_at
        FROM votes v
        JOIN polls p ON v.poll_id = p.id
        JOIN options o ON v.option_id = o.id
        WHERE v.user_id = ?
        ORDER BY v.voted_at DESC
    `, user.ID)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки истории голосования",
		})
		return
	}
	defer rows.Close()

	var votes []map[string]interface{}
	for rows.Next() {
		var pollID int
		var pollTitle, optionText string
		var votedAt time.Time

		err := rows.Scan(&pollID, &pollTitle, &optionText, &votedAt)
		if err != nil {
			continue
		}

		votes = append(votes, map[string]interface{}{
			"pollId":    pollID,
			"pollTitle": pollTitle,
			"option":    optionText,
			"votedAt":   votedAt,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    votes,
	})
}

func createPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user, ok := r.Context().Value("user").(User)
	if !ok {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Не авторизован",
		})
		return
	}

	var pollData struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Options     []string `json:"options"`
	}

	err := json.NewDecoder(r.Body).Decode(&pollData)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	if len(pollData.Options) < 2 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Должно быть минимум 2 варианта ответа",
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка создания голосования",
		})
		return
	}

	result, err := tx.Exec(
		"INSERT INTO polls (title, description, created_by, status, active) VALUES (?, ?, ?, 'approved', 0)",
		pollData.Title, pollData.Description, user.ID,
	)

	if err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка создания голосования",
		})
		return
	}

	pollID, _ := result.LastInsertId()

	for _, opt := range pollData.Options {
		_, err = tx.Exec("INSERT INTO options (poll_id, text) VALUES (?, ?)", pollID, opt)
		if err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(Response{
				Success: false,
				Message: "Ошибка добавления вариантов",
			})
			return
		}
	}

	err = tx.Commit()
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка сохранения голосования",
		})
		return
	}

	logAdminEvent("info", "Администратор создал голосование: "+pollData.Title)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Голосование успешно создано",
		Data: map[string]interface{}{
			"pollId": pollID,
		},
	})
}

func createUserPoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user, ok := r.Context().Value("user").(User)
	if !ok || user.ID == 0 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Необходимо авторизоваться",
		})
		return
	}

	var pollData struct {
		Title       string   `json:"title"`
		Description string   `json:"description"`
		Options     []string `json:"options"`
	}

	err := json.NewDecoder(r.Body).Decode(&pollData)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Неверный формат запроса",
		})
		return
	}

	if pollData.Title == "" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Введите название голосования",
		})
		return
	}

	if len(pollData.Options) < 2 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Должно быть минимум 2 варианта ответа",
		})
		return
	}

	tx, err := db.Begin()
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка создания заявки",
		})
		return
	}

	result, err := tx.Exec(
		"INSERT INTO polls (title, description, created_by, status, active) VALUES (?, ?, ?, 'pending', 0)",
		pollData.Title, pollData.Description, user.ID,
	)
	if err != nil {
		tx.Rollback()
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка создания заявки",
		})
		return
	}

	pollID, _ := result.LastInsertId()

	for _, opt := range pollData.Options {
		_, err = tx.Exec("INSERT INTO options (poll_id, text) VALUES (?, ?)", pollID, opt)
		if err != nil {
			tx.Rollback()
			json.NewEncoder(w).Encode(Response{
				Success: false,
				Message: "Ошибка добавления вариантов",
			})
			return
		}
	}

	if err = tx.Commit(); err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка сохранения заявки",
		})
		return
	}

	logAdminEvent("info", "Пользователь "+user.Username+" создал заявку на голосование: "+pollData.Title)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Голосование отправлено на одобрение",
	})
}

func getUserCreatedPolls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	user, ok := r.Context().Value("user").(User)
	if !ok || user.ID == 0 {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Необходимо авторизоваться",
		})
		return
	}

	rows, err := db.Query(`
        SELECT p.id, p.title, p.description, p.created_at, p.active, p.status, COALESCE(p.admin_comment, ''),
               COUNT(DISTINCT v.id) as total_votes
        FROM polls p
        LEFT JOIN votes v ON p.id = v.poll_id
        WHERE p.created_by = ?
        GROUP BY p.id
        ORDER BY p.created_at DESC
    `, user.ID)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки пользовательских голосований",
		})
		return
	}
	defer rows.Close()

	var polls []map[string]interface{}
	for rows.Next() {
		var id int
		var title, description, status, adminComment string
		var createdAt time.Time
		var active bool
		var totalVotes int

		if err := rows.Scan(&id, &title, &description, &createdAt, &active, &status, &adminComment, &totalVotes); err != nil {
			continue
		}

		polls = append(polls, map[string]interface{}{
			"id":           id,
			"title":        title,
			"description":  description,
			"createdAt":    createdAt,
			"active":       active,
			"status":       status,
			"adminComment": adminComment,
			"totalVotes":   totalVotes,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    polls,
	})
}

func getAdminPolls(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
        SELECT p.id, p.title, p.description, p.created_at, p.active, p.status,
               COALESCE(p.admin_comment, ''),
               COUNT(DISTINCT v.id) as total_votes,
               u.id, u.username, u.role
        FROM polls p
        LEFT JOIN votes v ON p.id = v.poll_id
        LEFT JOIN users u ON p.created_by = u.id
        GROUP BY p.id
        ORDER BY 
            CASE p.status 
                WHEN 'pending' THEN 0
                WHEN 'approved' THEN 1
                WHEN 'rejected' THEN 2
                ELSE 3
            END,
            p.created_at DESC
    `)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки голосований",
		})
		return
	}
	defer rows.Close()

	var polls []map[string]interface{}
	for rows.Next() {
		var id int
		var title, description, status, adminComment string
		var createdAt time.Time
		var active bool
		var totalVotes int
		var authorID int
		var authorUsername, authorRole string

		err := rows.Scan(&id, &title, &description, &createdAt, &active, &status, &adminComment, &totalVotes, &authorID, &authorUsername, &authorRole)
		if err != nil {
			continue
		}

		optRows, err := db.Query("SELECT id, text FROM options WHERE poll_id = ?", id)
		if err != nil {
			continue
		}

		var options []map[string]interface{}
		for optRows.Next() {
			var optID int
			var optText string
			optRows.Scan(&optID, &optText)
			options = append(options, map[string]interface{}{
				"id":   optID,
				"text": optText,
			})
		}
		optRows.Close()

		polls = append(polls, map[string]interface{}{
			"id":           id,
			"title":        title,
			"description":  description,
			"createdAt":    createdAt,
			"active":       active,
			"status":       status,
			"adminComment": adminComment,
			"totalVotes":   totalVotes,
			"options":      options,
			"author": map[string]interface{}{
				"id":       authorID,
				"username": authorUsername,
				"role":     authorRole,
			},
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    polls,
	})
}

func approvePoll(w http.ResponseWriter, r *http.Request) {
	handlePollModeration(w, r, "approved")
}

func rejectPoll(w http.ResponseWriter, r *http.Request) {
	handlePollModeration(w, r, "rejected")
}

func handlePollModeration(w http.ResponseWriter, r *http.Request, status string) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	pollID := vars["id"]

	var req struct {
		AdminComment string `json:"adminComment"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM polls WHERE id = ?)", pollID).Scan(&exists)
	if err != nil || !exists {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Голосование не найдено",
		})
		return
	}

	_, err = db.Exec("UPDATE polls SET status = ?, active = 0, admin_comment = ? WHERE id = ?", status, req.AdminComment, pollID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка обновления статуса голосования",
		})
		return
	}

	actionText := "одобрено"
	if status == "rejected" {
		actionText = "отклонено"
	}

	logAdminEvent("warning", "Голосование ID="+pollID+" было "+actionText)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Голосование успешно " + actionText,
	})
}

func activatePoll(w http.ResponseWriter, r *http.Request) {
	handlePollActivation(w, r, true)
}

func deactivatePoll(w http.ResponseWriter, r *http.Request) {
	handlePollActivation(w, r, false)
}

func handlePollActivation(w http.ResponseWriter, r *http.Request, active bool) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	pollID := vars["id"]

	var status string
	err := db.QueryRow("SELECT status FROM polls WHERE id = ?", pollID).Scan(&status)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Голосование не найдено",
		})
		return
	}

	if status != "approved" {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Сначала нужно одобрить голосование",
		})
		return
	}

	_, err = db.Exec("UPDATE polls SET active = ? WHERE id = ?", active, pollID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка обновления статуса",
		})
		return
	}

	action := "активировано"
	if !active {
		action = "деактивировано"
	}

	logAdminEvent("info", "Голосование ID="+pollID+" было "+action)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Голосование успешно " + action,
	})
}

func deletePoll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	pollID := vars["id"]

	_, err := db.Exec("DELETE FROM polls WHERE id = ?", pollID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка при удалении голосования",
		})
		return
	}

	logAdminEvent("warning", "Удалено голосование ID="+pollID)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "Голосование успешно удалено",
	})
}

func getPollResults(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	vars := mux.Vars(r)
	pollID := vars["id"]

	var poll struct {
		Title       string
		Description string
		Active      bool
		Status      string
	}
	err := db.QueryRow("SELECT title, description, active, status FROM polls WHERE id = ?", pollID).
		Scan(&poll.Title, &poll.Description, &poll.Active, &poll.Status)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Голосование не найдено",
		})
		return
	}

	var totalVotes int
	err = db.QueryRow("SELECT COUNT(*) FROM votes WHERE poll_id = ?", pollID).Scan(&totalVotes)
	if err != nil {
		totalVotes = 0
	}

	rows, err := db.Query(`
        SELECT o.id, o.text, 
               COUNT(v.id) as votes,
               CASE 
                   WHEN ? = 0 THEN 0
                   ELSE ROUND(COUNT(v.id) * 100.0 / ?, 2)
               END as percentage
        FROM options o
        LEFT JOIN votes v ON o.id = v.option_id
        WHERE o.poll_id = ?
        GROUP BY o.id
        ORDER BY o.id
    `, totalVotes, totalVotes, pollID)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки результатов",
		})
		return
	}
	defer rows.Close()

	var options []map[string]interface{}
	for rows.Next() {
		var id int
		var text string
		var votes int
		var percentage float64

		err := rows.Scan(&id, &text, &votes, &percentage)
		if err != nil {
			continue
		}

		options = append(options, map[string]interface{}{
			"id":         id,
			"text":       text,
			"votes":      votes,
			"percentage": percentage,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data: map[string]interface{}{
			"title":       poll.Title,
			"description": poll.Description,
			"active":      poll.Active,
			"status":      poll.Status,
			"totalVotes":  totalVotes,
			"options":     options,
		},
	})
}

func getFingerprint(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	info := antifraud.GetVoterInfo(r)

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    info,
	})
}

func getFraudInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
        SELECT 
            v.id,
            v.poll_id,
            p.title,
            o.text,
            COALESCE(v.guest_id, ''),
            COALESCE(v.ip, ''),
            COALESCE(v.country_code, ''),
            COALESCE(v.country_name, ''),
            COALESCE(v.os, ''),
            COALESCE(v.user_agent, ''),
            v.voted_at,
            CASE 
                WHEN v.user_id IS NOT NULL THEN u.username
                ELSE 'Гость'
            END as voter_name
        FROM votes v
        JOIN polls p ON v.poll_id = p.id
        JOIN options o ON v.option_id = o.id
        LEFT JOIN users u ON v.user_id = u.id
        ORDER BY v.voted_at DESC
        LIMIT 300
    `)

	if err != nil {
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Ошибка загрузки данных",
		})
		return
	}
	defer rows.Close()

	var votes []map[string]interface{}
	for rows.Next() {
		var id, pollID int
		var pollTitle, optionText, guestID, ip, countryCode, countryName, osName, userAgent, voterName string
		var votedAt time.Time

		err := rows.Scan(
			&id,
			&pollID,
			&pollTitle,
			&optionText,
			&guestID,
			&ip,
			&countryCode,
			&countryName,
			&osName,
			&userAgent,
			&votedAt,
			&voterName,
		)
		if err != nil {
			continue
		}

		votes = append(votes, map[string]interface{}{
			"id":           id,
			"poll_id":      pollID,
			"poll_title":   pollTitle,
			"option_text":  optionText,
			"guest_id":     guestID,
			"ip":           ip,
			"country_code": countryCode,
			"country_name": countryName,
			"os":           osName,
			"user_agent":   userAgent,
			"voter_name":   voterName,
			"voted_at":     votedAt,
		})
	}

	json.NewEncoder(w).Encode(Response{
		Success: true,
		Data:    votes,
	})
}
