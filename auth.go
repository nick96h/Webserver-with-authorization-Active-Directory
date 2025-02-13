package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"os"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
)

// Структура для хранения данных пользователя
type User struct {
	Username string
}

// Структура для сообщения об ошибке авторизации
type LoginPageData struct {
	ErrorMessage string
}

// Конфигурация для хранения сессий
var store = sessions.NewCookieStore([]byte("secret-key"))

// Парсинг всех HTML-шаблонов из директории 'templates'
var templates = template.Must(template.ParseGlob(filepath.Join("templates", "*.html")))

// Функция для рендера HTML-шаблона
func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmpl+".html", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func main() {
	// Загрузка переменных окружения из .env
	err := godotenv.Load() // Добавлено
	if err != nil {
		log.Println("Ошибка при загрузке .env:", err) // Не критично, если файл не найден
	}
	r := mux.NewRouter() // Создание нового роутера

	r.HandleFunc("/", indexHandler).Methods(http.MethodGet)                       // Главная страница
	r.HandleFunc("/login", loginHandler).Methods(http.MethodGet, http.MethodPost) // Страница входа
	r.HandleFunc("/logout", logoutHandler).Methods(http.MethodGet)                // Выход из аккаунта

	// Настройка сервера
	srv := &http.Server{
		Addr:         "localhost:8080",
		Handler:      r,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Запуск сервера на порту :8080")                                // Логирование старта сервера
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed { // Запуск сервера
		log.Fatalf("Ошибка запуска сервера: %v\n", err)
	}
}

// Обработчик главной страницы
func indexHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	isLoggedIn := session.Values["is_logged_in"] == true // Проверяем, залогинен ли пользователь

	if !isLoggedIn { // Если пользователь не залогинен, редирект на страницу входа
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	renderTemplate(w, "index", nil) // Рендер главной страницы
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		renderTemplate(w, "login", LoginPageData{}) // Передаем пустую структуру для начальной отрисовки формы
	case http.MethodPost:
		username := r.FormValue("username")
		password := r.FormValue("password")

		isAuthenticated, err := authenticateAD(username, password)
		log.Printf("Результат authenticateAD: isAuthenticated=%v, error=%v", isAuthenticated, err) // Добавлено логирование

		if err != nil {
			log.Printf("Ошибка аутентификации: %v", err)
			// Создаем структуру данных для шаблона с сообщением об ошибке
			data := LoginPageData{
				ErrorMessage: "Неверный логин или пароль", //  Установите сообщение об ошибке здесь
			}

			// Рендерим шаблон с сообщением об ошибке
			w.WriteHeader(http.StatusInternalServerError)
			renderTemplate(w, "login", data) // Передаем структуру LoginPageData
			return                           // Важно: выходим из обработчика
		}

		if isAuthenticated {
			session, _ := store.Get(r, "session-name")
			session.Values["is_logged_in"] = true
			err := session.Save(r, w) // Проверяем ошибку сохранения сессии
			if err != nil {
				log.Printf("Ошибка сохранения сессии: %v", err)
				http.Error(w, "Ошибка сохранения сессии", http.StatusInternalServerError)
				return
			}

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		// Если аутентификация не удалась, отображаем форму авторизации с сообщением об ошибке
		data := LoginPageData{
			ErrorMessage: "Неверное имя пользователя или пароль", //  Установите сообщение об ошибке здесь
		}
		w.WriteHeader(http.StatusUnauthorized)
		renderTemplate(w, "login", data) // Передаем структуру LoginPageData
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) { // Обработчик выхода из аккаунта
	session, _ := store.Get(r, "session-name") // Получаем сессию
	session.Values["is_logged_in"] = false     // Устанавливаем флаг, что пользователь вышел
	session.Save(r, w)                         // Сохраняем изменения в сессии

	http.Redirect(w, r, "/login", http.StatusFound) // Редирект на страницу входа
}

// Функция для аутентификации пользователя в Active Directory
func authenticateAD(username, password string) (bool, error) {
	ldapServer := os.Getenv("LDAP_SERVER")
	log.Printf("authenticateAD: LDAP_SERVER=%s", ldapServer)
	if ldapServer == "" {
		return false, fmt.Errorf("необходимо задать переменную окружения LDAP_SERVER")
	}
	ldapPort := 389
	ldapBaseDN := os.Getenv("LDAP_BASE_DN")
	log.Printf("authenticateAD: LDAP_BASE_DN=%s", ldapBaseDN)
	if ldapBaseDN == "" {
		return false, fmt.Errorf("необходимо задать переменную окружения LDAP_BASE_DN")
	}
	groupDN := os.Getenv("LDAP_GROUP_DN")
	log.Printf("authenticateAD: LDAP_GROUP_DN=%s", groupDN)
	if groupDN == "" {
		return false, fmt.Errorf("необходимо задать переменную окружения LDAP_GROUP_DN")
	}

	ldapUserDN := username + "@example.com"
	log.Printf("authenticateAD: ldapUserDN (UPN)=%s", ldapUserDN)

	ldapConn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapServer, ldapPort))
	if err != nil {
		log.Printf("authenticateAD: Dial error: %v", err)
		return false, fmt.Errorf("ошибка при подключении к LDAP: %w", err)
	}
	defer ldapConn.Close()

	// Попытка привязки напрямую (UPN)
	log.Printf("authenticateAD: Attempting Bind with ldapUserDN (UPN)=%s", ldapUserDN)
	err = ldapConn.Bind(ldapUserDN, password)
	if err != nil {
		log.Printf("authenticateAD: Bind with ldapUserDN (UPN) error: %v", err)
	}

	// Поиск DN пользователя по sAMAccountName (это необходимо для получения правильного DN для фильтра)
	log.Printf("authenticateAD: Attempting to find user by sAMAccountName=%s", username)
	searchRequest := ldap.NewSearchRequest(
		ldapBaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(sAMAccountName=%s)", username), // Фильтр по sAMAccountName
		[]string{"dn"},
		nil,
	)

	sr, err := ldapConn.Search(searchRequest)
	if err != nil {
		log.Printf("authenticateAD: Search error (sAMAccountName): %v", err)
		return false, fmt.Errorf("ошибка при поиске пользователя: %w", err)
	}

	if len(sr.Entries) == 0 {
		log.Printf("authenticateAD: User not found (sAMAccountName)")
		return false, fmt.Errorf("пользователь не найден")
	}

	userDN := sr.Entries[0].DN
	log.Printf("authenticateAD: Found userDN=%s", userDN)

	// Если привязка с UPN не удалась или удалась, используем DN пользователя для привязки и проверки членства
	if err != nil { // Если привязка с UPN не удалась, пытаемся привязаться с DN
		log.Printf("authenticateAD: Attempting Bind with userDN=%s", userDN)
		err = ldapConn.Bind(userDN, password)
		if err != nil {
			log.Printf("authenticateAD: Bind with userDN error: %v", err)
			return false, fmt.Errorf("ошибка аутентификации с найденным DN: %w", err)
		} else {
			log.Printf("authenticateAD: Bind with userDN successful")
		}
	}

	// Проверка членства в группе (используем userDN)
	isMember, err := isMemberOfGroup(ldapConn, username, groupDN, userDN)
	log.Printf("authenticateAD: isMemberOfGroup result: isMember=%v, err=%v", isMember, err)
	if err != nil {
		return false, fmt.Errorf("ошибка при проверке членства в группе: %w", err)
	}

	if !isMember {
		return false, fmt.Errorf("пользователь не является членом необходимой группы")
	}

	return true, nil
}

// Функция для проверки, является ли пользователь членом группы
func isMemberOfGroup(conn *ldap.Conn, username, groupDN, userDN string) (bool, error) {
	log.Printf("isMemberOfGroup: username=%s, groupDN=%s, userDN=%s", username, groupDN, userDN)
	searchRequest := ldap.NewSearchRequest(
		groupDN,              // DN группы, которую мы проверяем
		ldap.ScopeBaseObject, // Ищем только саму группу (не поддеревья)
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		fmt.Sprintf("(member=%s)", userDN), // Фильтр для проверки членства (используем userDN)
		[]string{"dn"},                     // Нам нужен только DN группы
		nil,
	)

	log.Printf("isMemberOfGroup: searchRequest.Filter=%s", searchRequest.Filter)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		log.Printf("isMemberOfGroup: Search error: %v", err)
		return false, fmt.Errorf("ошибка поиска группы: %w", err)
	}

	log.Printf("isMemberOfGroup: len(sr.Entries)=%d", len(sr.Entries))

	if len(sr.Entries) == 0 {
		log.Printf("isMemberOfGroup: Пользователь НЕ является членом группы")
		return false, nil // Пользователь не является членом группы
	}

	log.Printf("isMemberOfGroup: Пользователь ЯВЛЯЕТСЯ членом группы")
	return true, nil // Пользователь является членом группы
}
