package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/cockroachdb/pebble"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type App struct {
	db                 *pebble.DB
	sessionStore       *sessions.CookieStore
	googleOAuth        *oauth2.Config
	githubOAuth        *oauth2.Config
	allowedDomains     []string
	allowedGithubUsers []string
}

var wordList []string

func main() {
	// Load word list from JSON file

	err := godotenv.Load()

	wordData, err := os.ReadFile("words.json")
	if err != nil {
		log.Fatal("Failed to load words.json:", err)
	}
	if err := json.Unmarshal(wordData, &wordList); err != nil {
		log.Fatal("Failed to parse words.json:", err)
	}

	db, err := pebble.Open("data", &pebble.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "change-me-in-production"
		log.Println("WARNING: Using default SESSION_KEY. Set SESSION_KEY environment variable in production!")
	}

	app := &App{
		db:           db,
		sessionStore: sessions.NewCookieStore([]byte(sessionKey)),
		googleOAuth: &oauth2.Config{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GOOGLE_REDIRECT_URL"),
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
		},
		githubOAuth: &oauth2.Config{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
			RedirectURL:  os.Getenv("GITHUB_REDIRECT_URL"),
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		},
		allowedDomains:     filterEmpty(strings.Split(os.Getenv("ALLOWED_DOMAINS"), ",")),
		allowedGithubUsers: filterEmpty(strings.Split(os.Getenv("ALLOWED_GITHUB_USERS"), ",")),
	}

	r := mux.NewRouter()

	// Auth endpoints
	r.HandleFunc("/auth/google", app.googleLogin).Methods("GET")
	r.HandleFunc("/auth/google/callback", app.googleCallback).Methods("GET")
	r.HandleFunc("/auth/github", app.githubLogin).Methods("GET")
	r.HandleFunc("/auth/github/callback", app.githubCallback).Methods("GET")
	r.HandleFunc("/auth/logout", app.logout).Methods("GET")

	// Unified API routes endpoint - handles both public and admin
	r.HandleFunc("/api/routes", app.handleRoutes).Methods("GET", "POST")
	r.HandleFunc("/api/routes/{code}", app.handleRoute).Methods("PUT", "DELETE")

	// Static files and home page
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}
		http.NotFound(w, r)
	}).Methods("GET")
	r.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/admin.html")
	}).Methods("GET")
	r.PathPrefix("/assets/").Handler(http.StripPrefix("/assets/", http.FileServer(http.Dir("static/assets"))))
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Redirect handler (catch-all, must be last)
	r.PathPrefix("/").HandlerFunc(app.redirectHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}
