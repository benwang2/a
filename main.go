package main

import (
	"encoding/json"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type Route struct {
	Code       string    `json:"code"`
	URL        string    `json:"url"`
	ExpiresAt  time.Time `json:"expires_at"`
	Uses       int       `json:"uses"`
	LastAccess time.Time `json:"last_access"`
	CreatedAt  time.Time `json:"created_at"`
}

type App struct {
	db           *pebble.DB
	sessionStore *sessions.CookieStore
	googleOAuth  *oauth2.Config
	githubOAuth  *oauth2.Config
	allowedDomains []string
	allowedGithubUsers []string
}

var (
	reservedCodes = map[string]bool{
		"auth":  true,
		"api":   true,
		"admin": true,
	}
	wordList = []string{
		"able", "also", "area", "back", "base", "best", "blue", "book", "both", "call",
		"came", "care", "case", "city", "come", "data", "deep", "door", "down", "each",
		"early", "easy", "even", "ever", "face", "fact", "fall", "far", "fast", "feel",
		"feet", "file", "find", "fire", "fish", "five", "food", "foot", "form", "four",
		"free", "from", "full", "game", "gave", "girl", "give", "goal", "goes", "gold",
		"gone", "good", "great", "group", "grow", "half", "hand", "hard", "have", "head",
		"hear", "heat", "help", "here", "high", "hold", "home", "hope", "hour", "house",
		"idea", "into", "item", "just", "keep", "kind", "king", "know", "land", "large",
		"last", "late", "lead", "left", "less", "life", "line", "list", "live", "long",
		"look", "lost", "love", "made", "main", "make", "many", "mark", "mean", "meet",
		"mind", "more", "most", "move", "much", "must", "name", "near", "need", "news",
		"next", "nice", "note", "once", "only", "open", "over", "page", "part", "pass",
		"past", "path", "people", "plan", "play", "point", "power", "push", "race", "rain",
		"read", "real", "rest", "right", "road", "rock", "role", "room", "rule", "safe",
		"said", "same", "save", "seen", "self", "sell", "send", "ship", "shop", "show",
		"side", "sign", "site", "size", "slow", "small", "some", "soon", "sort", "sound",
		"star", "stay", "step", "stop", "sure", "take", "talk", "team", "tell", "test",
		"text", "than", "that", "them", "then", "they", "this", "time", "told", "took",
		"town", "tree", "true", "turn", "type", "unit", "upon", "used", "user", "very",
		"view", "wait", "walk", "wall", "want", "warm", "watch", "water", "week", "well",
		"went", "were", "west", "what", "when", "wide", "will", "wind", "wish", "with",
		"word", "work", "world", "year", "your",
	}
)

func main() {
	db, err := pebble.Open("data", &pebble.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	sessionKey := os.Getenv("SESSION_KEY")
	if sessionKey == "" {
		sessionKey = "change-me-in-production"
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
		allowedDomains:     strings.Split(os.Getenv("ALLOWED_DOMAINS"), ","),
		allowedGithubUsers: strings.Split(os.Getenv("ALLOWED_GITHUB_USERS"), ","),
	}

	r := mux.NewRouter()
	
	// Public endpoints
	r.HandleFunc("/api/public/routes", app.createPublicRoute).Methods("POST")
	
	// Auth endpoints
	r.HandleFunc("/auth/google", app.googleLogin).Methods("GET")
	r.HandleFunc("/auth/google/callback", app.googleCallback).Methods("GET")
	r.HandleFunc("/auth/github", app.githubLogin).Methods("GET")
	r.HandleFunc("/auth/github/callback", app.githubCallback).Methods("GET")
	r.HandleFunc("/auth/logout", app.logout).Methods("GET")
	
	// Admin API endpoints
	r.Handle("/api/admin/routes", app.requireAdmin(http.HandlerFunc(app.listRoutes))).Methods("GET")
	r.Handle("/api/admin/routes", app.requireAdmin(http.HandlerFunc(app.createAdminRoute))).Methods("POST")
	r.Handle("/api/admin/routes/{code}", app.requireAdmin(http.HandlerFunc(app.updateRoute))).Methods("PUT")
	r.Handle("/api/admin/routes/{code}", app.requireAdmin(http.HandlerFunc(app.deleteRoute))).Methods("DELETE")
	
	// Static files and home page
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.ServeFile(w, r, "static/index.html")
			return
		}
		http.NotFound(w, r)
	}).Methods("GET")
	r.PathPrefix("/admin").Handler(http.StripPrefix("/admin", http.FileServer(http.Dir("static/admin"))))
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

func (app *App) createPublicRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string `json:"url"`
		Code   string `json:"code,omitempty"`
		Expiry string `json:"expiry,omitempty"` // "1d" or "7d"
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}
	
	// Validate expiry - only 1d or 7d allowed for public
	var expiryDuration time.Duration
	switch req.Expiry {
	case "", "1d":
		expiryDuration = 24 * time.Hour
	case "7d":
		expiryDuration = 7 * 24 * time.Hour
	default:
		http.Error(w, "Invalid expiry, only 1d or 7d allowed for public routes", http.StatusBadRequest)
		return
	}
	
	code := req.Code
	if code == "" {
		code = app.generateCode()
	} else {
		if reservedCodes[code] {
			http.Error(w, "Code is reserved", http.StatusBadRequest)
			return
		}
		if app.codeExists(code) {
			http.Error(w, "Code already exists", http.StatusConflict)
			return
		}
	}
	
	route := Route{
		Code:      code,
		URL:       req.URL,
		ExpiresAt: time.Now().Add(expiryDuration),
		CreatedAt: time.Now(),
	}
	
	if err := app.saveRoute(route); err != nil {
		http.Error(w, "Failed to save route", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (app *App) redirectHandler(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimPrefix(r.URL.Path, "/")
	
	// Skip empty codes and reserved paths
	if code == "" || reservedCodes[code] || strings.HasPrefix(code, "static/") {
		http.NotFound(w, r)
		return
	}
	
	route, err := app.getRoute(code)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	// Check if expired
	if time.Now().After(route.ExpiresAt) {
		w.WriteHeader(http.StatusGone)
		w.Write([]byte("Link expired"))
		return
	}
	
	// Update usage stats
	route.Uses++
	route.LastAccess = time.Now()
	app.saveRoute(route)
	
	http.Redirect(w, r, route.URL, http.StatusFound)
}

func (app *App) listRoutes(w http.ResponseWriter, r *http.Request) {
	iter, err := app.db.NewIter(nil)
	if err != nil {
		http.Error(w, "Failed to list routes", http.StatusInternalServerError)
		return
	}
	defer iter.Close()
	
	var routes []Route
	for iter.First(); iter.Valid(); iter.Next() {
		var route Route
		if err := json.Unmarshal(iter.Value(), &route); err != nil {
			continue
		}
		routes = append(routes, route)
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(routes)
}

func (app *App) createAdminRoute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL    string `json:"url"`
		Code   string `json:"code,omitempty"`
		Expiry string `json:"expiry,omitempty"` // "1d", "7d", "30d", "perma"
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}
	
	var expiryDuration time.Duration
	switch req.Expiry {
	case "", "1d":
		expiryDuration = 24 * time.Hour
	case "7d":
		expiryDuration = 7 * 24 * time.Hour
	case "30d":
		expiryDuration = 30 * 24 * time.Hour
	case "perma":
		expiryDuration = 100 * 365 * 24 * time.Hour // 100 years
	default:
		http.Error(w, "Invalid expiry", http.StatusBadRequest)
		return
	}
	
	code := req.Code
	if code == "" {
		code = app.generateCode()
	} else {
		if reservedCodes[code] {
			http.Error(w, "Code is reserved", http.StatusBadRequest)
			return
		}
		if app.codeExists(code) {
			http.Error(w, "Code already exists", http.StatusConflict)
			return
		}
	}
	
	route := Route{
		Code:      code,
		URL:       req.URL,
		ExpiresAt: time.Now().Add(expiryDuration),
		CreatedAt: time.Now(),
	}
	
	if err := app.saveRoute(route); err != nil {
		http.Error(w, "Failed to save route", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (app *App) updateRoute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	code := vars["code"]
	
	route, err := app.getRoute(code)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	
	var req struct {
		URL    string `json:"url,omitempty"`
		Expiry string `json:"expiry,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	if req.URL != "" {
		route.URL = req.URL
	}
	
	if req.Expiry != "" {
		var expiryDuration time.Duration
		switch req.Expiry {
		case "1d":
			expiryDuration = 24 * time.Hour
		case "7d":
			expiryDuration = 7 * 24 * time.Hour
		case "30d":
			expiryDuration = 30 * 24 * time.Hour
		case "perma":
			expiryDuration = 100 * 365 * 24 * time.Hour
		default:
			http.Error(w, "Invalid expiry", http.StatusBadRequest)
			return
		}
		route.ExpiresAt = time.Now().Add(expiryDuration)
	}
	
	if err := app.saveRoute(route); err != nil {
		http.Error(w, "Failed to save route", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(route)
}

func (app *App) deleteRoute(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	code := vars["code"]
	
	if err := app.db.Delete([]byte(code), pebble.Sync); err != nil {
		http.Error(w, "Failed to delete route", http.StatusInternalServerError)
		return
	}
	
	w.WriteHeader(http.StatusNoContent)
}

func (app *App) generateCode() string {
	for {
		code := wordList[rand.Intn(len(wordList))]
		if !reservedCodes[code] && !app.codeExists(code) {
			return code
		}
	}
}

func (app *App) codeExists(code string) bool {
	_, closer, err := app.db.Get([]byte(code))
	if err != nil {
		return false
	}
	closer.Close()
	return true
}

func (app *App) getRoute(code string) (Route, error) {
	data, closer, err := app.db.Get([]byte(code))
	if err != nil {
		return Route{}, err
	}
	defer closer.Close()
	
	var route Route
	if err := json.Unmarshal(data, &route); err != nil {
		return Route{}, err
	}
	
	return route, nil
}

func (app *App) saveRoute(route Route) error {
	data, err := json.Marshal(route)
	if err != nil {
		return err
	}
	
	return app.db.Set([]byte(route.Code), data, pebble.Sync)
}

// OAuth handlers
func (app *App) googleLogin(w http.ResponseWriter, r *http.Request) {
	url := app.googleOAuth.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (app *App) googleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := app.googleOAuth.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	
	client := app.googleOAuth.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	var userInfo struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}
	
	// Check if email domain is allowed
	allowed := false
	for _, domain := range app.allowedDomains {
		if domain != "" && strings.HasSuffix(userInfo.Email, "@"+domain) {
			allowed = true
			break
		}
	}
	
	if !allowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	session, _ := app.sessionStore.Get(r, "auth-session")
	session.Values["authenticated"] = true
	session.Values["email"] = userInfo.Email
	session.Save(r, w)
	
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (app *App) githubLogin(w http.ResponseWriter, r *http.Request) {
	url := app.githubOAuth.AuthCodeURL("state", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (app *App) githubCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	token, err := app.githubOAuth.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	
	client := app.githubOAuth.Client(r.Context(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	
	var userInfo struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Failed to decode user info", http.StatusInternalServerError)
		return
	}
	
	// Check if GitHub username is allowed
	allowed := false
	for _, username := range app.allowedGithubUsers {
		if username != "" && username == userInfo.Login {
			allowed = true
			break
		}
	}
	
	if !allowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	session, _ := app.sessionStore.Get(r, "auth-session")
	session.Values["authenticated"] = true
	session.Values["username"] = userInfo.Login
	session.Save(r, w)
	
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (app *App) logout(w http.ResponseWriter, r *http.Request) {
	session, _ := app.sessionStore.Get(r, "auth-session")
	session.Values["authenticated"] = false
	session.Save(r, w)
	
	http.Redirect(w, r, "/", http.StatusFound)
}

func (app *App) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := app.sessionStore.Get(r, "auth-session")
		
		auth, ok := session.Values["authenticated"].(bool)
		if !ok || !auth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		
		next.ServeHTTP(w, r)
	})
}
