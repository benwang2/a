package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

func (app *App) googleLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}
	
	session, _ := app.sessionStore.Get(r, "auth-session")
	session.Values["oauth-state"] = state
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	
	url := app.googleOAuth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (app *App) googleCallback(w http.ResponseWriter, r *http.Request) {
	session, _ := app.sessionStore.Get(r, "auth-session")
	
	// Verify state parameter
	state := r.URL.Query().Get("state")
	savedState, ok := session.Values["oauth-state"].(string)
	if !ok || state != savedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	
	code := r.URL.Query().Get("code")
	token, err := app.googleOAuth.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}
	
	client := app.googleOAuth.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/auth/userinfo.email")
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
		if strings.HasSuffix(userInfo.Email, "@"+domain) {
			allowed = true
			break
		}
	}
	
	if !allowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	session.Values["authenticated"] = true
	session.Values["email"] = userInfo.Email
	delete(session.Values, "oauth-state")
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (app *App) githubLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomState()
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}
	
	session, _ := app.sessionStore.Get(r, "auth-session")
	session.Values["oauth-state"] = state
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	
	url := app.githubOAuth.AuthCodeURL(state, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (app *App) githubCallback(w http.ResponseWriter, r *http.Request) {
	session, _ := app.sessionStore.Get(r, "auth-session")
	
	// Verify state parameter
	state := r.URL.Query().Get("state")
	savedState, ok := session.Values["oauth-state"].(string)
	if !ok || state != savedState {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}
	
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
		if username == userInfo.Login {
			allowed = true
			break
		}
	}
	
	if !allowed {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	session.Values["authenticated"] = true
	session.Values["username"] = userInfo.Login
	delete(session.Values, "oauth-state")
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Failed to save session", http.StatusInternalServerError)
		return
	}
	
	http.Redirect(w, r, "/admin", http.StatusFound)
}

func (app *App) logout(w http.ResponseWriter, r *http.Request) {
	session, _ := app.sessionStore.Get(r, "auth-session")
	session.Values["authenticated"] = false
	if err := session.Save(r, w); err != nil {
		log.Printf("Failed to save session during logout: %v", err)
	}
	
	http.Redirect(w, r, "/", http.StatusFound)
}
