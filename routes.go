package main

import (
	"crypto/rand"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/cockroachdb/pebble"
	"github.com/gorilla/mux"
)

var (
	reservedCodes = map[string]bool{
		"auth":  true,
		"api":   true,
		"admin": true,
	}
)

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
	if err := app.saveRoute(route); err != nil {
		log.Printf("Failed to update route stats for %s: %v", code, err)
	}
	
	http.Redirect(w, r, route.URL, http.StatusFound)
}

// Unified route handler - handles both public and admin requests
func (app *App) handleRoutes(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, _ := app.sessionStore.Get(r, "auth-session")
	auth, _ := session.Values["authenticated"].(bool)
	
	switch r.Method {
	case "GET":
		// List routes - only for authenticated admins
		if !auth {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		app.listRoutes(w, r)
	case "POST":
		// Create route - public or admin
		app.createRoute(w, r, auth)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (app *App) handleRoute(w http.ResponseWriter, r *http.Request) {
	// Check if user is authenticated
	session, _ := app.sessionStore.Get(r, "auth-session")
	auth, _ := session.Values["authenticated"].(bool)
	
	if !auth {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	switch r.Method {
	case "PUT":
		app.updateRoute(w, r)
	case "DELETE":
		app.deleteRoute(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
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

// Unified create route handler
func (app *App) createRoute(w http.ResponseWriter, r *http.Request, isAdmin bool) {
	var req struct {
		URL    string `json:"url"`
		Code   string `json:"code,omitempty"`
		Expiry string `json:"expiry,omitempty"`
	}
	
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	
	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}
	
	// Validate URL
	if err := validateURL(req.URL); err != nil {
		http.Error(w, "Invalid URL: only http and https URLs are allowed", http.StatusBadRequest)
		return
	}
	
	// Validate and get expiry duration
	expiryDuration, err := getExpiryDuration(req.Expiry, isAdmin)
	if err != nil {
		if isAdmin {
			http.Error(w, "Invalid expiry", http.StatusBadRequest)
		} else {
			http.Error(w, "Invalid expiry, only 1d or 7d allowed for public routes", http.StatusBadRequest)
		}
		return
	}
	
	code := req.Code
	if code == "" {
		code = app.generateCode()
	} else {
		if err := validateCode(code); err != nil {
			http.Error(w, "Invalid code: only alphanumeric characters and hyphens allowed (1-50 chars)", http.StatusBadRequest)
			return
		}
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
		if err := validateURL(req.URL); err != nil {
			http.Error(w, "Invalid URL: only http and https URLs are allowed", http.StatusBadRequest)
			return
		}
		route.URL = req.URL
	}
	
	if req.Expiry != "" {
		expiryDuration, err := getExpiryDuration(req.Expiry, true)
		if err != nil {
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
		// Use crypto/rand for secure random selection
		b := make([]byte, 1)
		rand.Read(b)
		idx := int(b[0]) % len(wordList)
		code := wordList[idx]
		
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
