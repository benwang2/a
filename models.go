package main

import "time"

type Route struct {
	Code       string    `json:"code"`
	URL        string    `json:"url"`
	ExpiresAt  time.Time `json:"expires_at"`
	Uses       int       `json:"uses"`
	LastAccess time.Time `json:"last_access"`
	CreatedAt  time.Time `json:"created_at"`
}
