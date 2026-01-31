package main

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var codePattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,50}$`)

func filterEmpty(strs []string) []string {
	var result []string
	for _, s := range strs {
		if s != "" {
			result = append(result, s)
		}
	}
	return result
}

func validateURL(urlStr string) error {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return err
	}
	
	scheme := strings.ToLower(parsedURL.Scheme)
	if scheme != "http" && scheme != "https" {
		return &url.Error{Op: "parse", URL: urlStr, Err: http.ErrNotSupported}
	}
	
	return nil
}

func validateCode(code string) error {
	if !codePattern.MatchString(code) {
		return &url.Error{Op: "validate", URL: code, Err: http.ErrNotSupported}
	}
	return nil
}

func getExpiryDuration(expiry string, isAdmin bool) (time.Duration, error) {
	switch expiry {
	case "", "1d":
		return 24 * time.Hour, nil
	case "7d":
		return 7 * 24 * time.Hour, nil
	case "30d":
		if !isAdmin {
			return 0, &url.Error{Op: "expiry", URL: expiry, Err: http.ErrNotSupported}
		}
		return 30 * 24 * time.Hour, nil
	case "365d":
		if !isAdmin {
			return 0, &url.Error{Op: "expiry", URL: expiry, Err: http.ErrNotSupported}
		}
		return 365 * 24 * time.Hour, nil
	case "perma":
		if !isAdmin {
			return 0, &url.Error{Op: "expiry", URL: expiry, Err: http.ErrNotSupported}
		}
		return 100 * 365 * 24 * time.Hour, nil
	default:
		return 0, &url.Error{Op: "expiry", URL: expiry, Err: http.ErrNotSupported}
	}
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
