package config

import "time"

type BlacklistToken struct {
	Token     string
	ExpiresAt time.Time
}

var TokenBlacklist = make(map[string]time.Time)

func IsTokenBlacklisted(token string) bool {
	if expirationTime, exists := TokenBlacklist[token]; exists {
		return time.Now().Before(expirationTime)
	}
	return false
}

func IsTokenExpired(token string) bool {
	expirationTime, exists := TokenBlacklist[token]
	if exists && time.Now().After(expirationTime) {
		return true // Token telah kadaluwarsa
	}
	return false // Token masih valid
}
