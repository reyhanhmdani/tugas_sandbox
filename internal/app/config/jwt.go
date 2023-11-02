package config

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"os"
	"time"
)

var JwtKey = []byte(os.Getenv("JWT_KEY"))

type Claims struct {
	UserID uuid.UUID `json:"user_id"`
	Role   string    `json:"role"`
	jwt.StandardClaims
}

// Membuat token JWT
func CreateJWTToken(userID uuid.UUID, role string, rememberMe bool) (string, string, error) {
	// Set masa berlaku access token (misalnya, 1 jam)
	accessTokenExpiration := time.Now().Add(60 * time.Minute)
	accessTokenClaims := &Claims{
		//ID:     Id,
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: accessTokenExpiration.Unix(),
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)

	accessTokenString, err := accessToken.SignedString(JwtKey)
	if err != nil {
		return "", "", err
	}

	// Jika "rememberMe" dicentang, buat refresh token
	var refreshTokenString string
	if rememberMe {
		refreshTokenExpiration := time.Now().Add(24 * time.Hour) // Misalnya, berlaku selama 1 hari
		refreshTokenClaims := &Claims{
			UserID: userID,
			Role:   role,
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: refreshTokenExpiration.Unix(),
			},
		}
		refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
		refreshTokenString, err = refreshToken.SignedString(JwtKey)
		if err != nil {
			return "", "", err
		}
	}

	return accessTokenString, refreshTokenString, nil
}
