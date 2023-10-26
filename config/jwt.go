package config

import (
	"github.com/dgrijalva/jwt-go"
	"os"
	"time"
)

var JwtKey = []byte(os.Getenv("JWT_KEY"))

type Claims struct {
	//Username string `json:"username"`
	UserID     uint   `json:"user_id"`
	Role       string `json:"role"`
	RememberMe bool   `json:"remember_me"`
	jwt.StandardClaims
}

// Membuat token JWT
func CreateJWTToken(userID uint, role string, rememberMe bool) (string, error) {
	var expirationTime time.Time

	if rememberMe {
		// Jika "remember me" dicentang, atur waktu kedaluwarsa token ke 1 menit
		expirationTime = time.Now().Add(time.Minute)
	} else {
		// Jika tidak, atur waktu kedaluwarsa token ke 10 detik
		expirationTime = time.Now().Add(20 * time.Second)
	}

	// Atur payload token
	claims := &Claims{
		//Username: username,
		UserID: userID,
		Role:   role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Buat token JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Simpan token dalam string dengan mengenkripsi menggunakan secret key
	tokenString, err := token.SignedString(JwtKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
