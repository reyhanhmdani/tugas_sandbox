package config

import (
	"github.com/dgrijalva/jwt-go"
	"os"
	"time"
)

var JwtKey = []byte(os.Getenv("JWT_KEY"))

type Claims struct {
	//Username string `json:"username"`
	Id     uint   `json:"id"`
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.StandardClaims
}

// Membuat token JWT
func CreateJWTToken(ID, userID uint, rememberMe bool) (string, string, error) {
	// Set masa berlaku access token (misalnya, 1 jam)
	accessTokenExpiration := time.Now().Add(120 * time.Second)
	accessTokenClaims := &Claims{
		Id:     ID,
		UserID: userID,
		//Role:   role,
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
			//Role:   role,
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

//func CreateNewTokens(userID uint, role string, rememberMe bool) (string, string, error) {
//	// Membuat access token yang baru
//	accessToken, err := CreateAccessToken(userID, role)
//
//	if err != nil {
//		return "", "", err
//	}
//
//	// Membuat refresh token yang baru
//	refreshToken, err := CreateRefreshToken(userID, role, rememberMe)
//
//	if err != nil {
//		return "", "", err
//	}
//
//	// Di sini, Anda dapat menyimpan refresh token yang baru untuk digunakan selanjutnya
//
//	return accessToken, refreshToken, nil
//}
