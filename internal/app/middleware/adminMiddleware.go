package middleware

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"testing_backend/internal/app/config"
	"testing_backend/internal/app/database"
	token2 "testing_backend/internal/app/model"
	"testing_backend/util/respError"
)

func AdminMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		db, err := database.Db()
		if err != nil {
			// Handle error jika gagal menginisialisasi db
			return respError.ErrResponse(ctx, fiber.StatusInternalServerError, "Database connection error")
		}
		// Mengambil token dari header Authorization
		authHeader := ctx.Get("Authorization")

		if authHeader == "" {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized")
		}

		// Memisahkan token dari header
		tokenString := authHeader[len("Bearer "):]

		// Parsing token dengan secret key
		claims := &config.Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return config.JwtKey, nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrSignatureInvalid) {
				return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized")
			}
			return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid or expired token")
		}

		if !token.Valid {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized (non Valid)")
		}

		// refresh
		refreshTokenString := ctx.Cookies("refresh_token")
		if refreshTokenString == "" {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Refresh token tidak ditemukan")
		}

		// Validasi refresh token
		refreshClaims := &config.Claims{}
		refreshToken, err := jwt.ParseWithClaims(tokenString, refreshClaims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return config.JwtKey, nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrSignatureInvalid) {
				return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Invalid or expired token")
			}
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Invalid or expired token")
		}

		// Cek apakah token ada di dalam tabel valid_token
		userID := claims.UserID
		validToken := &token2.ValidToken{}
		if err = db.Where("user_id = ? AND token = ?", userID, tokenString).First(&validToken).Error; err != nil {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Invalid or expired token")

		}

		// Menetapkan data pengguna dari token ke dalam konteks
		ctx.Locals("user_id", claims.UserID)
		ctx.Locals("role", claims.Role) // Menambahkan data peran ke konteks

		////
		var user token2.User
		if err = db.Where("id = ?", userID).First(&user).Error; err != nil {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: User not found")
		}

		// Periksa peran pengguna
		if user.Role != "admin" {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Only admin can access this endpoint")

		}

		if !refreshToken.Valid {
			// Cek apakah refresh token kadaluwarsa
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: token tidak valid or expired refresh token")

		}

		// Melanjutkan ke handler jika semua pengecekan berhasil
		return ctx.Next()
	}
}

// Pengecekan peran admin
//logrus.Info("claims.Role: ", claims.Role)
//if claims.Role != "admin" {
//	return ctx.Status(fiber.StatusUnauthorized).JSON(respError.ErrorResponse{
//		Message: "Unauthorized: Only admin can access this endpoint",
//		Status:  fiber.StatusUnauthorized,
//	})
//}
//

//ctx.Locals("username", claims.Username)
