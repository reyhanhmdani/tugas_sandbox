package middleware

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"testing_backend/internal/app/config"
	"testing_backend/internal/app/database"
	"testing_backend/internal/app/model"
	"testing_backend/util/respError"
)

func PegawaiMiddleware() fiber.Handler {
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
		refreshToken, err := jwt.ParseWithClaims(refreshTokenString, refreshClaims, func(token *jwt.Token) (interface{}, error) {
			return config.JwtKey, nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrSignatureInvalid) {
				return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Invalid refresh token")
			}
			return respError.ErrResponse(ctx, fiber.StatusBadRequest, "Invalid or expired refresh token")
		}

		// Cek apakah token ada di dalam tabel valid_token
		userID := claims.UserID
		validToken := &model.ValidToken{}
		if err = db.Where("user_id = ? AND token = ?", userID, tokenString).First(&validToken).Error; err != nil {
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: Invalid or expired token")
		}

		// Menetapkan data pengguna dari token ke dalam konteks
		ctx.Locals("user_id", claims.UserID)
		ctx.Locals("role", claims.Role) // Menambahkan data peran ke konteks

		if !refreshToken.Valid {
			// Cek apakah refresh token kadaluwarsa
			return respError.ErrResponse(ctx, fiber.StatusUnauthorized, "Unauthorized: token tidak valid or expired refresh token")
		}

		// Melanjutkan ke handler jika semua pengecekan berhasil
		return ctx.Next()
	}
}
