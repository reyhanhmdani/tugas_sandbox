package middleware

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"testing_backend/internal/app/config"
	"testing_backend/internal/app/database"
	"testing_backend/internal/app/model/entity"
	"testing_backend/internal/app/model/respError"
)

func PegawaiMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		db, err := database.Db()
		if err != nil {
			// Handle error jika gagal menginisialisasi db
			return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
				Message: "Database connection error",
				Status:  fiber.StatusInternalServerError,
			})
		}
		// Mengambil token dari header Authorization
		authHeader := ctx.Get("Authorization")

		if authHeader == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
				Message: "Unauthorized",
				Status:  fiber.StatusUnauthorized,
			})
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
				return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
					Message: "Unauthorized",
					Status:  fiber.StatusUnauthorized,
				})
			}
			return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
				Message: "Invalid or expired token",
				Status:  fiber.StatusBadRequest,
			})
		}

		if !token.Valid {
			return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
				Message: "Unauthorized (non Valid)",
				Status:  fiber.StatusUnauthorized,
			})
		}

		// refresh
		refreshTokenString := ctx.Cookies("refresh_token")
		if refreshTokenString == "" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
				Message: "Unauthorized: Refresh token tidak ditemukan",
				Status:  fiber.StatusUnauthorized,
			})
		}

		// Validasi refresh token
		refreshClaims := &config.Claims{}
		refreshToken, err := jwt.ParseWithClaims(refreshTokenString, refreshClaims, func(token *jwt.Token) (interface{}, error) {
			return config.JwtKey, nil
		})

		if err != nil {
			if errors.Is(err, jwt.ErrSignatureInvalid) {
				return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
					Message: "Unauthorized: Invalid refresh token",
					Status:  fiber.StatusUnauthorized,
				})
			}
			return ctx.Status(fiber.StatusBadRequest).JSON(&respError.ErrorResponse{
				Message: "Invalid or expired refresh token",
				Status:  fiber.StatusBadRequest,
			})

		}

		// Cek apakah token ada di dalam tabel valid_token
		userID := claims.UserID
		validToken := &entity.ValidToken{}
		if err = db.Where("user_id = ? AND token = ?", userID, tokenString).First(&validToken).Error; err != nil {
			return ctx.Status(fiber.StatusUnauthorized).JSON(respError.ErrorResponse{
				Message: "Unauthorized: Invalid or expired token",
				Status:  fiber.StatusUnauthorized,
			})
		}

		// Menetapkan data pengguna dari token ke dalam konteks
		// ctx.Locals("username", claims.Username)
		ctx.Locals("user_id", claims.UserID)
		ctx.Locals("role", claims.Role) // Menambahkan data peran ke konteks

		if !refreshToken.Valid {
			// Cek apakah refresh token kadaluwarsa
			return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
				Message: "Unauthorized: token tidak valid or expired refresh token",
				Status:  fiber.StatusUnauthorized,
			})
		}

		// Melanjutkan ke handler jika semua pengecekan berhasil
		return ctx.Next()
	}
}