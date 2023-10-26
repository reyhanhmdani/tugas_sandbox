package middleware

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gofiber/fiber/v2"
	"testing_backend/config"
	"testing_backend/database"
	"testing_backend/model/entity"
	"testing_backend/model/respError"
)

func AdminMiddleware() fiber.Handler {
	return func(ctx *fiber.Ctx) error {
		db, err := database.Db()
		if err != nil {
			// Handle error jika gagal menginisialisasi db
			return ctx.Status(fiber.StatusInternalServerError).JSON(&respError.ErrorResponse{
				Message: "Database connection to table valid_token error",
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

		if !token.Valid {
			return ctx.Status(fiber.StatusUnauthorized).JSON(&respError.ErrorResponse{
				Message: "Unauthorized (non Valid)",
				Status:  fiber.StatusUnauthorized,
			})
		}

		// Menetapkan data pengguna dari token ke dalam konteks
		//ctx.Locals("username", claims.Username)
		ctx.Locals("user_id", claims.UserID)
		ctx.Locals("role", claims.Role) // Menambahkan data peran ke konteks

		// Pengecekan peran admin
		if claims.Role != "admin" {
			return ctx.Status(fiber.StatusUnauthorized).JSON(respError.ErrorResponse{
				Message: "Unauthorized: Only admin can access this endpoint",
				Status:  fiber.StatusUnauthorized,
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

		// Melanjutkan ke handler jika semua pengecekan berhasil
		return ctx.Next()
	}
}
