package generate

import (
	"errors"
	"testing_backend/internal/app/config"
	"testing_backend/internal/app/database"
	"testing_backend/internal/app/model/entity"
)

func GenerateNewAccessToken(refreshToken string, user *entity.RefreshToken) (string, error) {
	//var userLogin request.UserLogin

	db, _ := database.Db()

	// Contoh validasi menggunakan GORM:
	var validRefreshToken entity.GenerateRefreshToken
	if err := db.Where("id = ? AND refresh_token = ?", user.ID, refreshToken).First(&validRefreshToken).Error; err != nil {
		return "", errors.New("Invalid refresh token")
	}

	//rememberMe := userLogin.Remember

	// Jika refresh token masih valid, Anda dapat membuat access token yang baru
	accessTokenString, _, err := config.CreateJWTToken(validRefreshToken.UserID, validRefreshToken.Role, false) // false menunjukkan bahwa bukan remember me
	if err != nil {
		return "", errors.New("Failed to create a new access token")
	}

	return accessTokenString, nil
}
