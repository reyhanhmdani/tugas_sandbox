package generate

import (
	"errors"
	"testing_backend/config"
	"testing_backend/database"
	"testing_backend/model/entity"
)

func GenerateNewAccessToken(refreshToken string, user *entity.RefreshToken) (string, error) {
	//var userLogin request.UserLogin

	db, _ := database.Db()

	// Contoh validasi menggunakan GORM:
	var validRefreshToken entity.ValidToken
	if err := db.Where("id = ? AND refresh_token = ?", user.ID, refreshToken).First(&validRefreshToken).Error; err != nil {
		return "", errors.New("Invalid refresh token")
	}

	//rememberMe := userLogin.Remember

	// Jika refresh token masih valid, Anda dapat membuat access token yang baru
	accessTokenString, _, err := config.CreateJWTToken(validRefreshToken.ID, validRefreshToken.UserID, false) // false menunjukkan bahwa bukan remember me
	if err != nil {
		return "", errors.New("Failed to create a new access token")
	}

	return accessTokenString, nil
}
