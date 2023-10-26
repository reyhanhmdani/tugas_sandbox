package database

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
	"testing_backend/config"
	"testing_backend/model/entity"
	"time"
)

type UserRepository struct {
	DB *gorm.DB
}

func NewUserRepository(DB *gorm.DB) *UserRepository {
	return &UserRepository{
		DB: DB,
	}
}

func (U *UserRepository) AllUsersData() ([]entity.User, error) {
	var users []entity.User
	if err := U.DB.Preload("Tasks").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (U *UserRepository) CreateUser(users *entity.User) error {
	if err := U.DB.Create(&users).Error; err != nil {
		return err
	}
	return nil
}

// PROFILE

func (U *UserRepository) ProfileUser(userId uint) (*entity.ListUsers, error) {
	var profile entity.ListUsers
	if err := U.DB.Where("id = ?", userId).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Santri data not found for the user
		}
		return nil, err // Other database error
	}
	return &profile, nil
}

func (U *UserRepository) GetByID(userID uint) (*entity.User, error) {
	var user entity.User
	if err := U.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// other
func (U *UserRepository) CheckUsername(username string) (*entity.User, error) {
	var user entity.User
	result := U.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &user, nil
}

func (U *UserRepository) PaginatePegawaiUsers(users *[]entity.User, perPage, offset int) error {
	// Mencari pengguna dengan role pegawai berdasarkan halaman dan jumlah per halaman
	err := U.DB.Preload("Tasks").Where("role = ?", "pegawai").Offset(offset).Limit(perPage).Find(users).Error
	if err != nil {
		return err
	}
	return nil
}

// token

func (U *UserRepository) AddValidToken(userID uint, token string) error {
	// Buat objek ValidToken berdasarkan model data Anda
	validToken := entity.ValidToken{
		UserID: userID,
		Token:  token,
	}

	// Simpan validToken ke dalam database menggunakan GORM
	if err := U.DB.Create(&validToken).Error; err != nil {
		return err
	}

	return nil
}

// DELETE USER
func (U *UserRepository) DeleteTasksByUserID(userID uint) error {
	// Hapus semua tugas yang dimiliki oleh pengguna dengan ID yang diberikan
	err := U.DB.Where("user_id = ?", userID).Delete(&entity.Tasks{}).Error
	if err != nil {
		return err
	}
	return nil
}

func (U *UserRepository) DeleteUser(userID uint) error {
	// Hapus pengguna berdasarkan ID
	err := U.DB.Where("id = ?", userID).Delete(&entity.User{}).Error
	if err != nil {
		return err
	}
	return nil
}

// Logout
func (U *UserRepository) DeleteUserToken(userID uint) error {
	// Hapus validToken berdasarkan userID dan token di dalam database menggunakan GORM
	if err := U.DB.Where("user_id = ?", userID).Delete(entity.ValidToken{}).Error; err != nil {
		return err
	}

	return nil
}

func (U *UserRepository) UpdateTokenExpiration(userID uint, expirationSeconds time.Time) error {
	// Perbarui token_expiration dengan waktu kadaluwarsa
	err := U.DB.Model(&entity.ValidToken{}).Where("user_id = ?", userID).Update("token_expiration", expirationSeconds).Error
	if err != nil {
		return err
	}

	return nil
}

func (U *UserRepository) GetUserIDByToken(token string) (uint, error) {
	var validToken entity.ValidToken

	// Cari validToken berdasarkan token di dalam database menggunakan GORM
	if err := U.DB.Where("token = ?", token).First(&validToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Token tidak ditemukan
			return 0, err
		}
		return 0, err
	}

	return validToken.UserID, nil
}

// valid token

func (U *UserRepository) ValidateTokenInDatabase(tokenString string) (uint, string, error) {
	// Parsing token dengan secret key
	claims := &config.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return config.JwtKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return 0, "", err
		}
		return 0, "", err
	}

	if !token.Valid {
		return 0, "", err
	}

	// Cek apakah token ada dalam tabel valid_token
	var validToken entity.ValidToken
	if err := U.DB.Where("token = ?", tokenString).First(&validToken).Error; err != nil {
		return 0, "", err
	}

	return claims.UserID, claims.Role, nil
}

//func (U *UserRepository) AddTokenToBlacklist(blacklistToken config.BlacklistToken) {
//	config.TokenBlacklist[blacklistToken.Token] = blacklistToken.ExpiresAt
//}
