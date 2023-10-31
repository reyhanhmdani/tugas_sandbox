package database

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"gorm.io/gorm"
	"testing_backend/internal/app/config"
	entity2 "testing_backend/internal/app/model/entity"
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

func (U *UserRepository) AllUsersData() ([]entity2.User, error) {
	var users []entity2.User
	if err := U.DB.Preload("Tasks").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (U *UserRepository) CreateUser(users *entity2.User) error {
	if err := U.DB.Create(&users).Error; err != nil {
		return err
	}
	return nil
}

// PROFILE

func (U *UserRepository) ProfileUser(userId uint) (*entity2.ListUsers, error) {
	var profile entity2.ListUsers
	if err := U.DB.Where("id = ?", userId).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Santri data not found for the user
		}
		return nil, err // Other database error
	}
	return &profile, nil
}

func (U *UserRepository) GetByID(userID uint) (*entity2.User, error) {
	var user entity2.User
	if err := U.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (U *UserRepository) GetUserByID(id uint) ([]entity2.User, error) {
	var users []entity2.User
	err := U.DB.Where("id", id).Find(&users).Error
	if err != nil {
		return nil, err

	}
	return users, nil
}

func (U *UserRepository) GetTaskByUserByID(userID uint, user *entity2.User) error {
	err := U.DB.Where("id = ?", userID).First(user).Error
	if err != nil {
		return err
	}
	return nil
}

// other
func (U *UserRepository) CheckUsername(username string) (*entity2.UserLogin, error) {
	var user entity2.UserLogin
	result := U.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &user, nil
}

func (U *UserRepository) PaginatePegawaiUsers(users *[]entity2.User, perPage, offset int) error {
	// Mencari pengguna dengan role pegawai berdasarkan halaman dan jumlah per halaman
	err := U.DB.Where("role = ?", "pegawai").Offset(offset).Limit(perPage).Find(users).Error
	if err != nil {
		return err
	}
	return nil
}

func (U *UserRepository) PaginateTaskUsers(tasks *[]entity2.Tasks, perPage, offset int) error {
	err := U.DB.Offset(offset).Limit(perPage).Find(tasks).Error
	if err != nil {
		return err
	}
	return nil
}

// token

func (U *UserRepository) AddValidToken(userID uint, token, refreshToken string) error {
	// Cek apakah token sudah ada dalam database
	existingToken := entity2.ValidToken{}
	if err := U.DB.Where("user_id = ? AND token = ? AND refresh_token = ?", userID, token, refreshToken).First(&existingToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Token tidak ada dalam database, tambahkan
			newToken := entity2.ValidToken{
				UserID:       userID,
				Token:        token,
				RefreshToken: refreshToken,
			}
			if err := U.DB.Create(&newToken).Error; err != nil {
				return err
			}
		} else {
			// Terjadi kesalahan database lainnya
			return err
		}
	}
	return nil
}
func (U *UserRepository) AddRefreshToken(userID uint, refreshToken string) error {
	// Buat objek RefreshToken berdasarkan model data Anda
	refresh := entity2.ValidToken{
		UserID: userID,
		Token:  refreshToken,
	}

	// Simpan refresh token ke dalam database menggunakan GORM
	if err := U.DB.Create(&refresh).Error; err != nil {
		return err
	}

	return nil
}

// DELETE USER
func (U *UserRepository) DeleteTasksByUserID(userID uint) error {
	// Hapus semua tugas yang dimiliki oleh pengguna dengan ID yang diberikan
	err := U.DB.Where("user_id = ?", userID).Delete(&entity2.Tasks{}).Error
	if err != nil {
		return err
	}
	return nil
}

func (U *UserRepository) DeleteUser(userID uint) error {
	// Hapus pengguna berdasarkan ID
	err := U.DB.Where("id = ?", userID).Delete(&entity2.User{}).Error
	if err != nil {
		return err
	}
	return nil
}

// Logout
func (U *UserRepository) DeleteUserToken(userID uint) error {
	// Hapus validToken berdasarkan userID dan token di dalam database menggunakan GORM
	if err := U.DB.Where("user_id = ?", userID).Delete(entity2.ValidToken{}).Error; err != nil {
		return err
	}

	return nil
}

func (U *UserRepository) UpdateTokenExpiration(userID uint, expirationSeconds time.Time) error {
	// Perbarui token_expiration dengan waktu kadaluwarsa
	err := U.DB.Model(&entity2.ValidToken{}).Where("user_id = ?", userID).Update("token_expiration", expirationSeconds).Error
	if err != nil {
		return err
	}

	return nil
}

func (U *UserRepository) GetUserIDByToken(token string) (uint, error) {
	var validToken entity2.ValidToken

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

// login
func (U *UserRepository) GetValidTokenByUserID(userID uint) (*entity2.ValidToken, error) {
	validToken := &entity2.ValidToken{}
	if err := U.DB.Where("user_id = ?", userID).First(validToken).Error; err != nil {
		return nil, err
	}

	return validToken, nil
}

func (U *UserRepository) DeleteValidTokenByUserID(userID uint) error {
	// Hapus token yang sesuai dengan ID pengguna dari tabel valid_tokens
	if err := U.DB.Where("user_id = ?", userID).Delete(&entity2.ValidToken{}).Error; err != nil {
		return err
	}

	return nil
}

// valid token

func (U *UserRepository) ValidateTokenInDatabase(tokenString string) (uint, error) {
	// Parsing token dengan secret key
	claims := &config.Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return config.JwtKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			return 0, err
		}
		return 0, err
	}

	if !token.Valid {
		return 0, err
	}

	// Cek apakah token ada dalam tabel valid_token
	var validToken entity2.ValidToken
	if err := U.DB.Where("token = ?", tokenString).First(&validToken).Error; err != nil {
		return 0, err
	}

	return claims.UserID, nil
}

func (U *UserRepository) StoreRefreshToken(userID uint, refreshToken string) error {
	// Buat atau perbarui token penyegaran di dalam database
	refresh := entity2.ValidToken{
		UserID:       userID,
		RefreshToken: refreshToken,
	}

	// Cek apakah token penyegaran untuk pengguna tersebut sudah ada di database
	var existingRefresh entity2.ValidToken
	result := U.DB.Where("user_id = ?", userID).First(&existingRefresh)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			// Jika tidak ada token penyegaran sebelumnya, buat yang baru
			err := U.DB.Create(&refresh).Error
			if err != nil {
				return err
			}
		} else {
			return result.Error
		}
	} else {
		// Jika sudah ada token penyegaran sebelumnya, perbarui dengan yang baru
		result := U.DB.Model(&existingRefresh).Update("refresh_token", refreshToken)
		if result.Error != nil {
			return result.Error
		}
	}

	return nil
}

// view or page

// refresh Token

func (U *UserRepository) GetUserByRefreshToken(refreshToken string) (*entity2.RefreshToken, error) {
	var user entity2.RefreshToken
	if err := U.DB.Where("refresh_token = ?", refreshToken).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (U *UserRepository) UpdateAccessToken(userID uint, newAccessToken string) error {
	return U.DB.Model(&entity2.ValidToken{}).Where("user_id = ?", userID).Update("token", newAccessToken).Error
}

//func (U *UserRepository)   {
//
//}