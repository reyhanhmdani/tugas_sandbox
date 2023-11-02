package repo_IMPL

import (
	"errors"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"testing_backend/internal/app/model"
)

type UserRepository struct {
	DB *gorm.DB
}

func NewUserRepository(DB *gorm.DB) *UserRepository {
	return &UserRepository{
		DB: DB,
	}
}

func (U *UserRepository) AllUsersData() ([]model.User, error) {
	var users []model.User
	if err := U.DB.Preload("Tasks").Find(&users).Error; err != nil {
		return nil, err
	}
	return users, nil
}

func (U *UserRepository) CreateUser(users *model.User) error {
	if err := U.DB.Create(&users).Error; err != nil {
		return err
	}
	return nil
}

// PROFILE

func (U *UserRepository) ProfileUser(userId uuid.UUID) (*model.ListUsers, error) {
	var profile model.ListUsers
	if err := U.DB.Where("id = ?", userId).First(&profile).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil // Santri data not found for the user
		}
		return nil, err // Other database error
	}
	return &profile, nil
}

func (U *UserRepository) GetByID(userID uuid.UUID) (*model.User, error) {
	var user model.User
	if err := U.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (U *UserRepository) GetUserByID(id uuid.UUID) ([]model.User, error) {
	var users []model.User
	err := U.DB.Where("id", id).Find(&users).Error
	if err != nil {
		return nil, err

	}
	return users, nil
}

func (U *UserRepository) GetTaskByUserByID(userID uuid.UUID, user *model.User) error {
	err := U.DB.Where("id = ?", userID).First(user).Error
	if err != nil {
		return err
	}
	return nil
}

// other
func (U *UserRepository) CheckUsername(username string) (*model.UserLogin, error) {
	var user model.UserLogin
	result := U.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, result.Error
	}
	return &user, nil
}

func (U *UserRepository) PaginatePegawaiUsers(users *[]model.User, perPage, offset int) error {
	// Mencari pengguna dengan role pegawai berdasarkan halaman dan jumlah per halaman
	err := U.DB.Where("role = ?", "pegawai").Offset(offset).Limit(perPage).Find(users).Error
	if err != nil {
		return err
	}
	return nil
}

// token

func (U *UserRepository) AddValidToken(userID uuid.UUID, token, refreshToken string) error {
	// Cek apakah token sudah ada dalam database
	existingToken := model.ValidToken{}
	if err := U.DB.Where("user_id = ? AND token = ? AND refresh_token = ?", userID, token, refreshToken).First(&existingToken).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Token tidak ada dalam database, tambahkan
			newToken := model.ValidToken{
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

// DELETE USER
func (U *UserRepository) DeleteTasksByUserID(userID uuid.UUID) error {
	// Hapus semua tugas yang dimiliki oleh pengguna dengan ID yang diberikan
	err := U.DB.Where("user_id = ?", userID).Delete(&model.Tasks{}).Error
	if err != nil {
		return err
	}
	return nil
}

func (U *UserRepository) DeleteUser(userID uuid.UUID) error {
	// Hapus pengguna berdasarkan ID
	err := U.DB.Where("id = ?", userID).Delete(&model.User{}).Error
	if err != nil {
		return err
	}
	return nil
}

// Logout
func (U *UserRepository) DeleteUserToken(userID uuid.UUID) error {
	// Hapus validToken berdasarkan userID dan token di dalam database menggunakan GORM
	if err := U.DB.Where("user_id = ?", userID).Delete(model.ValidToken{}).Error; err != nil {
		return err
	}

	return nil
}

// login
func (U *UserRepository) GetValidTokenByUserID(userID uuid.UUID) (*model.ValidToken, error) {
	validToken := &model.ValidToken{}
	if err := U.DB.Where("user_id = ?", userID).First(validToken).Error; err != nil {
		return nil, err
	}

	return validToken, nil
}

func (U *UserRepository) DeleteValidTokenByUserID(userID uuid.UUID) error {
	// Hapus token yang sesuai dengan ID pengguna dari tabel valid_tokens
	if err := U.DB.Where("user_id = ?", userID).Delete(&model.ValidToken{}).Error; err != nil {
		return err
	}

	return nil
}

// valid token
func (U *UserRepository) StoreRefreshToken(userID uuid.UUID, refreshToken string) error {
	// Buat atau perbarui token penyegaran di dalam database
	refresh := model.ValidToken{
		UserID:       userID,
		RefreshToken: refreshToken,
	}

	// Cek apakah token penyegaran untuk pengguna tersebut sudah ada di database
	var existingRefresh model.ValidToken
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

func (U *UserRepository) GetUserByRefreshToken(refreshToken string) (*model.RefreshToken, error) {
	var user model.RefreshToken
	if err := U.DB.Where("refresh_token = ?", refreshToken).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (U *UserRepository) UpdateAccessToken(userID uuid.UUID, newAccessToken string) error {
	return U.DB.Model(&model.ValidToken{}).Where("user_id = ?", userID).Update("token", newAccessToken).Error
}

//func (U *UserRepository)   {
//
//}
