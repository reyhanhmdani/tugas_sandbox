package repository

import (
	"testing_backend/model/entity"
	"time"
)

type UserRepository interface {

	// all data
	AllUsersData() ([]entity.User, error)
	// CRUD
	CreateUser(users *entity.User) error

	// PROFILE
	ProfileUser(userId uint) (*entity.ListUsers, error)
	GetByID(userID uint) (*entity.User, error)
	GetUserByID(id uint) ([]entity.User, error)
	GetTaskByUserByID(userID uint, user *entity.User) error

	CheckUsername(username string) (*entity.UserLogin, error)
	PaginatePegawaiUsers(users *[]entity.User, perPage, offset int) error
	PaginateTaskUsers(tasks *[]entity.Tasks, perPage, offset int) error
	// token
	//UpdateUserToken(user *entity.User) error
	AddValidToken(userID uint, token, refreshToken string) error
	AddRefreshToken(userID uint, refreshToken string) error
	// DELETE USER

	DeleteTasksByUserID(userID uint) error
	DeleteUser(userID uint) error

	//Logout
	DeleteUserToken(userID uint) error
	UpdateTokenExpiration(userID uint, expirationSeconds time.Time) error
	GetUserIDByToken(token string) (uint, error)

	// login
	GetValidTokenByUserID(userID uint) (*entity.ValidToken, error)
	DeleteValidTokenByUserID(userID uint) error

	//AddTokenToBlacklist(blacklistToken config.BlacklistToken)

	// validtoken
	ValidateTokenInDatabase(tokenString string) (uint, error)
	StoreRefreshToken(userID uint, refreshToken string) error

	// refresh token
	GetUserByRefreshToken(refreshToken string) (*entity.RefreshToken, error)
	UpdateAccessToken(userID uint, newAccessToken string) error

	// view or page
	//AllUsers() ([]entity.User, error)
}
